from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import os
import time
import requests
from authlib.oauth2 import OAuth2Error
from authlib.oauth2.rfc6749.util import scope_to_list
from authlib.oauth2.rfc6749.grants import AuthorizationEndpointMixin
from authlib.oauth2.rfc6749.errors import InvalidClientError, UnauthorizedClientError
from authlib.oauth2.rfc8628 import (DeviceAuthorizationEndpoint as _DeviceAuthorizationEndpoint,
                                    DeviceCodeGrant as _DeviceCodeGrant,
                                    DeviceCredentialDict,
                                    DEVICE_CODE_GRANT_TYPE)

from DIRAC import gLogger, S_OK, S_ERROR
from DIRAC.ConfigurationSystem.Client.Utilities import getAuthAPI

log = gLogger.getSubLogger(__name__)


class DeviceAuthorizationEndpoint(_DeviceAuthorizationEndpoint):
  URL = '%s/device' % getAuthAPI()

  def create_endpoint_response(self, req):
    """ See :func:`authlib.oauth2.rfc8628.DeviceAuthorizationEndpoint.create_endpoint_response` """
    # Share original request object to endpoint class before create_endpoint_response
    self.req = req
    return super(DeviceAuthorizationEndpoint, self).create_endpoint_response(req)

  def get_verification_uri(self):
    """ Create verification uri when `DeviceCode` flow initialized

        :return: str
    """
    return self.URL

  def save_device_credential(self, client_id, scope, data):
    """ Save device credentials

        :param str client_id: client id
        :param str scope: request scopes
        :param dict data: device credentials
    """
    data.update(dict(uri='{api}?{query}&response_type=device&client_id={client_id}&scope={scope}'.format(
        api=data['verification_uri'], query=self.req.query, client_id=client_id, scope=scope,
    ), id=data['device_code'], client_id=client_id, scope=scope))
    result = self.server.db.addSession(data)
    if not result['OK']:
      raise OAuth2Error('Cannot save device credentials', result['Message'])


class DeviceCodeGrant(_DeviceCodeGrant, AuthorizationEndpointMixin):
  RESPONSE_TYPES = {'device'}

  def validate_authorization_request(self):
    """ Validate authorization request
    
        :return: None
    """
    # Validate client for this request
    client_id = self.request.client_id
    log.debug('Validate authorization request of', client_id)
    if client_id is None:
      raise InvalidClientError(state=self.request.state)
    client = self.server.query_client(client_id)
    if not client:
      raise InvalidClientError(state=self.request.state)
    response_type = self.request.response_type
    if not client.check_response_type(response_type):
      raise UnauthorizedClientError('The client is not authorized to use "response_type={}"'.format(response_type))
    self.request.client = client
    self.validate_requested_scope()

    # Check user_code, when user go to authorization endpoint
    userCode = self.request.args.get('user_code')
    if not userCode:
      raise OAuth2Error('user_code is absent.')

    # Get session from cookie
    if not self.server.db.getSessionByUserCode(userCode):
      raise OAuth2Error('Session with %s user code is expired.' % userCode)
    return None

  def create_authorization_response(self, redirect_uri, user):
    """ Mark session as authed with received user

        :param str redirect_uri: redirect uri
        :param dict user: dictionary with username and userID

        :return: result of `handle_response`
    """
    result = self.server.db.getSessionByUserCode(self.request.data['user_code'])
    if not result['OK']:
      raise OAuth2Error(result['Message'])
    data = result['Value']
    data.update(dict(user_id=user['ID'], uri=self.request.uri,
                     username=user['username'], scope=self.request.scope))
    # Save session with user
    result = self.server.db.updateSession(data, data['id'])
    if not result['OK']:
      raise OAuth2Error('Cannot save authorization result', result['Message'])
    return 200, 'Authorization complite.'

  def query_device_credential(self, device_code):
    result = self.server.db.getSession(device_code)
    print('query_device_credential>>  %s' % result)
    if not result['OK']:
      raise OAuth2Error(result['Message'])
    data = result['Value']
    if not data:
      return None
    data['expires_at'] = int(data['expires_in']) + int(time.time())
    data['interval'] = DeviceAuthorizationEndpoint.INTERVAL
    data['verification_uri'] = DeviceAuthorizationEndpoint.URL
    print('query_device_credential: %s' % DeviceCredentialDict(data))
    print('scope: %s' % DeviceCredentialDict(data).get_scope())
    return DeviceCredentialDict(data)

  def query_user_grant(self, user_code):
    """ Check if user alredy authed and return it to token generator

        :param str user_code: user code

        :return: str, bool -- user dict and user auth status
    """
    result = self.server.db.getSessionByUserCode(user_code)
    if not result['OK']:
      raise OAuth2Error('Cannot found authorization session', result['Message'])
    data = result['Value']
    return (data['user_id'], True) if data.get('username') != "None" else None

  def should_slow_down(self, credential, now):
    """ If need to slow down requests """
    return False


class SaveSessionToDB(object):
  """ SaveSessionToDB extension to Device Code Grant. It is used to
      seve authorization session of Device Code flow for public clients in MySQL database.

      Then register this extension via::

        server.register_grant(DeviceCodeGrant, [SaveSessionToDB(db=self.db)])
  """
  def __init__(self, db):
    self.db = db

  def __call__(self, grant):
    grant.register_hook('after_validate_consent_request', self.save_session)

  def save_session(self, *args, **kwargs):
    print('SAVE-SESSION')
    print(args)
