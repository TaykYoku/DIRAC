""" IdProvider based on OAuth2 protocol
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import re
import six
import time
import pprint
import requests
from requests import exceptions
from authlib.jose import JsonWebKey, jwt
from authlib.common.urls import url_decode
from authlib.common.security import generate_token
from authlib.oauth2.rfc6749.util import scope_to_list, list_to_scope
from authlib.oauth2.rfc6749.parameters import prepare_token_request
from authlib.oauth2.rfc8414 import AuthorizationServerMetadata
from authlib.oauth2.rfc8628 import DEVICE_CODE_GRANT_TYPE
from authlib.integrations.requests_client import OAuth2Session
from authlib.oidc.discovery.well_known import get_well_known_url
from DIRAC.FrameworkSystem.private.authorization.utils.Requests import createOAuth2Request
from DIRAC.FrameworkSystem.private.authorization.utils.Tokens import OAuth2Token
from DIRAC.ConfigurationSystem.Client.Utilities import getAuthClients

from DIRAC import S_OK, S_ERROR, gLogger
from DIRAC.Resources.IdProvider.IdProvider import IdProvider
from DIRAC.ConfigurationSystem.Client.Helpers.Registry import getVOMSRoleGroupMapping, getVOForGroup, getGroupOption

__RCSID__ = "$Id$"

DEFAULT_HEADERS = {
    'Accept': 'application/json',
    'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
}


def claimParser(claimDict, attributes):
  """ Parse claims to write it as DIRAC profile

      :param dict claimDict: claims
      :param dict attributes: contain claim and regex to parse it
      :param dict profile: to fill parsed data

      :return: dict
  """
  profile = {}
  result = None
  for claim, reg in attributes.items():
    if claim not in claimDict:
      continue
    profile[claim] = {}
    if isinstance(claimDict[claim], dict):
      result = claimParser(claimDict[claim], reg)
      if result:
        profile[claim] = result
    elif isinstance(claimDict[claim], six.string_types):
      result = re.compile(reg).match(claimDict[claim])
      if result:
        for k, v in result.groupdict().items():
          profile[claim][k] = v
    else:
      profile[claim] = []
      for claimItem in claimDict[claim]:
        if isinstance(reg, dict):
          result = claimParser(claimItem, reg)
          if result:
            profile[claim].append(result)
        else:
          result = re.compile(reg).match(claimItem)
          if result:
            profile[claim].append(result.groupdict())

  return profile


class OAuth2IdProvider(IdProvider, OAuth2Session):

  jwks_uri = None
  jwks = None

  def __init__(self, name=None, token_endpoint_auth_method='client_secret_post', revocation_endpoint_auth_method=None,
               scope=None, token=None, token_placement='header', update_token=None, **parameters):
    """ OIDCClient constructor
    """
    if 'ProviderName' not in parameters:
      parameters['ProviderName'] = name
    IdProvider.__init__(self, **parameters)
    OAuth2Session.__init__(self, token_endpoint_auth_method=token_endpoint_auth_method,
                           revocation_endpoint_auth_method=revocation_endpoint_auth_method,
                           scope=scope, token=token, token_placement=token_placement,
                           update_token=update_token, **parameters)
    # Convert scope to list
    scope = scope or ''
    self.scope = [s.strip() for s in scope.strip().replace('+', ' ').split(',' if ',' in scope else ' ')]
    self.parameters = parameters
    self.name = parameters['ProviderName']
    self.verify = False

    self.server_metadata_url = parameters.get('server_metadata_url', get_well_known_url(self.metadata['issuer'], True))

    self.log.debug('"%s" OAuth2 IdP initialization done:' % self.name,
                   '\nclient_id: %s\nclient_secret: %s\nmetadata:\n%s' % (self.client_id,
                                                                          self.client_secret,
                                                                          pprint.pformat(self.metadata)))

  def store_token(self, token):
    """ need to implement
    """
    return S_OK(None)

  def update_token(self, token, refresh_token):
    pass

  def get_metadata(self, option=None):
    """
    """
    if not self.metadata.get(option):
      self.metadata.update(self.fetch_metadata())
    return self.metadata.get(option)

  def fetch_metadata(self, url=None):
    """
    """
    return self.get(url or self.server_metadata_url, withhold_token=True).json()

  def researchGroup(self, payload, token):
    """ Research group
    """
    return {}

  def authorization(self, group=None):
    """
    """
    result = self.submitDeviceCodeAuthorizationFlow(group)
    if not result['OK']:
      return result
    response = result['Value']

    # Notify user to go to authorization endpoint
    showURL = 'Use next link to continue, your user code is "%s"\n%s' % (response['user_code'],
                                                                         response['verification_uri'])
    gLogger.notice(showURL)

    return self.waitFinalStatusOfDeviceCodeAuthorizationFlow(response['device_code'])

  def submitNewSession(self, session=None):
    """ Submit new authorization session

        :param str session: session number

        :return: S_OK(str)/S_ERROR()
    """
    url, state = self.create_authorization_url(self.get_metadata('authorization_endpoint'), state=self.generateState(session))
    return S_OK((url, state, {}))

  def parseAuthResponse(self, response, session=None):
    """ Make user info dict:

        :param dict response: response on request to get user profile
        :param object session: session

        :return: S_OK(dict)/S_ERROR()
    """
    response = createOAuth2Request(response)

    self.log.debug('Try to parse authentication response:', pprint.pformat(response.data))

    if not session:
      session = {}  # Session(response.args['state'])

    self.log.debug('Current session is:\n', pprint.pformat(dict(session)))
    
    self.fetch_access_token(self.get_metadata('token_endpoint'),
                            authorization_response=response.uri,
                            code_verifier=session.get('code_verifier'))

    # Get user info
    claims = self.getUserProfile()
    credDict = self.parseBasic(claims)
    credDict.update(self.parseEduperson(claims))
    cerdDict = self.userDiscover(credDict)

    self.log.debug('Got response dictionary:\n', pprint.pformat(cerdDict))

    # Store token
    self.token['client_id'] = self.client_id
    self.token['provider'] = self.name
    self.token['user_id'] = credDict['ID']
    self.log.debug('Store token to the database:\n', pprint.pformat(dict(self.token)))

    result = self.store_token(self.token)
    if not result['OK']:
      return result

    return S_OK(credDict)

  def parseBasic(self, claimDict):
    """ Parse basic claims

        :param dict claimDict: claims

        :return: S_OK(dict)/S_ERROR()
    """
    credDict = {}
    credDict['ID'] = claimDict['sub']
    return credDict

  def __getUserInfo(self, useToken=None):
    self.log.debug('Sent request to userinfo endpoint..')
    r = None
    try:
      r = self.request('GET', self.get_metadata('userinfo_endpoint'), withhold_token=useToken)
      r.raise_for_status()
      return S_OK(r.json())
    except (self.exceptions.RequestException, ValueError) as e:
      return S_ERROR("%s: %s" % (repr(e), r.text if r else ''))

  def parseEduperson(self, claimDict):
    """ Parse eduperson claims

        :return: dict
    """
    credDict = {}
    attributes = {
        'eduperson_unique_id': '^(?P<ID>.*)',
        'eduperson_entitlement': '^(?P<NAMESPACE>[A-z,.,_,-,:]+):(group:registry|group):(?P<VO>[A-z,.,_,-]+):role=(?P<VORole>[A-z,.,_,-]+)[:#].*'
    }
    print('==> getUserProfile 1')
    pprint.pprint(claimDict)
    if 'eduperson_entitlement' not in claimDict:
      print('==> getUserProfile 2')
      claimDict = self.getUserProfile()
    pprint.pprint(claimDict)
    resDict = claimParser(claimDict, attributes)
    print('++..')
    pprint.pprint(resDict)
    if not resDict:
      return credDict
    credDict['ID'] = resDict['eduperson_unique_id']['ID']
    credDict['VOs'] = {}
    for voDict in resDict['eduperson_entitlement']:
      if voDict['VO'] not in credDict['VOs']:
        credDict['VOs'][voDict['VO']] = {'VORoles': []}
      if voDict['VORole'] not in credDict['VOs'][voDict['VO']]['VORoles']:
        credDict['VOs'][voDict['VO']]['VORoles'].append(voDict['VORole'])
    return credDict

  def userDiscover(self, credDict):
    credDict['DN'] = '/O=DIRAC/CN=%s' % credDict['ID']
    credDict['DIRACGroups'] = []
    for vo, voData in credDict.get('VOs', {}).items():
      result = getVOMSRoleGroupMapping(vo)
      pprint.pprint(result)
      if result['OK']:
        for role in voData['VORoles']:
          groups = result['Value']['VOMSDIRAC'].get('/%s' % role)
          if groups:
            credDict['DIRACGroups'] = list(set(credDict['DIRACGroups'] + groups))
    if credDict['DIRACGroups']:
      credDict['group'] = credDict['DIRACGroups'][0]
    return credDict

  def submitDeviceCodeAuthorizationFlow(self, group=None):
    """ Submit authorization flow

        :return: S_OK(dict)/S_ERROR() -- dictionary with device code flow response
    """
    print('scopes: %s' % self.scope)
    groupScopes = []
    if group:
      result = self.getGroupScopes(group)
      if not result['OK']:
        return result
      groupScopes = result['Value']

    try:
      r = requests.post(self.get_metadata('device_authorization_endpoint'), data=dict(
        client_id=self.client_id, scope=list_to_scope(self.scope + groupScopes)
      ), verify=self.verify)
      print(list_to_scope(self.scope + groupScopes))
      r.raise_for_status()
      deviceResponse = r.json()
      if 'error' in deviceResponse:
        return S_ERROR('%s: %s' % (deviceResponse['error'], deviceResponse.get('description', '')))

      # Check if all main keys are present here
      for k in ['user_code', 'device_code', 'verification_uri']:
        if not deviceResponse.get(k):
          return S_ERROR('Mandatory %s key is absent in authentication response.' % k)

      return S_OK(deviceResponse)
    except requests.exceptions.Timeout:
      return S_ERROR('Authentication server is not answer, timeout.')
    except requests.exceptions.RequestException as ex:
      return S_ERROR(repr(ex))
    except Exception as ex:
      return S_ERROR('Cannot read authentication response: %s' % repr(ex))

  def waitFinalStatusOfDeviceCodeAuthorizationFlow(self, deviceCode, interval=5, timeout=300):
    """ Submit waiting loop process, that will monitor current authorization session status

        :param str deviceCode: received device code
        :param int interval: waiting interval
        :param int timeout: max time of waiting

        :return: S_OK(dict)/S_ERROR() - dictionary contain access/refresh token and some metadata
    """
    __start = time.time()

    gLogger.notice('Authorization pending.. (use CNTL + C to stop)')
    while True:
      time.sleep(int(interval))
      if time.time() - __start > timeout:
        return S_ERROR('Time out.')
      r = requests.post(self.get_metadata('token_endpoint'), data=dict(client_id=self.client_id,
                                                                   grant_type=DEVICE_CODE_GRANT_TYPE,
                                                                   device_code=deviceCode), verify=self.verify)
      token = r.json()
      if not token:
        return S_ERROR('Resived token is empty!')
      if 'error' not in token:
        self.token = token
        return S_OK(token)
      if token['error'] != 'authorization_pending':
        return S_ERROR(token['error'] + ' : ' + token.get('description', ''))

  def getGroupScopes(self, group):
    """ Get group scopes

        :param str group: DIRAC group

        :return: list
    """
    idPScope = getGroupOption(group, 'IdPScope')
    if not idPScope:
      return S_ERROR('Cannot find role for %s' % group)
    return S_OK(scope_to_list(idPScope))

  def exchangeGroup(self, group):
    """ Get new tokens for group scope

        :param str group: requested group

        :return: dict -- token
    """
    result = self.getGroupScopes(group)
    if not result['OK']:
      return result
    groupScopes = result['Value']
    print(list_to_scope(self.scope + groupScopes))
    try:
      token = self.exchange_token(self.get_metadata('token_endpoint'), subject_token=self.token['access_token'],
                                  subject_token_type='urn:ietf:params:oauth:token-type:access_token',
                                  scope=list_to_scope(self.scope + groupScopes))
      if not token:
        return S_ERROR('Cannot exchange token with %s group.' % group)
      self.token = token
      return S_OK(token)
      
    except Exception as e:
      return S_ERROR(repr(e))

  def getUserProfile(self):
    return self.get(self.get_metadata('userinfo_endpoint')).json()

  def exchange_token(self, url, subject_token=None, subject_token_type=None, body='',
                     refresh_token=None, access_token=None, auth=None, headers=None, **kwargs):
    """ Fetch a new access token using a refresh token.

        :param url: Refresh Token endpoint, must be HTTPS.
        :param str subject_token: subject_token
        :param str subject_token_type: token type https://tools.ietf.org/html/rfc8693#section-3
        :param body: Optional application/x-www-form-urlencoded body to add the
                      include in the token request. Prefer kwargs over body.
        :param str refresh_token: refresh token
        :param str access_token: access token
        :param auth: An auth tuple or method as accepted by requests.
        :param headers: Dict to default request headers with.
        :return: A :class:`OAuth2Token` object (a dict too).
    """
    session_kwargs = self._extract_session_request_params(kwargs)
    refresh_token = refresh_token or self.token.get('refresh_token')
    access_token = access_token or self.token.get('access_token')
    subject_token = subject_token or refresh_token
    subject_token_type = subject_token_type or 'urn:ietf:params:oauth:token-type:refresh_token'
    if 'scope' not in kwargs and self.scope:
      kwargs['scope'] = self.scope
    body = prepare_token_request('urn:ietf:params:oauth:grant-type:token-exchange', body,
                                 subject_token=subject_token, subject_token_type=subject_token_type, **kwargs)

    if headers is None:
      headers = DEFAULT_HEADERS

    for hook in self.compliance_hook.get('exchange_token_request', []):
      url, headers, body = hook(url, headers, body)

    if auth is None:
      auth = self.client_auth(self.token_endpoint_auth_method)

    return self._exchange_token(url, refresh_token=refresh_token, body=body, headers=headers,
                                auth=auth, **session_kwargs)

  def _exchange_token(self, url, body='', refresh_token=None, headers=None, auth=None, **kwargs):
    resp = self.session.post(url, data=dict(url_decode(body)), headers=headers, auth=auth, **kwargs)

    for hook in self.compliance_hook.get('exchange_token_response', []):
      resp = hook(resp)

    token = self.parse_response_token(resp.json())
    if 'refresh_token' not in token:
      self.token['refresh_token'] = refresh_token

    if callable(self.update_token):
      self.update_token(self.token, refresh_token=refresh_token)

    return self.token

  def generateState(self, session=None):
    return session or generate_token(10)
