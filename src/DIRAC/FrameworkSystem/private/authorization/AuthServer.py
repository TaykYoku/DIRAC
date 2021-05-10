""" This class provides authorization server activity. """
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import json
from time import time
import pprint
from dominate import document, tags as dom
from tornado.template import Template

from authlib.jose import jwt
from authlib.oauth2 import HttpRequest, AuthorizationServer as _AuthorizationServer
from authlib.oauth2.base import OAuth2Error
from authlib.oauth2.rfc6750 import BearerToken
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oauth2.rfc8414 import AuthorizationServerMetadata
from authlib.oauth2.rfc6749.util import scope_to_list

from DIRAC.FrameworkSystem.private.authorization.grants.DeviceFlow import (DeviceAuthorizationEndpoint,
                                                                           DeviceCodeGrant,
                                                                           SaveSessionToDB)
from DIRAC.FrameworkSystem.private.authorization.grants.AuthorizationCode import (OpenIDCode,
                                                                                  AuthorizationCodeGrant)
from DIRAC.FrameworkSystem.private.authorization.grants.RefreshToken import RefreshTokenGrant
from DIRAC.FrameworkSystem.private.authorization.grants.TokenExchange import TokenExchangeGrant
from DIRAC.FrameworkSystem.private.authorization.utils.Clients import Client
from DIRAC.FrameworkSystem.private.authorization.utils.Requests import (OAuth2Request,
                                                                        createOAuth2Request)

from DIRAC import gLogger, gConfig, S_OK, S_ERROR
from DIRAC.FrameworkSystem.DB.AuthDB import AuthDB
from DIRAC.Resources.IdProvider.IdProviderFactory import IdProviderFactory
from DIRAC.ConfigurationSystem.Client.Utilities import getAuthorisationServerMetadata, getAuthClients
from DIRAC.ConfigurationSystem.Client.Helpers.Resources import getProvidersForInstance
from DIRAC.ConfigurationSystem.Client.Helpers.CSGlobals import getSetup
from DIRAC.ConfigurationSystem.Client.Helpers.Registry import getUsernameForDN, getEmailsForGroup
from DIRAC.FrameworkSystem.Client.ProxyManagerClient import ProxyManagerClient

import logging
import sys
log = logging.getLogger('authlib')
log.addHandler(logging.StreamHandler(sys.stdout))
log.setLevel(logging.DEBUG)
log = gLogger.getSubLogger(__name__)


class AuthServer(_AuthorizationServer):
  """ Implementation of :class:`authlib.oauth2.rfc6749.AuthorizationServer`.

      Initialize::

        server = AuthServer()
  """
  css = {}
  LOCATION = None

  metadata_class = AuthorizationServerMetadata

  def __init__(self):
    self.db = AuthDB()
    self.proxyCli = ProxyManagerClient()
    self.idps = IdProviderFactory()
    # Privide two authlib methods query_client and save_token
    _AuthorizationServer.__init__(self, query_client=self.getClient, save_token=self.saveToken)
    self.generate_token = self.generateProxyOrToken  # BearerToken(self.access_token_generator, self.refresh_token_generator)
    self.config = {}
    self.collectMetadata()
    # Register configured grants
    if TokenExchangeGrant.GRANT_TYPE in self.metadata['grant_types_supported']:
      self.register_grant(TokenExchangeGrant)
    if RefreshTokenGrant.GRANT_TYPE in self.metadata['grant_types_supported']:
      self.register_grant(RefreshTokenGrant)
    if DeviceCodeGrant.GRANT_TYPE in self.metadata['grant_types_supported']:
      self.register_grant(DeviceCodeGrant, [SaveSessionToDB(db=self.db)])
      self.register_endpoint(DeviceAuthorizationEndpoint)
    if AuthorizationCodeGrant.GRANT_TYPE in self.metadata['grant_types_supported']:
      self.register_grant(AuthorizationCodeGrant, [CodeChallenge(required=True), OpenIDCode(require_nonce=False)])      

  def collectMetadata(self):
    """ Collect metadata """
    self.metadata = {}
    result = getAuthorisationServerMetadata()
    if not result['OK']:
      raise Exception('Cannot prepare authorization server metadata. %s' % result['Message'])
    # Verify metadata
    metadata = self.metadata_class(result['Value'])
    metadata.validate()
    self.metadata = metadata

  def addSession(self, session):
    self.db.addSession(session)
  
  def getSession(self, session):
    self.db.getSession(session)

  def saveToken(self, token, request):
    """ Store tokens

        :param dict token: tokens
        :param object request: http Request object, implemented for compatibility with authlib library (unuse)
    """
    if 'refresh_token' in token:
      return self.db.storeToken(token)
    return S_OK(None)
  
  def getClient(self, clientID):
    """ Search authorization client

        :param str clientID: client ID

        :return: object
    """
    gLogger.debug('Try to query %s client' % clientID)
    client = None
    result = getAuthClients(clientID)
    if result['OK']:
      client = Client(result['Value'])
      gLogger.debug('Found client', client)
    return client
  
  def generateProxyOrToken(self, user=None, scope=None, include_refresh_token=None, **kwargs):
    """
    """
    print('generateProxyOrToken:')
    print('user: %s' % user)
    print('scope: %s' % scope)
    print('include_refresh_token: %s' % include_refresh_token)
    print('kwargs: %s' % kwargs)
    if 'proxy' in scope_to_list(scope):
      group = [s.split(':')[1] for s in scope_to_list(scope) if s.startswith('g:')][0]
      lifetime = [s.split(':')[1] for s in scope_to_list(scope) if s.startswith('lifetime:')]
      result = self.proxyCli.downloadProxy(user, group, requiredTimeLeft=lifetime[0] if lifetime else None)
      if not result['OK']:
        raise Exception(result['Message'])
      gLogger.info('Proxy was created.')
      return result['Value'].dumpAllToString()
    return BearerToken(self.access_token_generator, self.refresh_token_generator)

  def getIdPAuthorization(self, providerName, request):
    """ Submit subsession and return dict with authorization url and session number

        :param str providerName: provider name
        :param object request: main session request

        :return: S_OK(response)/S_ERROR() -- dictionary contain response generated by `handle_response`
    """
    result = self.idps.getIdProvider(providerName)
    if not result['OK']:
      return result
    idpObj = result['Value']
    result = idpObj.submitNewSession()
    if not result['OK']:
      return result
    authURL, state, session = result['Value']
    session['state'] = state
    session['Provider'] = providerName
    session['mainSession'] = request if isinstance(request, dict) else request.toDict()

    gLogger.verbose('Redirect to', authURL)
    return self.handle_response(302, {}, [("Location", authURL)], session)

  def parseIdPAuthorizationResponse(self, response, session):
    """ Fill session by user profile, tokens, comment, OIDC authorize status, etc.
        Prepare dict with user parameters, if DN is absent there try to get it.
        Create new or modify existing DIRAC user and store the session

        :param dict response: authorization response
        :param str session: session

        :return: S_OK(dict)/S_ERROR()
    """
    providerName = session.pop('Provider')
    gLogger.debug('Try to parse authentification response from %s:\n' % providerName, pprint.pformat(response))
    # Parse response
    result = self.idps.getIdProvider(providerName, sessionManager=self.db)
    if not result['OK']:
      return result
    provObj = result['Value']
    result = provObj.parseAuthResponse(response, session)
    if not result['OK']:
      return result
    # FINISHING with IdP auth result
    credDict = result['Value']
    gLogger.debug("Read profile:", pprint.pformat(credDict))
    # Is ID registred?
    result = getUsernameForDN(credDict['DN'])
    if not result['OK']:
      # if sync with extVO is turn on:
      #   return autogenerated username and userID
      # else:
      comment = '%s ID is not registred in the DIRAC.' % credDict['ID']
      result = self.__registerNewUser(providerName, credDict)
      if result['OK']:
        comment += ' Administrators have been notified about you.'
      else:
        comment += ' Please, contact the DIRAC administrators.'
      return S_ERROR(comment)
    credDict['username'] = result['Value']
    return S_OK(credDict)

  def access_token_generator(self, client, grant_type, user, scope):
    """ A function to generate ``access_token``

        :param object client: Client object
        :param str grant_type: grant type
        :param str user: user unique id
        :param str scope: scope

        :return: jwt object
    """
    # if 'proxy' in scope:
    #   group = [s.split(':')[1] for s in scope_to_list(scope) if s.startswith('g:')][0]
    #   lifetime = [s.split(':')[1] for s in scope_to_list(scope) if s.startswith('lifetime:')]
    #   result = self.proxyCli.downloadProxy(user, group, requiredTimeLeft=lifetime[0] if lifetime else None)
    #   if not result['OK']:
    #     raise Exception(result['Message'])
    #   gLogger.info('Proxy was created.')
    #   return result['Value'].dumpAllToString()
    gLogger.debug('GENERATE DIRAC ACCESS TOKEN for "%s" with "%s" scopes.' % (user, scope))
    header = {'alg': 'RS256'}
    payload = {'sub': user,
               'iss': self.metadata['issuer'],
               'iat': int(time()),
               'exp': int(time()) + (12 * 3600),
               'scope': scope,
               'setup': getSetup()}
    # #
    # Return proxy with token in one response?
    # #

    # Read private key of DIRAC auth service
    with open('/opt/dirac/etc/grid-security/jwtRS256.key', 'r') as f:
      key = f.read()
    # Need to use enum==0.3.1 for python 2.7
    return jwt.encode(header, payload, key)

  def refresh_token_generator(self, client, grant_type, user, scope):
    """ A function to generate ``refresh_token``

        :param object client: Client object
        :param str grant_type: grant type
        :param str user: user unique id
        :param str scope: scope

        :return: jwt object
    """
    gLogger.debug('GENERATE DIRAC REFRESH TOKEN for "%s" with "%s" scopes.' % (user, scope))
    header = {'alg': 'RS256'}
    payload = {'sub': user,
               'iss': self.metadata['issuer'],
               'iat': int(time()),
               'exp': int(time()) + (30 * 24 * 3600),
               'scope': scope,
               'setup': getSetup(),
               'client_id': client.client_id}
    # Read private key of DIRAC auth service
    with open('/opt/dirac/etc/grid-security/jwtRS256.key', 'r') as f:
      key = f.read()
    # Need to use enum==0.3.1 for python 2.7
    return jwt.encode(header, payload, key)

  def get_error_uris(self, request):
    error_uris = self.config.get('error_uris')
    if error_uris:
      return dict(error_uris)

  def create_oauth2_request(self, request, method_cls=OAuth2Request, use_json=False):
    gLogger.debug('Create OAuth2 request', 'with json' if use_json else '')
    return createOAuth2Request(request, method_cls, use_json)

  def create_json_request(self, request):
    return self.create_oauth2_request(request, HttpRequest, True)

  def handle_error_response(self, request, error):
    return self.handle_response(*error(translations=self.get_translations(request),
                                       error_uris=self.get_error_uris(request)), error=True)

  def handle_response(self, status_code=None, payload=None, headers=None, newSession=None, error=None, **actions):
    gLogger.debug('Handle authorization response with %s status code:' % status_code, payload)
    gLogger.debug('Headers:', headers)
    if newSession:
      gLogger.debug('newSession:', newSession)
    return S_OK([[status_code, headers, payload, newSession, error], actions])

  def create_authorization_response(self, response, username):
    result = super(AuthServer, self).create_authorization_response(response, username)
    if result['OK']:
      # Remove auth session
      result['Value'][0][4] = True
    return result

  def validate_consent_request(self, request, provider=None):
    """ Validate current HTTP request for authorization page. This page
        is designed for resource owner to grant or deny the authorization::

        :param object request: tornado request
        :param provider: provider

        :return: response generated by `handle_response` or S_ERROR or html
    """
    if request.method != 'GET':
      return 'Use GET method to access this endpoint.'
    try:
      req = self.create_oauth2_request(request)
      gLogger.info('Validate consent request for', req.state)
      grant = self.get_authorization_grant(req)
      gLogger.debug('Use grant:', grant)
      grant.validate_consent_request()
      if not hasattr(grant, 'prompt'):
        grant.prompt = None
      
      
      # Check Identity Provider
      provider, providerChooser = self.validateIdentityProvider(req, provider)
      if not provider:
        return providerChooser

      # Submit second auth flow through IdP
      return self.getIdPAuthorization(provider, req)
    except OAuth2Error as error:
      return self.handle_error_response(None, error)

  def validateIdentityProvider(self, request, provider):
    """ Check if identity provider registred in DIRAC

        :param object request: request
        :param str provider: provider name

        :return: str, S_OK()/S_ERROR() -- provider name and html page to choose it
    """
    # Research supported IdPs
    result = getProvidersForInstance('Id')
    if not result['OK']:
      return None, result
    idPs = result['Value']
    if not idPs:
      return None, S_ERROR('No identity providers found.')

    if not provider:
      if len(idPs) == 1:
        return idPs[0], None
      # Choose IdP interface
      doc = document('DIRAC authentication')
      with doc.head:
        dom.link(rel='stylesheet',
                href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css")
        dom.style(self.css['CSS'])
      with doc:
        with dom.div(style=self.css['css_main']):
          with dom.div('Choose identity provider', style=self.css['css_align_center']):
            for idP in idPs:
              # data: Status, Comment, Action
              dom.button(dom.a(idP, href='%s/authorization/%s?%s' % (self.LOCATION, idP, request.query)),
                               cls='button')
      return None, self.handle_response(payload=Template(doc.render()).generate())

    # Check IdP
    if provider not in idPs:
      return None, S_ERROR('%s is not registered in DIRAC.' % provider)

    return provider, None
    
  def __registerNewUser(self, provider, userProfile):
    """ Register new user

        :param str provider: provider
        :param dict userProfile: user information dictionary

        :return: S_OK()/S_ERROR()
    """
    from DIRAC.FrameworkSystem.Client.NotificationClient import NotificationClient

    username = userProfile['DN']

    mail = {}
    mail['subject'] = "[SessionManager] User %s to be added." % username
    mail['body'] = 'User %s was authenticated by ' % userProfile['FullName']
    mail['body'] += provider
    mail['body'] += "\n\nAuto updating of the user database is not allowed."
    mail['body'] += " New user %s to be added," % username
    mail['body'] += "with the following information:\n"
    mail['body'] += "\nUser name: %s\n" % username
    mail['body'] += "\nUser profile:\n%s" % pprint.pformat(userProfile)
    mail['body'] += "\n\n------"
    mail['body'] += "\n This is a notification from the DIRAC AuthManager service, please do not reply.\n"
    result = S_OK()
    for addresses in getEmailsForGroup('dirac_admin'):
      result = NotificationClient().sendMail(addresses, mail['subject'], mail['body'], localAttempt=False)
      if not result['OK']:
        self.log.error(result['Message'])
    if result['OK']:
      self.log.info(result['Value'], "administrators have been notified about a new user.")
    return result