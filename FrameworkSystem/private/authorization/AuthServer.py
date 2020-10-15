import json
from time import time
from pprint import pprint

from authlib.deprecate import deprecate
from authlib.jose import jwt
from authlib.oauth2 import (
    OAuth2Error,
    # OAuth2Request,
    HttpRequest,
    AuthorizationServer as _AuthorizationServer,
)
from authlib.oauth2.rfc6749.grants import ImplicitGrant
from .grants import (
  DeviceAuthorizationEndpoint,
  DeviceCodeGrant,
  OpenIDCode,
  AuthorizationCodeGrant,
  RefreshTokenGrant,
  OpenIDImplicitGrant,
  NotebookImplicitGrant
)
from .utils import (
  Client,
  ClientRegistrationEndpoint,
  SessionManager,
  ClientManager,
  OAuth2Request,
  createOAuth2Request
)
from authlib.oidc.core import UserInfo

from authlib.oauth2.rfc6750 import BearerToken
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oauth2.rfc8414 import AuthorizationServerMetadata
from authlib.common.security import generate_token
from authlib.common.encoding import to_unicode, json_dumps, json_b64encode, urlsafe_b64decode, json_loads

from DIRAC import gLogger, gConfig, S_OK, S_ERROR
from DIRAC.FrameworkSystem.DB.AuthDB2 import AuthDB2
from DIRAC.ConfigurationSystem.Client.Helpers.CSGlobals import getSetup
from DIRAC.Resources.IdProvider.IdProviderFactory import IdProviderFactory
from DIRAC.FrameworkSystem.Client.AuthManagerClient import gSessionManager
# from DIRAC.Core.Web.SessionData import SessionStorage

log = gLogger.getSubLogger(__name__)


class AuthServer(_AuthorizationServer, SessionManager, ClientManager):
  """ Implementation of :class:`authlib.oauth2.rfc6749.AuthorizationServer`.
      Initialize it ::

          server = AuthServer()
  """
  metadata_class = AuthorizationServerMetadata

  def __init__(self):
    self.__db = AuthDB2()
    self.idps = IdProviderFactory()
    ClientManager.__init__(self, self.__db)
    SessionManager.__init__(self)
    _AuthorizationServer.__init__(self, query_client=self.getClient, save_token=self.saveToken)
    self.generate_token = BearerToken(self.access_token_generator, self.refresh_token_generator)
    self.config = {}
    self.metadata = {}
    result = gConfig.getOptionsDictRecursively('/Systems/Framework/Production/Services/AuthManager/AuthorizationServer')
    if result['OK']:
      data = {}
      # Search values with type list
      for key, v in result['Value'].items():
        data[key] = [e for e in v.replace(', ', ',').split(',') if e] if ',' in v else v
      # Verify metadata
      metadata = self.metadata_class(data)
      metadata.validate()
      self.metadata = metadata

    self.config.setdefault('error_uris', self.metadata.get('OAUTH2_ERROR_URIS'))
    if self.metadata.get('OAUTH2_JWT_ENABLED'):
      deprecate('Define "get_jwt_config" in OpenID Connect grants', '1.0')
      self.init_jwt_config(self.metadata)

    self.register_grant(NotebookImplicitGrant) #OpenIDImplicitGrant)
    self.register_grant(RefreshTokenGrant)
    self.register_grant(DeviceCodeGrant)
    self.register_grant(AuthorizationCodeGrant,
                        [CodeChallenge(required=True), OpenIDCode(require_nonce=False)])
    self.register_endpoint(ClientRegistrationEndpoint)
    self.register_endpoint(DeviceAuthorizationEndpoint)
  
  def saveToken(self, token, request):
    if 'refresh_token' in token:
      self.addSession(token['refresh_token'], **token)
    return None

  def getIdPAuthorization(self, providerName, mainSession):
    """ Submit subsession and return dict with authorization url and session number

        :param str providerName: provider name
        :param str mainSession: main session identificator

        :return: S_OK(dict)/S_ERROR() -- dictionary contain next keys:
                 Status -- session status
                 UserName -- user name, returned if status is 'ready'
                 Session -- session id, returned if status is 'needToAuth'
    """
    # Start subsession
    session = generate_token(10)
    self.addSession(session, mainSession=mainSession, Provider=providerName)

    result = gSessionManager.getIdPAuthorization(providerName, session)
    if result['OK']:
      authURL, sessionParams = result['Value']
      self.updateSession(session, **sessionParams)
    return S_OK(authURL) if result['OK'] else result

  def parseIdPAuthorizationResponse(self, response, session):
    """ Fill session by user profile, tokens, comment, OIDC authorize status, etc.
        Prepare dict with user parameters, if DN is absent there try to get it.
        Create new or modify existing DIRAC user and store the session

        :param str providerName: identity provider name
        :param dict response: authorization response
        :param str session: session 

        :return: S_OK(dict)/S_ERROR()
    """
    print('=== AUTHSERV: parseIdPAuthorizationResponse ===')
    pprint(self.getSessions())
    print('----------------')
    # Check session
    sessionDict = self.getSession(session)
    if not sessionDict:
      return S_ERROR("Session expired.")
    
    mainSession = sessionDict['mainSession']
    providerName = sessionDict['Provider']
    result = gSessionManager.parseAuthResponse(providerName,
                                               createOAuth2Request(response).toDict(),
                                               sessionDict)
    if not result['OK']:
      self.updateSession(mainSession, Status='failed', Comment=result['Message'])
      return result
    self.removeSession(session)
    username, profile = result['Value']
    if username and profile:
      self.updateSession(mainSession, username=username, profile=profile, userID=profile['ID'])
    return S_OK(mainSession)

  def access_token_generator(self, client, grant_type, user, scope):
    print('GENERATE ACCESS TOKEN')
    print('scope: %s' % scope)
    header = {'alg': 'RS256'}
    payload = {'sub': user,
               'iss': self.metadata['issuer'],
               'iat': int(time()),
               'exp': int(time()) + (12 * 3600),
               'scopes': scope.split(),
               'setup': getSetup()}
    # Read private key of DIRAC auth service
    with open('/opt/dirac/etc/grid-security/jwtRS256.key', 'r') as f:
      key = f.read()
    # Need to use enum==0.3.1 for python 2.7
    return jwt.encode(header, payload, key)
  
  def refresh_token_generator(self, client, grant_type, user, scope):
    print('GENERATE REFRESH TOKEN')
    print('scope: %s' % scope)
    header = {'alg': 'RS256'}
    payload = {'sub': user,
               'iss': self.metadata['issuer'],
               'iat': int(time()),
               'exp': int(time()) + (30 * 24 * 3600),
               'scopes': scope.split(),
               'setup': getSetup(),
               'client': client.client_id}
    # Read private key of DIRAC auth service
    with open('/opt/dirac/etc/grid-security/jwtRS256.key', 'r') as f:
      key = f.read()
    # Need to use enum==0.3.1 for python 2.7
    return jwt.encode(header, payload, key)

  def init_jwt_config(self, config):
    """ Initialize JWT related configuration. """
    jwt_iss = config.get('OAUTH2_JWT_ISS')
    if not jwt_iss:
      raise RuntimeError('Missing "OAUTH2_JWT_ISS" configuration.')

    jwt_key_path = config.get('OAUTH2_JWT_KEY_PATH')
    if jwt_key_path:
      with open(jwt_key_path, 'r') as f:
        if jwt_key_path.endswith('.json'):
          jwt_key = json.load(f)
        else:
          jwt_key = to_unicode(f.read())
    else:
      jwt_key = config.get('OAUTH2_JWT_KEY')

    if not jwt_key:
      raise RuntimeError('Missing "OAUTH2_JWT_KEY" configuration.')

    jwt_alg = config.get('OAUTH2_JWT_ALG')
    if not jwt_alg:
      raise RuntimeError('Missing "OAUTH2_JWT_ALG" configuration.')

    jwt_exp = config.get('OAUTH2_JWT_EXP', 3600)
    self.config.setdefault('jwt_iss', jwt_iss)
    self.config.setdefault('jwt_key', jwt_key)
    self.config.setdefault('jwt_alg', jwt_alg)
    self.config.setdefault('jwt_exp', jwt_exp)

  def get_error_uris(self, request):
    error_uris = self.config.get('error_uris')
    if error_uris:
      return dict(error_uris)

  def create_oauth2_request(self, request, method_cls=OAuth2Request, use_json=False):
    print('==== create_oauth2_request === USE JSON: %s' % use_json)
    return createOAuth2Request(request, method_cls, use_json)
  def create_json_request(self, request):
    return self.create_oauth2_request(request, HttpRequest, True)

  def handle_response(self, status_code, payload, headers):
    print('handle_response:')
    print(status_code)
    print(payload)
    print(headers)
    if isinstance(payload, dict):
      # `OAuth2Request` is not JSON serializable
      payload.pop('request', None)
      payload = json_dumps(payload)
    return (payload, status_code, headers)

  def validate_consent_request(self, request, end_user=None):
    """ Validate current HTTP request for authorization page. This page
        is designed for resource owner to grant or deny the authorization::

        :param object request: tornado request
        :param end_user: end user

        :return: grant instance
    """
    print('==== validate_consent_request ===')
    req = self.create_oauth2_request(request)
    req.user = end_user
    grant = self.get_authorization_grant(req)
    print('==== GRANT: %s ===' % grant)
    grant.validate_consent_request()
    # session = req.state or generate_token(10)
    # self.server.updateSession(session, request=req, group=req.args.get('group'))
    if not hasattr(grant, 'prompt'):
      grant.prompt = None
    print('==== Session: %s' % req.state)
    print('==== Request:')
    pprint(req.data)
    print('============')
    self.updateSession(req.state, request=req)
    return grant, req.state
