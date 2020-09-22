import json
from time import time
from pprint import pprint
from tornado.escape import json_decode
from tornado.httpclient import HTTPResponse
from tornado.httputil import HTTPHeaders
from authlib.deprecate import deprecate
from authlib.jose import jwt, JsonWebSignature
from authlib.oauth2 import (
    OAuth2Request,
    HttpRequest,
    AuthorizationServer as _AuthorizationServer,
)
from authlib.oauth2.rfc8628 import (
    DeviceAuthorizationEndpoint as _DeviceAuthorizationEndpoint,
    DeviceCodeGrant as _DeviceCodeGrant,
    DeviceCredentialDict,
)
from authlib.oauth2.rfc6749 import grants, errors
from authlib.oauth2.rfc6750 import BearerToken
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oauth2.rfc8414 import AuthorizationServerMetadata
from authlib.integrations.sqla_oauth2 import OAuth2ClientMixin
from authlib.common.security import generate_token
from authlib.common.encoding import to_unicode, json_dumps, json_b64encode, urlsafe_b64decode, json_loads
# from .signals import client_authenticated, token_revoked

from DIRAC import gLogger, S_OK, S_ERROR
from DIRAC.Core.Utilities import ThreadSafe
from DIRAC.Core.Utilities.DictCache import DictCache
from DIRAC.FrameworkSystem.DB.AuthDB2 import AuthDB2
from DIRAC.ConfigurationSystem.Client.Helpers.CSGlobals import getSetup
from DIRAC.Resources.IdProvider.IdProviderFactory import IdProviderFactory
from DIRAC.FrameworkSystem.Client.AuthManagerClient import gSessionManager
# from DIRAC.FrameworkSystem.Client.AuthManagerData import gAuthManagerData

gCacheClient = ThreadSafe.Synchronizer()
gCacheSession = ThreadSafe.Synchronizer()

class Client(OAuth2ClientMixin):
  def __init__(self, params):
    super(OAuth2ClientMixin, self).__init__()
    self.client_id = params['client_id']
    self.client_secret = params['client_secret']
    self.client_id_issued_at = params['client_id_issued_at']
    self.client_secret_expires_at = params['client_secret_expires_at']
    self.client_metadata = params['client_metadata']

class OAuth2Code(dict):
  def __init__(self, params):
    params['auth_time'] = params.get('auth_time', int(time()))
    super(OAuth2Code, self).__init__(params)

  @property
  def user(self):
    return self.get('user_id')
  
  @property
  def code_challenge(self):
    return self.get('code_challenge')

  @property
  def code_challenge_method(self):
    return self.get('code_challenge_method', 'pain')

  def is_expired(self):
    return self.get('auth_time') + 300 < time()

  def get_redirect_uri(self):
    return self.get('redirect_uri')

  def get_scope(self):
    return self.get('scope', '')

  def get_auth_time(self):
    return self.get('auth_time')

class DeviceAuthorizationEndpoint(_DeviceAuthorizationEndpoint):
  def get_verification_uri(self):
    return 'https://marosvn32.in2p3.fr/DIRAC/auth/device'

  def save_device_credential(self, client_id, scope, data):
    data = {}
    data['flow'] = 'device'
    data['client_id'] = client_id
    data['scope'] = self.get_argument('scope', '')
    data['group'] = self.get_argument('group', None)
    data['Provider'] = self.get_argument('provider', None)
    self.addSession(generate_token(20), data)

class DeviceCodeGrant(_DeviceCodeGrant):
  def query_device_credential(self, device_code):
    _, data = self.getSessionByOption('device_code', device_code)
    if not data:
      return None
    data['expires_at'] = data['expires_in'] + int(time())
    data['device_code'] = device_code
    data['scope'] = ''
    data['interval'] = 5
    data['verification_uri'] = 'https://marosvn32.in2p3.fr/DIRAC/auth/device'
    return DeviceCredentialDict(data)

  def query_user_grant(self, user_code):
    _, data = self.getSessionByOption('user_code', user_code)
    return (data['user_id'], data['group']) if data else None

  def should_slow_down(self, credential, now):
    return False

class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
  TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic', 'client_secret_post', 'none']

  def save_authorization_code(self, code, request):
    # print('========= save_authorization_code =============')
    # pprint(request.args)
    # session, _ = self.getSessionByOption('client_id', request.args['client_id'])
    # self.updateSession(session, code=code)
    pass
  
  def delete_authorization_code(self, authorization_code):
    # session, _ = self.getSessionByOption('code', authorization_code)
    # if session:
    #   self.updateSession(session, code=None)
    pass

  def query_authorization_code(self, code, client):
    """ Parse authorization code

        :param code: authorization code as JWS
        :param client: client

        :return: OAuth2Code or None
    """
    jws = JsonWebSignature(algorithms=['RS256'])
    with open('/opt/dirac/etc/grid-security/jwtRS256.key', 'rb') as f:
      key = f.read()
    data = jws.deserialize_compact(code, key)
    try:
      item = OAuth2Code(json_loads(urlsafe_b64decode(data['payload'])))
    except Exception as e:
      return None
    if not item.is_expired():
      return item

  def authenticate_user(self, authorization_code):
      return authorization_code.user
  
  def generate_authorization_code(self):
    """ return code """
    print('========= generate_authorization_code =========')
    pprint(self.__dict__)
    jws = JsonWebSignature(algorithms=['RS256'])
    protected = {'alg': 'RS256'}
    code = OAuth2Code({'user_id': None, 'scope': None,  # how to get it
                       'client_id': self.request.args['client_id'], 'redirect_uri': None,  # how to get it
                       'code_challenge': self.request.args.get('code_challenge'),
                       'code_challenge_method': self.request.args.get('code_challenge_method')})
    payload = json_b64encode(code)
    with open('/opt/dirac/etc/grid-security/jwtRS256.key', 'rb') as f:
      key = f.read()
    return jws.serialize_compact(protected, payload, key)


class AuthorizationServer(_AuthorizationServer):
  """ Flask implementation of :class:`authlib.oauth2.rfc6749.AuthorizationServer`.
      Initialize it with ``query_client``, ``save_token`` methods and Flask
      app instance::

          server = AuthorizationServer()
          # or initialize lazily
          server = AuthorizationServer()
          server.init_app(app, query_client, save_token)
  """
  metadata_class = AuthorizationServerMetadata

  def __init__(self):
    self.__db = AuthDB2()
    self.idps = IdProviderFactory()
    self.cacheSession = DictCache()
    self.cacheClient = DictCache()
    super(AuthorizationServer, self).__init__(query_client=self.getClient,
                                              save_token=self.__db.storeToken)
    self.generate_token = BearerToken(self.access_token_generator)
    self.config = {}

    # TODO: get metadata from CS to dict
    # result = getAuthServerMetadata()
    # if not result['OK']:
    #   raise result['Message']
    # metadata = result['Value']
    metadata = {'issuer': 'https://marosvn32.in2p3.fr/DIRAC/auth',
                'authorization_endpoint': 'https://marosvn32.in2p3.fr/DIRAC/auth/authorization',
                'token_endpoint': 'https://marosvn32.in2p3.fr/DIRAC/auth/token',
                'registration_endpoint': 'https://marosvn32.in2p3.fr/DIRAC/auth/register',
                'response_types_supported': ['code'],
                'grant_types_supported': ['authorization_code'],
                'code_challenge_methods_supported': ['pain', 'S256']}
    if metadata.get('OAUTH2_METADATA_FILE'):
      with open(metadata['OAUTH2_METADATA_FILE']) as f:
        metadata = json.load(f)
    metadata = self.metadata_class(metadata)
    metadata.validate()
    self.metadata = metadata

    self.config.setdefault('error_uris', metadata.get('OAUTH2_ERROR_URIS'))
    if metadata.get('OAUTH2_JWT_ENABLED'):
      deprecate('Define "get_jwt_config" in OpenID Connect grants', '1.0')
      self.init_jwt_config(metadata)
    
    self.register_grant(AuthorizationCodeGrant, [CodeChallenge(required=True)])
    self.register_endpoint(DeviceAuthorizationEndpoint)

  @gCacheClient
  def addClient(self, data):
    result = self.__db.addClient(data)
    if result['OK']:
      data = result['Value']
      self.cacheClient.add(data['client_id'], 24 * 3600, Client(data))
    return result

  @gCacheClient
  def getClient(self, clientID):
    client = self.cacheClient.get(clientID)
    if not client:
      result = self.__db.getClient(clientID)
      if result['OK']:
        client = Client(result['Value'])
        self.cacheClient.add(clientID, 24 * 3600, client)
    return client
  
  @gCacheSession
  def addSession(self, session, data={}, exp=300, **kwargs):
    data.update(kwargs)
    data['Status'] = data.get('Status', 'submited')
    self.cacheSession.add(session, exp, data)
  
  @gCacheSession
  def getSession(self, session=None):
    return self.cacheSession.get(session) if session else self.cacheSession.getDict()
  
  @gCacheSession
  def removeSession(self, session):
    self.cacheSession.delete(session)

  def updateSession(self, session, data={}, exp=300, **kwargs):
    data.update(kwargs)
    origData = self.getSession(session) or {}
    for k, v in data.items():
      origData[k] = v
    self.addSession(session, origData, exp)
  
  def getSessionByOption(self, key, value):
    if key and value:
      sessions = self.getSession()
      for session, data in sessions.items():
        if data.get(key) == value:
          return session, data
    return None, {}

  def getIdPAuthorization(self, providerName, mainSession):
    """ Submit subsession and return dict with authorization url and session number

        :param str providerName: provider name
        :param str session: session identificator

        :return: S_OK(dict)/S_ERROR() -- dictionary contain next keys:
                 Status -- session status
                 UserName -- user name, returned if status is 'ready'
                 Session -- session id, returned if status is 'needToAuth'
    """
    # Start subsession
    session = generate_token(10)
    self.addSession(session, mainSession=mainSession, Provider=providerName)

    result = self.idps.getIdProvider(providerName, sessionManager=self.__db)
    if result['OK']:
      result = result['Value'].submitNewSession(session)
      if result['OK']:
        authURL, sessionParams = result['Value']
        self.updateSession(session, sessionParams)
    return S_OK(authURL) if result['OK'] else result

  def parseIdPAuthorizationResponse(self, response, session):
    """ Fill session by user profile, tokens, comment, OIDC authorize status, etc.
        Prepare dict with user parameters, if DN is absent there try to get it.
        Create new or modify existend DIRAC user and store the session

        :param str providerName: identity provider name
        :param dict response: authorization response
        :param dict session: session data dictionary

        :return: S_OK(dict)/S_ERROR()
    """
    # Check session
    sessionDict = self.getSession(session)
    if not sessionDict:
      return S_ERROR("Session expired.")
    
    mainSession = sessionDict['mainSession']
    providerName = sessionDict['Provider']

    # Parse response
    print('------> self.idps.getIdProvider')
    result = self.idps.getIdProvider(providerName, sessionManager=self.__db)
    if result['OK']:
      print('------> idp.parseAuthResponse')
      result = result['Value'].parseAuthResponse(response, sessionDict)
      if result['OK']:
        self.removeSession(session)
        # FINISHING with IdP auth result
        username, userProfile = result['Value']
        print('------> gSessionManager.parseAuthResponse')
        result = gSessionManager.parseAuthResponse(providerName, username, userProfile)
        print('-- finishing --')
    if not result['OK']:
      self.updateSession(mainSession, Status='failed', Comment=result['Message'])
      return result
    
    username, profile = result['Value']
    if username and profile:
      self.updateSession(mainSession, username=username, profile=profile, userID=profile['ID'])

    return S_OK(mainSession)

  def access_token_generator(self, client, grant_type, user, scope):
    print('GENERATE ACCESS TOKEN')
    # TODO: need to use self.config attributes
    header = {'alg': 'RS256'}
    payload = {'sub': user,
               'grp': scope,
               'iss': getSetup(),
               'exp': 12 * 3600}
    # Read private key of DIRAC auth service
    with open('/opt/dirac/etc/grid-security/jwtRS256.key', 'r') as f:
      key = f.read()
    # Need to use enum==0.3.1 for python 2.7
    return jwt.encode(header, payload, key)

  def init_jwt_config(self, config): #
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
    print('==== create_oauth2_request ===')
    if isinstance(request, method_cls):
      return request
    body = None
    print(request.body)
    print(request.body_arguments)
    print(request.query_arguments)
    print(request.arguments)
    if request.method == 'POST':
      pprint(request.body)
      pprint(request)
      if use_json:
        ## ???
        body = json_decode(request.body)
      else:
        body = json_decode(request.body_arguments)

    return method_cls(request.method, request.uri, body, request.headers)

  def create_json_request(self, request):
    return create_oauth2_request(request, HttpRequest, True)

  def handle_response(self, status_code, payload, headers):
    if isinstance(payload, dict):
      payload = json.dumps(payload)
    # headersObj = HTTPHeaders()
    # for k, v in headers:
    #   headersObj.add(k, v)
    return (payload, status_code, headers)
    # return HTTPResponse(payload, code=status_code, headers=headersObj)

  # def send_signal(self, name, *args, **kwargs):
  #     if name == 'after_authenticate_client':
  #         client_authenticated.send(self, *args, **kwargs)
  #     elif name == 'after_revoke_token':
  #         token_revoked.send(self, *args, **kwargs)

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
    print('==== GRANT ===')
    print(grant)
    grant.validate_consent_request()
    if not hasattr(grant, 'prompt'):
      grant.prompt = None
    return grant
