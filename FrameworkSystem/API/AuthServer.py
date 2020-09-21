import json
from time import time
from pprint import pprint
from tornado.escape import json_decode
from tornado.httpclient import HTTPResponse
from authlib.deprecate import deprecate
from authlib.jose import jwt, JsonWebSignature
from authlib.oauth2 import (
    OAuth2Request,
    HttpRequest,
    AuthorizationServer as _AuthorizationServer,
)
from authlib.oauth2.rfc6749 import grants, errors
from authlib.oauth2.rfc6750 import BearerToken
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oauth2.rfc8414 import AuthorizationServerMetadata
from authlib.integrations.sqla_oauth2 import OAuth2ClientMixin
from authlib.common.security import generate_token
from authlib.common.encoding import to_unicode, json_dumps, json_b64encode, urlsafe_b64decode, json_loads
# from .signals import client_authenticated, token_revoked

from DIRAC.Core.Utilities import ThreadSafe
from DIRAC.Core.Utilities.DictCache import DictCache
from DIRAC.FrameworkSystem.DB.AuthDB2 import AuthDB2
from DIRAC.ConfigurationSystem.Client.Helpers.CSGlobals import getSetup

gCacheClient = ThreadSafe.Synchronizer()
gCacheSession = ThreadSafe.Synchronizer()

class Client(OAuth2ClientMixin):
  def __init__(self, params):
    super(OAuth2ClientMixin, self).__init__(params)
    self.client_id = params['client_id']
    self.client_secret = params['client_secret']
    self.client_id_issued_at = params['client_id_issued_at']
    self.client_secret_expires_at = params['client_secret_expires_at']
    self._client_metadata = params['_client_metadata']

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


class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
  TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic', 'client_secret_post', 'none']

  def save_authorization_code(self, code, request):
    pass
  
  def delete_authorization_code(self, authorization_code):
    pass

  def query_authorization_code(self, code, client):
    """ Parse authorization code

        :param code: authorization code as JWS
        :param client: client

        :return: OAuth2Code or None
    """
    jws = JsonWebSignature(algorithms=['RS256'])
    with open('private.pem', 'rb') as f:
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
    jws = JsonWebSignature(algorithms=['RS256'])
    protected = {'alg': 'RS256'}
    code = OAuth2Code({'user_id': None, 'scope': None,  # how to get it
                       'client_id': None, 'redirect_uri': None,  # how to get it
                       'code_challenge': self.request.args.get('code_challenge'),
                       'code_challenge_method': self.request.args.get('code_challenge_method')})
    payload = json_b64encode(code)
    with open('private.pem', 'rb') as f:
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
    if request.method == 'POST':
      if use_json:
        ## ???
        body = json_decode(request.body)
      else:
        body = json_decode(request.body)

    return method_cls(request.method, request.uri, body, request.headers)

  def create_json_request(self, request):
    return create_oauth2_request(request, HttpRequest, True)

  def handle_response(self, status_code, payload, headers):
    if isinstance(payload, dict):
      payload = json.dumps(payload)
    headersObj = HTTPHeaders()
    for k, v in headers:
      headersObj.add(k, v)
    return HTTPResponse(payload, code=status_code, headers=headersObj)

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
