from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from time import time
from authlib.oauth2 import OAuth2Error, ResourceProtector as _ResourceProtector
from authlib.oauth2.rfc6749 import MissingAuthorizationError, HttpRequest
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc6749.wrappers import OAuth2Token as _OAuth2Token


class OAuth2Token(_OAuth2Token):
  def __init__(self, params=None, **kwargs):
    kwargs.update(params or {})
    self.sub = kwargs.get('sub')
    self.isser = kwargs.get('iss')
    self.client_id = kwargs.get('client_id', kwargs.get('aud'))
    self.token_type = kwargs.get('token_type')
    self.access_token = kwargs.get('access_token')
    self.refresh_token = kwargs.get('refresh_token')
    self.scope = kwargs.get('scope')
    self.revoked = kwargs.get('revoked')
    self.issued_at = int(kwargs.get('issued_at', kwargs.get('iat', 0)))
    self.expires_in = int(kwargs.get('expires_in', 0))
    self.expires_at = int(kwargs.get('expires_at', kwargs.get('exp', 0)))
    if not self.expires_at and self.expires_in and self.issued_at:
      self.expires_at = self.issued_at + self.expires_in
    kwargs.update({'client_id': self.client_id
                  'token_type': self.token_type
                  'access_token': self.access_token
                  'refresh_token': self.refresh_token
                  'scope': self.scope
                  'revoked': self.revoked
                  'issued_at': self.issued_at
                  'expires_in': self.expires_in
                  'expires_at': self.expires_at})
    super(OAuth2Token, self).__init__(kwargs)
  
  @property
  def scopes(self):
    return self.scope.split(' ')
  
  @property
  def groups(self):
    return [s.split(':')[1] for s in self.scopes if s.startswith('g:')]

class ResourceProtector(_ResourceProtector):
  """ A protecting method for resource servers. Creating a ``require_oauth``
      decorator easily with ResourceProtector::

      from authlib.integrations.flask_oauth2 import ResourceProtector

      require_oauth = ResourceProtector()

      # add bearer token validator
      from authlib.oauth2.rfc6750 import BearerTokenValidator
      from project.models import Token

      class MyBearerTokenValidator(BearerTokenValidator):
          def authenticate_token(self, token_string):
              return Token.query.filter_by(access_token=token_string).first()

          def request_invalid(self, request):
              return False

          def token_revoked(self, token):
              return False

      require_oauth.register_token_validator(MyBearerTokenValidator())

      # protect resource with require_oauth

      class AuthHandler(tornado.web.RequestHandler):
      
          @require_oauth('profile')
          def get(self):
              if self.request.path == '/auth':
                  user = User.query.get(self.request.oauth_token.user_id)
                  self.finish(jsonify(user.to_dict()))

  """
  def __init__(self):
    validator = BearerTokenValidator(OAuth2Token)
    self._token_validators = {validator.TOKEN_TYPE: validator}

  def raise_error_response(self, error):
    """ Raise HTTPException for OAuth2Error. Developers can re-implement
        this method to customize the error response.

        :param error: OAuth2Error
        :raise: HTTPException
    """
    status = error.status_code
    body = json.dumps(dict(error.get_body()))
    headers = error.get_headers()
    raise_http_exception(status, body, headers)

  def acquire_token(self, request, scope=None, operator='AND'):
    """ A method to acquire current valid token with the given scope.

        :param request: Tornado HTTP request instance
        :param scope: string or list of scope values
        :param operator: value of "AND" or "OR"
        :return: token object
    """
    # headers = parse_request_headers(request)
    url = request.uri
    req = HttpRequest(request.method, url, request.body, request.headers)
    if not callable(operator):
        operator = operator.upper()
    token = self.validate_request(scope, req, operator)
    token_authenticated.send(sender=self.__class__, token=token)
    return token

  @contextmanager
  def acquire(self, scope=None, operator='AND'):
    """ The with statement of ``require_oauth``. Instead of using a
        decorator, you can use a with statement instead::

        @app.route('/api/user')
        def user_api():
            with require_oauth.acquire('profile') as token:
                user = User.query.get(token.user_id)
                return jsonify(user.to_dict())
    """
    try:
      yield self.acquire_token(scope, operator)
    except OAuth2Error as error:
      self.raise_error_response(error)

  def __call__(self, scope=None, operator='AND', optional=False):
    def wrapper(f):
      @functools.wraps(f)
      def decorated(request, *args, **kwargs):
        try:
          token = self.acquire_token(request, scope, operator)
          request.oauth_token = token
        except MissingAuthorizationError as error:
          if optional:
            request.oauth_token = None
            return f(request, *args, **kwargs)
          return return_error_response(error)
        except OAuth2Error as error:
          return return_error_response(error)
        return f(request, *args, **kwargs)
      return decorated
    return wrapper


class BearerTokenValidator(_BearerTokenValidator):
  """ Token validator
      
      Use:
      require_oauth = ResourceProtector()
      require_oauth.register_token_validator(BearerTokenValidator())
  """
  def __init__(self, realm=None):
    super(BearerTokenValidator, self).__init__(realm)

  def authenticate_token(self, aToken):
    """ A method to query token from database with the given token string.

        :param token_string: A string to represent the access_token.
        
        :return: token
    """
    # Read public key of DIRAC auth service
    with open('/opt/dirac/etc/grid-security/jwtRS256.key.pub', 'rb') as f:
      key = f.read()
    # Get claims and verify signature
    claims = jwt.decode(aToken, key)
    
    # Verify token
    claims.validate()

    return OAuth2Token(claims, access_token=aToken)

  def request_invalid(self, request):
    """ Request validation

        :param object request: request

        :return: bool
    """
    return False

  def token_revoked(self, token):
    """ If token can be revoked

        :param object token: token

        :return: bool
    """
    return token.revoked
