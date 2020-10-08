from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from authlib.oauth2 import (
    OAuth2Error,
    ResourceProtector as _ResourceProtector
)
from authlib.oauth2.rfc6749 import (
    MissingAuthorizationError,
    HttpRequest,
)


class TokenManager(object):
  def __init__(self, addTime=300, maxAge=3600 * 12):
    self.__tokens = DictCache()
    self.__addTime = addTime
    self.__maxAge = maxAge

  @gCacheSession
  def addSession(self, session, exp=None, **kwargs):
    exp = exp or self.__addTime
    if not isinstance(session, Session):
      session = Session(session, kwargs, exp)
    if session.age > self.__maxAge:
      return self.__sessions.delete(session.id)
    self.__sessions.add(session.id, min(exp, self.__maxAge), session)

  @gCacheSession
  def getSession(self, session):
    return self.__sessions.get(session.id if isinstance(session, Session) else session)

  @gCacheSession
  def getSessions(self):
    return self.__sessions.getDict()
  
  @gCacheSession
  def removeSession(self, session):
    self.__sessions.delete(session.id if isinstance(session, Session) else session)

  def updateSession(self, session, exp=None, **kwargs):
    exp = exp or self.__addTime
    sObj = self.getSession(session.id if isinstance(session, Session) else session)
    if sObj and sObj.age < self.__maxAge:
      if (sObj.age + exp) > self.__maxAge:
        exp = self.__maxAge - sObj.age
      for k, v in kwargs.items() or {}:
        sObj[k] = v
      self.addSession(sObj, exp)
  
  def getSessionByOption(self, key, value):
    if key and value:
      sessions = self.getSessions()
      for session, data in sessions.items():
        if data.get(key) == value:
          return session, data
    return None, None


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

# require_oauth = ResourceProtector()
# require_oauth.register_token_validator(BearerTokenValidator(OAuth2Token))