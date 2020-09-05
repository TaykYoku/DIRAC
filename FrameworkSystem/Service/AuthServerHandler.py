""" The OAuth service provides a toolkit to authoticate throught OIDC session.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from werkzeug.utils import import_string
import json
from tornado.httpclient import HTTPResponse
# from flask import Response, json
from authlib.deprecate import deprecate
from authlib.oauth2 import (
    OAuth2Request,
    HttpRequest,
    AuthorizationServer as _AuthorizationServer,
)
from authlib.oauth2.rfc6750 import BearerToken
from authlib.oauth2.rfc8414 import AuthorizationServerMetadata
from authlib.common.security import generate_token
from authlib.common.encoding import to_unicode
from .signals import client_authenticated, token_revoked

from tornado.escape import json_decode
from authlib.common.encoding import to_unicode

from DIRAC.Core.Tornado.Server.TornadoService import TornadoService


def create_oauth_request(request, request_cls, use_json=False):
    if isinstance(request, request_cls):
        return request
    body = None
    if request.method == 'POST':
        body = json_decode(request.body)

    return request_cls(request.method, request.uri, body, request.headers)

__RCSID__ = "$Id$"

# self.generate_token = self.create_bearer_token_generator(app.settings)

class AuthServerHandler(TornadoService, _AuthorizationServer):
  """ Authentication manager
  """
    """Flask implementation of :class:`authlib.oauth2.rfc6749.AuthorizationServer`.
    Initialize it with ``query_client``, ``save_token`` methods and Flask
    app instance::

        def query_client(client_id):
            return Client.query.filter_by(client_id=client_id).first()

        def save_token(token, request):
            if request.user:
                user_id = request.user.get_user_id()
            else:
                user_id = None
            client = request.client
            tok = Token(
                client_id=client.client_id,
                user_id=user.get_user_id(),
                **token
            )
            db.session.add(tok)
            db.session.commit()

        server = AuthorizationServer(app, query_client, save_token)
        # or initialize lazily
        server = AuthorizationServer()
        server.init_app(app, query_client, save_token)
    """

    metadata_class = AuthorizationServerMetadata

    @classmethod
    def initializeHandler(cls, serviceInfo):
      """ Handler initialization
      """
      cls.__db = AuthDB()
      
      AuthorizationServer.__init__(cls, query_client=cls.query_client,
                                   save_token=cls.save_token)
      self.generate_token = self.create_bearer_token_generator(self.metadata)

    def query_client(self, client_id):
      """ Method to get client object by ID

          :param str client_id: client ID

          :return: object/dict
      """
      return self.__db.getClient(client_id)

    def save_token(self, token, request):
      """ Save token

          :param dict token: token obj
          :param request: request obj
      """
        if request.user:
            user_id = request.user.get_user_id()
        else:
            user_id = None
        client = request.client
        # tok = OAuth2Token(client_id=client.client_id, user_id=user.get_user_id(), **token)
        self.__db.saveToken(token)

    def get_error_uris(self, request):
        error_uris = self.metadata.get('error_uris')
        if error_uris:
            return dict(error_uris)

    def create_oauth2_request(self, request):
        return create_oauth_request(request, OAuth2Request)

    def create_json_request(self, request):
        return create_oauth_request(request, HttpRequest, True)

    def handle_response(self, status_code, payload, headers):
        if isinstance(payload, dict):
            payload = json.dumps(payload)
        headersObj = HTTPHeaders()
        for k, v in headers:
            headersObj.add(k, v)
        return HTTPResponse(payload, code=status_code, headers=headersObj)

    def send_signal(self, name, *args, **kwargs):
        if name == 'after_authenticate_client':
            client_authenticated.send(self, *args, **kwargs)
        elif name == 'after_revoke_token':
            token_revoked.send(self, *args, **kwargs)

    def create_token_expires_in_generator(self, config):
        """Create a generator function for generating ``expires_in`` value.
        Developers can re-implement this method with a subclass if other means
        required. The default expires_in value is defined by ``grant_type``,
        different ``grant_type`` has different value. It can be configured
        with::

            OAUTH2_TOKEN_EXPIRES_IN = {
                'authorization_code': 864000,
                'urn:ietf:params:oauth:grant-type:jwt-bearer': 3600,
            }
        """
        expires_conf = config.get('OAUTH2_TOKEN_EXPIRES_IN')
        return create_token_expires_in_generator(expires_conf)

    def create_bearer_token_generator(self, config):
        """Create a generator function for generating ``token`` value. This
        method will create a Bearer Token generator with
        :class:`authlib.oauth2.rfc6750.BearerToken`. By default, it will not
        generate ``refresh_token``, which can be turn on by configuration
        ``OAUTH2_REFRESH_TOKEN_GENERATOR=True``.
        """
        conf = config.get('OAUTH2_ACCESS_TOKEN_GENERATOR', True)
        access_token_generator = create_token_generator(conf, 42)

        conf = config.get('OAUTH2_REFRESH_TOKEN_GENERATOR', False)
        refresh_token_generator = create_token_generator(conf, 48)

        expires_generator = self.create_token_expires_in_generator(config)
        return BearerToken(
            access_token_generator,
            refresh_token_generator,
            expires_generator
        )

    def validate_consent_request(self, request, end_user=None):
        """Validate current HTTP request for authorization page. This page
        is designed for resource owner to grant or deny the authorization::

            class AuthorizationHandler(RequestHandler)
              def get():
                  try:
                      grant = server.validate_consent_request(self.request, end_user=current_user)
                      self.render(
                          'authorize.html',
                          grant=grant,
                          user=current_user
                      )
                  except OAuth2Error as error:
                      self.render(
                          'error.html',
                          error=error
                      )
        """
        req = self.create_oauth2_request(request)
        req.user = end_user

        grant = self.get_authorization_grant(req)
        grant.validate_consent_request()
        if not hasattr(grant, 'prompt'):
            grant.prompt = None
        return grant


def create_token_expires_in_generator(expires_in_conf=None):
    data = {}
    data.update(BearerToken.GRANT_TYPES_EXPIRES_IN)
    if expires_in_conf:
        data.update(expires_in_conf)

    def expires_in(client, grant_type):
        return data.get(grant_type, BearerToken.DEFAULT_EXPIRES_IN)

    return expires_in


def create_token_generator(token_generator_conf, length=42):
    if callable(token_generator_conf):
        return token_generator_conf

    if isinstance(token_generator_conf, str):
        return import_string(token_generator_conf)
    elif token_generator_conf is True:
        def token_generator(*args, **kwargs):
            return generate_token(length)
        return token_generator
