from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from time import time
from authlib.oauth2 import OAuth2Error
from authlib.oauth2.rfc6749.grants import AuthorizationEndpointMixin, ImplicitGrant as _ImplicitGrant
from authlib.oidc.core.grants import OpenIDImplicitGrant as _OpenIDImplicitGrant

from DIRAC import gLogger

log = gLogger.getSubLogger(__name__)


# class ImplicitGrant(_ImplicitGrant):



class OpenIDImplicitGrant(_OpenIDImplicitGrant):
  def validate_authorization_request(self):
    redirect_uri = super(OpenIDImplicitGrant, self).validate_authorization_request()
    session = self.request.state or generate_token(10)
    self.server.updateSession(session, request=self.request, group=self.request.args.get('group'))
    return redirect_uri
  
  def get_jwt_config(self):
    with open('/opt/dirac/etc/grid-security/jwtRS256.key', 'rb') as f:
      key = f.read()
    issuer = self.server.metadata['issuer']
    return dict(key=key, alg='RS256', iss=issuer, exp=3600)

  def generate_user_info(self, user, scopes):
    print('=== generate_user_info ===')
    print(user)
    print(scopes)
    data = self.server.getSession(self.request.state)
    return UserInfo(sub=data['userID'], profile=data['profile'], grp=data['group'])

  def exists_nonce(self, nonce, request):
    # TODO: need to implement
    return False