from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from authlib.oauth2.rfc6749.grants import RefreshTokenGrant as _RefreshTokenGrant
from authlib.oauth2.base import OAuth2Error


class RefreshTokenGrant(_RefreshTokenGrant):

  def authenticate_refresh_token(self, refresh_token):
    """ Get credential for token

        :param str refresh_token: refresh token

        :return: object
    """
    # Check auth session
    result = self.server.db.getTokenByRefreshToken(refresh_token)
    if not result['OK']:
      raise OAuth2Error('Cannot get token', result['Message'])
    return result['Value']

  def authenticate_user(self, credential):
    """ Authorize user

        :param object credential: credential

        :return: str
    """
    return credential.sub

  def revoke_old_credential(self, credential):
    """ Remove old credential

        :param object credential: credential
    """
    self.server.db.removeToken(credential['refresh_token'])
