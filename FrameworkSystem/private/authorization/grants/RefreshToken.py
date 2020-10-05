from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from authlib.oauth2.rfc6749.grants import RefreshTokenGrant as _RefreshTokenGrant

class RefreshTokenGrant(_RefreshTokenGrant):
    def authenticate_refresh_token(self, refresh_token):
      # Check token
      # --
      # If it not long lived look it in a cache
      # Else look it in a db
      # --
      # return credential
      try:
        item = OAuth2Token.objects.get(refresh_token=refresh_token)
        if item.is_refresh_token_active():
          return item
      except OAuth2Token.DoesNotExist:
        return None

    def authenticate_user(self, credential):
      return credential.user

    def revoke_old_credential(self, credential):
      credential.revoked = True
      credential.save()
      return credential
