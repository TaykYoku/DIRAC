from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from authlib.oauth2.rfc7009 import RevocationEndpoint as _RevocationEndpoint

from DIRAC import gLogger


class RevocationEndpoint(_RevocationEndpoint):

  def query_token(self, token, token_type_hint, client):
    """ Query requested token from database. """
    result = self.server.db.getToken(token, token_type_hint)
    if not result['OK']:
      gLogger.error(result['Message'])
      return None
    rv = result['Value']
    client_id = client.get_client_id()
    if rv and rv.client_id == client_id:
      return rv
    return None

  def revoke_token(self, token):
    """ Mark the give token as revoked. """
    result = self.server.db.revokeToken(token)
    if not result['OK']:
      gLogger.error(result['Message'])
