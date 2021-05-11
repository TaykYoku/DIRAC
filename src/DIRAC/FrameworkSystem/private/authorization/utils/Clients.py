from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import json
import time

from authlib.integrations.sqla_oauth2 import OAuth2ClientMixin
from authlib.oauth2.rfc6749.util import scope_to_list, list_to_scope

from DIRAC import S_OK

__RCSID__ = "$Id$"

DEFAULT_SCOPE = 'proxy g: lifetime:'


class Client(OAuth2ClientMixin):
  def __init__(self, params):
    super(Client, self).__init__()
    client_metadata = params.get('client_metadata', {})
    client_metadata['scope'] = ' '.join([client_metadata.get('scope', ''), DEFAULT_SCOPE])
    self.client_id = params['client_id']
    self.client_secret = params.get('client_secret', '')
    self.client_id_issued_at = params.get('client_id_issued_at', int(time.time()))
    self.client_secret_expires_at = params.get('client_secret_expires_at', 0)
    if isinstance(client_metadata, dict):
      self._client_metadata = json.dumps(client_metadata)
    else:
      self._client_metadata = client_metadata

  def get_allowed_scope(self, scope):
    scopes = scope_to_list(super(Client, self).get_allowed_scope(scope))
    return list_to_scope([s for s in scopes if s.startswith('g:') or s.startswith('lifetime:')])
