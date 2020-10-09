from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from authlib.integrations.sqla_oauth2 import OAuth2ClientMixin
from authlib.oauth2.rfc7591 import ClientRegistrationEndpoint as _ClientRegistrationEndpoint

from DIRAC.Core.Utilities import ThreadSafe
from DIRAC.Core.Utilities.DictCache import DictCache

__RCSID__ = "$Id$"

gCacheClient = ThreadSafe.Synchronizer()


class ClientManager(object):
  def __init__(self, database):
    self.__db = database
    self.__clients = DictCache()

  @gCacheClient
  def addClient(self, data):
    result = self.__db.addClient(data)
    if result['OK']:
      data = result['Value']
      self.__clients.add(data['client_id'], 24 * 3600, Client(data))
    return result

  @gCacheClient
  def getClient(self, clientID):
    client = self.__clients.get(clientID)
    if not client:
      result = self.__db.getClient(clientID)
      if result['OK']:
        client = Client(result['Value'])
        self.__clients.add(clientID, 24 * 3600, client)
    return client


class Client(OAuth2ClientMixin):
  def __init__(self, params):
    super(OAuth2ClientMixin, self).__init__()
    self.client_id = params['client_id']
    self.client_secret = params['client_secret']
    self.client_id_issued_at = params['client_id_issued_at']
    self.client_secret_expires_at = params['client_secret_expires_at']
    self.client_metadata = params['client_metadata']


class ClientRegistrationEndpoint(_ClientRegistrationEndpoint):
  def authenticate_user(self, request):
    return True

  def save_client(self, client_info, client_metadata, request):
    for k, v in [('grant_types',
                  ['authorization_code', 'urn:ietf:params:oauth:grant-type:device_code']),
                 ('response_types', ['code', 'device']),
                 ('token_endpoint_auth_method', 'none')]:
      if k not in client_metadata:
        client_metadata[k] = v

    if client_metadata['token_endpoint_auth_method'] == 'none':
      client_info['client_secret'] = ''
    else:
      client_info['client_secret'] = generate_token(48)

    client_info['client_metadata'] = client_metadata

    result = self.server.addClient(client_info)
    return Client(result['Value']) if result['OK'] else None
