""" DIRAC AuthManager Client class encapsulates the methods exposed
    by the AuthManager service.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import six
import requests

from DIRAC import gLogger, S_OK, S_ERROR
from DIRAC.Core.Base.Client import Client, createClient
from DIRAC.Core.Utilities import DIRACSingleton
from DIRAC.ConfigurationSystem.Client.Utilities import getAuthAPI

from DIRAC.FrameworkSystem.Client.AuthManagerData import gAuthManagerData

__RCSID__ = "$Id$"


@createClient('Framework/AuthManager')
@six.add_metaclass(DIRACSingleton.DIRACSingleton)
class AuthManagerClient(Client):
  """ Authentication manager
  """

  def __init__(self, **kwargs):
    """ Constructor
    """
    super(AuthManagerClient, self).__init__(**kwargs)
    self.setServer('Framework/AuthManager')

  def getTokenWithAuth(self, idP, group, livetime):
    gLogger.info('%s authorization for %s.' % (idP, group))

    result = IdProviderFactory().getIdProvider(idP, sessionManager=self.__getRPC())
    if not result['OK']:
      return result
    provObj = result['Value']
    return provObj.getTokenWithAuth(group, livetime)

  def submitAuthorizeFlow(self, providerName, group=None):
    """ Register new session and return dict with authorization url and session number

        :param str providerName: provider name
        :param str session: session identificator

        :return: S_OK(dict)/S_ERROR() -- dictionary contain next keys:
                 Status -- session status
                 UserName -- user name, returned if status is 'ready'
                 Session -- session id, returned if status is 'needToAuth'
    """
    authAPI = getAuthAPI()
    if not authAPI:
      return S_ERROR('Cannot read authorithation REST endpoint.')

    try:
      r = requests.get(*args, **kwargs)
      r.raise_for_status()
      token = r.json()
    except self.exceptions.Timeout:
      return S_ERROR('Time out')
    except self.exceptions.RequestException as ex:
      return S_ERROR(r.content or ex)

  def parseAuthResponse(self, response, state):
    """ Fill session by user profile, tokens, comment, OIDC authorize status, etc.
        Prepare dict with user parameters, if DN is absent there try to get it.
        Create new or modify existend DIRAC user and store the session

        :param dict response: authorization response
        :param basestring state: session number

        :return: S_OK(dict)/S_ERROR()
    """
    result = self._getRPC().parseAuthResponse(response, state)
    if result['OK'] and result['Value']['Status'] in ['authed', 'redirect']:
      gAuthManagerData.updateProfiles(result['Value']['upProfile'])
      gAuthManagerData.updateSessions(result['Value']['upSession'])

    return result


gSessionManager = AuthManagerClient()
