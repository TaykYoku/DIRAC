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
from DIRAC.Resources.IdProvider.IdProviderFactory import IdProviderFactory
from DIRAC.ConfigurationSystem.Client.Utilities import getAuthAPI

from DIRAC.FrameworkSystem.Client.AuthManagerData import gAuthManagerData

__RCSID__ = "$Id$"


@createClient('Framework/AuthManager')
@six.add_metaclass(DIRACSingleton.DIRACSingleton)
class AuthManagerClient(Client):
  """ Authentication manager
  """

  def __init__(self, *args, **kwargs):
    """ Constructor
    """
    super(AuthManagerClient, self).__init__(*args, **kwargs)
    self.setServer('Framework/AuthManager')

  def submitAuthorizeFlow(self, providerName, session):
    """ Register new session and return dict with authorization url and session number

        :param str providerName: provider name
        :param str session: session identificator

        :return: S_OK(dict)/S_ERROR() -- dictionary contain next keys:
                 Status -- session status
                 UserName -- user name, returned if status is 'ready'
                 Session -- session id, returned if status is 'needToAuth'
    """
    result = IdProviderFactory().getIdProvider(providerName, sessionManager=self.__getRPC())
    if not result['OK']:
      return result
    provObj = result['Value']
    return provObj.submitNewSession(session)

  def parseAuthResponse(self, providerName, response, session):
    """ Fill session by user profile, tokens, comment, OIDC authorize status, etc.
        Prepare dict with user parameters, if DN is absent there try to get it.
        Create new or modify existend DIRAC user and store the session

        :param str providerName: identity provider name
        :param dict response: authorization response
        :param dict session: session data dictionary

        :return: S_OK(dict)/S_ERROR()
    """
    result = self._getRPC().parseAuthResponse(providerName, response, session)
    if result['OK'] and result['Value']:
      _ profile = result['Value']
      gAuthManagerData.updateProfiles(profile['ID'], profile)
    return result

gSessionManager = AuthManagerClient()
