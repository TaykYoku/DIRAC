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
from DIRAC.FrameworkSystem.Client.NotificationClient import NotificationClient

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

  def getTokenWithAuth(self, idP, group, livetime):
    gLogger.info('%s authorization for %s.' % (idP, group))

    result = IdProviderFactory().getIdProvider(idP, sessionManager=self.__getRPC())
    if not result['OK']:
      return result
    provObj = result['Value']
    return provObj.getTokenWithAuth(group, livetime)

  def submitAuthorizeFlow(self, providerName, session):
    """ Register new session and return dict with authorization url and session number

        :param str providerName: provider name
        :param str session: session identificator

        :return: S_OK(dict)/S_ERROR() -- dictionary contain next keys:
                 Status -- session status
                 UserName -- user name, returned if status is 'ready'
                 Session -- session id, returned if status is 'needToAuth'
    """
    result = IdProviderFactory().getIdProvider(idP)
    if not result['OK']:
      return result
    provObj = result['Value']
    return provObj.submitNewSession(session)
    # authAPI = getAuthAPI()
    # if not authAPI:
    #   return S_ERROR('Cannot read authorithation REST endpoint.')

    # try:
    #   r = requests.get(*args, **kwargs)
    #   r.raise_for_status()
    #   token = r.json()
    # except self.exceptions.Timeout:
    #   return S_ERROR('Time out')
    # except self.exceptions.RequestException as ex:
    #   return S_ERROR(r.content or ex)

  def parseAuthResponse(self, providerName, response, session):
    """ Fill session by user profile, tokens, comment, OIDC authorize status, etc.
        Prepare dict with user parameters, if DN is absent there try to get it.
        Create new or modify existend DIRAC user and store the session

        :param str providerName: identity provider name
        :param dict response: authorization response
        :param dict session: session data dictionary

        :return: S_OK(dict)/S_ERROR()
    """
    result = IdProviderFactory().getIdProvider(providerName, sessionManager=self.__getRPC())
    if not result['OK']:
      return result
    provObj = result['Value']
    result = provObj.parseAuthResponse(response, session)
    if not result['OK']:
      return result
    
    # FINISHING with IdP auth result
    userProfile = result['Value']['UsrOptns']
    username = result['Value']['username']

    # Is ID registred?
    userID = userProfile['ID']
    result = getUsernameForID(userID)
    if not result['OK']:
      comment = '%s ID is not registred in the DIRAC.' % userID
      result = self.__registerNewUser(provider, username, userProfile)
      if result['OK']:
        comment += ' Administrators have been notified about you.'
      else:
        comment += ' Please, contact the DIRAC administrators.'
      return S_ERROR(comment)
    return S_OK((result['Value'], userProfile))

    # result = self._getRPC().parseAuthResponse(response, state)
    # if result['OK'] and result['Value']['Status'] in ['authed', 'redirect']:
    #   gAuthManagerData.updateProfiles(result['Value']['upProfile'])
    #   gAuthManagerData.updateSessions(result['Value']['upSession'])

    # return result
  
  def __registerNewUser(self, provider, username, userProfile):
    """ Register new user

        :param str provider: provider
        :param str username: user name
        :param dict userProfile: user information dictionary

        :return: S_OK()/S_ERROR()
    """
    mail = {}
    mail['subject'] = "[SessionManager] User %s to be added." % username
    mail['body'] = 'User %s was authenticated by ' % userProfile['FullName']
    mail['body'] += provider
    mail['body'] += "\n\nAuto updating of the user database is not allowed."
    mail['body'] += " New user %s to be added," % username
    mail['body'] += "with the following information:\n"
    mail['body'] += "\nUser name: %s\n" % username
    mail['body'] += "\nUser profile:\n%s" % pprint.pformat(userProfile)
    mail['body'] += "\n\n------"
    mail['body'] += "\n This is a notification from the DIRAC AuthManager service, please do not reply.\n"
    result = S_OK()
    for addresses in getEmailsForGroup('dirac_admin'):
      result = NotificationClient().sendMail(addresses, mail['subject'], mail['body'], localAttempt=False)
      if not result['OK']:
        self.log.error(result['Message'])
    if result['OK']:
      self.log.info(result['Value'], "administrators have been notified of a new user.")
    return result

gSessionManager = AuthManagerClient()
