""" DIRAC AuthManager Client class encapsulates the methods exposed
    by the AuthManager service.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import six
import requests
from authlib.common.security import generate_token

from DIRAC.Core.Utilities import ThreadSafe
from DIRAC.Core.Utilities.DictCache import DictCache

from DIRAC import gLogger, S_OK, S_ERROR
from DIRAC.Core.Base.Client import Client, createClient
from DIRAC.Core.Utilities import DIRACSingleton
from DIRAC.Resources.IdProvider.IdProviderFactory import IdProviderFactory
from DIRAC.ConfigurationSystem.Client.Utilities import getAuthAPI
from DIRAC.FrameworkSystem.Client.ProxyManagerClient import gProxyManager
from DIRAC.FrameworkSystem.Client.AuthManagerData import gAuthManagerData

__RCSID__ = "$Id$"


gCacheClient = ThreadSafe.Synchronizer()
gCacheSession = ThreadSafe.Synchronizer()
SESSION_ATTRS = ['user_code',
                 'device_code',
                 'state',
                 'code_challenge',
                 'code_challenge_method',
                 'code',
                 'Provider',
                 'Status',
                 'Comment',
                 'group',
                 'Token',
                 'grant',
                 'redirect_uri',
                 'subSession']


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
    self.cacheSession = DictCache()
    self.cacheClient = DictCache()
    self.idps = IdProviderFactory()
  
  @gCacheClient
  def addClient(self, data):
    result = self._getRPC().createClient(data)
    if result['OK']:
      data = result['Value']
      self.cacheClient.add(data['client_id'], 24 * 3600, data)
    return result

  @gCacheClient
  def getClient(self, clientID):
    data = self.cacheClient.get(clientID)
    if not data:
      result = self._getRPC().getClientByID(clientID)
      if result['OK']:
        data = result['Value']
        self.cacheClient.add(data['client_id'], 24 * 3600, data)
    return data
  
  @gCacheSession
  def addSession(self, session, data={}, exp=300, **kwargs):
    data.update(kwargs)
    data['Status'] = data.get('Status', 'submited')
    self.cacheSession.add(session, exp, data)
  
  @gCacheSession
  def getSession(self, session=None):
    return self.cacheSession.get(session) if session else self.cacheSession.getDict()
  
  @gCacheSession
  def removeSession(self, session):
    self.cacheSession.delete(session)

  def updateSession(self, session, data={}, exp=300, **kwargs):
    data.update(kwargs)
    origData = self.getSession(session) or {}
    for k, v in data.items():
      origData[k] = v
    self.addSession(session, origData, exp)
  
  def getSessionByOption(self, key, value):
    if key and value:
      sessions = self.getSession()
      for session, data in sessions.items():
        if data.get(key) == value:
          return session, data
    return None, {}

  def submitAuthorizeFlow(self, providerName, mainSession):
    """ Register new session and return dict with authorization url and session number

        :param str providerName: provider name
        :param str session: session identificator

        :return: S_OK(dict)/S_ERROR() -- dictionary contain next keys:
                 Status -- session status
                 UserName -- user name, returned if status is 'ready'
                 Session -- session id, returned if status is 'needToAuth'
    """
    # Start subsession
    session = generate_token(10)
    self.addSession(session, mainSession=mainSession, Provider=providerName)

    result = self.idps.getIdProvider(providerName, sessionManager=self.__getRPC())
    if result['OK']:
      result = result['Value'].submitNewSession(session)
      if result['OK']:
        authURL, sessionParams = result['Value']
        self.updateSession(session, sessionParams)
    return S_OK(authURL) if result['OK'] else result

  def parseAuthResponse(self, response, session):
    """ Fill session by user profile, tokens, comment, OIDC authorize status, etc.
        Prepare dict with user parameters, if DN is absent there try to get it.
        Create new or modify existend DIRAC user and store the session

        :param str providerName: identity provider name
        :param dict response: authorization response
        :param dict session: session data dictionary

        :return: S_OK(dict)/S_ERROR()
    """
    # Check session
    sessionDict = self.getSession(session)
    if not sessionDict:
      return S_ERROR("Session expired.")
    
    mainSession = sessionDict['mainSession']
    providerName = sessionDict['Provider']

    # Parse response
    result = self.idps.getIdProvider(providerName, sessionManager=self._getRPC())
    if result['OK']:
      result = result['Value'].parseAuthResponse(response, sessionDict)
      if result['OK']:
        self.removeSession(session)
        # FINISHING with IdP auth result
        username, userProfile = result['Value']
        result = self._getRPC().parseAuthResponse(providerName, username, userProfile)
    
    if not result['OK']:
      self.updateSession(mainSession, Status='failed', Comment=result['Message'])
      return result
    
    username, profile = result['Value']
    if username and profile:
      gAuthManagerData.updateProfiles(profile['ID'], profile)
      self.updateSession(mainSession, username=username, profile=profile)

    return S_OK((username, profile['ID'], mainSession))

gSessionManager = AuthManagerClient()
