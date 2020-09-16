""" The OAuth service provides a toolkit to authoticate throught OIDC session.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import re
import six
import time
import pprint
import threading
from authlib.jose import jwt  # TODO: need to add authlib to DIRACOS

from DIRAC import gLogger, S_OK, S_ERROR
from DIRAC.Core.DISET.RequestHandler import RequestHandler
from DIRAC.Core.Utilities import ThreadSafe
from DIRAC.Core.Utilities.DictCache import DictCache
from DIRAC.Core.Utilities.ThreadScheduler import gThreadScheduler
from DIRAC.ConfigurationSystem.Client.Helpers.Resources import getProviderInfo, getProvidersForInstance
from DIRAC.ConfigurationSystem.Client.Helpers.Registry import getUsernameForID, getIDsForUsername, getEmailsForGroup
from DIRAC.Resources.IdProvider.IdProviderFactory import IdProviderFactory
from DIRAC.ConfigurationSystem.Client.Utilities import getAuthAPI

from DIRAC.FrameworkSystem.DB.AuthDB2 import AuthDB2

# from DIRAC.FrameworkSystem.DB.AuthServerHandler import AuthServerHandler

__RCSID__ = "$Id$"


gCacheSessions = ThreadSafe.Synchronizer()
gCacheProfiles = ThreadSafe.Synchronizer()


class AuthManagerHandler(RequestHandler):
  """ Authentication manager
  """
  __cacheSessions = DictCache()
  # # {
  # #   <session1>: {
  # #     ID: ..,
  # #     Provider: ..,
  # #     Tokens: { <tokens> }
  # #   },
  # #   <session2>: { ... }
  # # }

  __cahceIDs = DictCache()
  # # {
  # #   <ID1>: [ <sessions> ],
  # #   <ID2>: ...
  # # }

  __cahceIdPIDs = DictCache()
  # # {
  # #   <IdP1>: [ <IDs> ],
  # #   <IdP2>: ...
  # # }

  __cacheProfiles = DictCache()
  # # {
  # #   <ID1>: {
  # #     DNs: {
  # #       <DN1>: {
  # #         ProxyProvider: [ <proxy providers> ],
  # #         VOMSRoles: [ <VOMSRoles> ],
  # #         ...
  # #       },
  # #       <DN2>: { ... },
  # #     }
  # #   },
  # #   <ID2>: { ... }
  # # }

  __db = None

  @classmethod
  @gCacheProfiles
  def __getProfiles(cls, userID=None):
    """ Get cache information

        :param str userID: user ID

        :return: dict
    """
    if userID:
      return cls.__cacheProfiles.get(userID) or {}
    return cls.__cacheProfiles.getDict()

  @classmethod
  @gCacheProfiles
  def __addProfiles(cls, data, time=3600 * 24):
    """ Caching information

        :param dict data: ID information data
        :param int time: lifetime
    """
    if data:
      for oid, info in data.items():
        cls.__cacheProfiles.add(oid, time, value=info)

  @classmethod
  @gCacheSessions
  def __getSessions(cls, session=None, userID=None):
    """ Get cache information

        :param str session: session
        :param str userID: user ID

        :return: dict
    """
    if session:
      data = cls.__cacheSessions.get(session)
      if userID and userID != data['ID']:
        return {}
      return data

    if userID:
      data = {}
      for session in cls.__cahceIDs.get(userID) or []:
        data[session] = cls.__cacheSessions.get(session)
      return data

    return cls.__cacheSessions.getDict()

  @classmethod
  @gCacheSessions
  def __addSessions(cls, data, time=3600 * 24):
    """ Caching information

        :param dict data: ID information data
        :param int time: lifetime
    """
    for session, info in data.items():
      idSessions = cls.__cahceIDs.get(info['ID']) or []
      cls.__cahceIDs.add(info['ID'], time, list(set(idSessions + [session])))
      cls.__cacheSessions.add(session, time, value=info)

  @classmethod
  def __updateSessionsFromDB(cls, idPs=None, IDs=None, session=None):
    """ Update information about sessions

        :param list idPs: list of identity providers that sessions need to update, if None - update all
        :param list IDs: list of IDs that need to update, if None - update all
        :param str session: session to update

        :return: S_OK()/S_ERROR()
    """
    result = cls.__db.updateSessionsFromDB(idPs=idPs, IDs=IDs, session=session)
    if result['OK']:
      cls.__addSessions(result['Value'] or {})
      gLogger.info(len(result['Value']), 'sessions has been uploaded from DB to cache.')
    return result

  @classmethod
  def __refreshReservedSessions(cls):
    """ Refresh reserved sessions
    """
    result = cls.__db.getReservedSessions()
    if not result['OK']:
      return result
    freshDict = {}
    for data in result['Value']:
      session = data['Session']
      provider = data['Provider']
      if provider not in freshDict:
        freshDict[provider] = []
      freshDict[provider] = list(set(freshDict[provider] + [session]))

    for idP, sessions in freshDict.items():
      result = IdProviderFactory().getIdProvider(idP, sessionManager=cls.__db)
      if result['OK']:
        provObj = result['Value']
        result = provObj.checkStatus(session=session)
        if result['OK']:
          cls.log.verbose(session, 'session refreshed!')
          continue
      cls.log.error('%s session not refreshed:' % session, result['Message'])

  @classmethod
  def __cleanAuthDB(cls):
    """ Check AuthDB for zombie sessions and clean

        :return: S_OK()/S_ERROR()
    """
    cls.log.info("Kill zombie sessions")
    result = cls.__db.getZombieSessions()
    if not result['OK']:
      gLogger.error('Cannot clean zombies: %s' % result['Message'])
      return result
    for idP, sessions in result['Value'].items():
      result = IdProviderFactory().getIdProvider(idP, sessionManager=cls.__db)
      if not result['OK']:
        for session in sessions:
          cls.log.error('%s session, with %s IdP, cannot log out:' % (sessions, idP), result['Message'])
          cls.__db.killSession(session)
        continue
      provObj = result['Value']
      for session in sessions:
        result = provObj.logOut(session)
        if not result['OK']:
          cls.log.error('%s session, with %s IdP, cannot log out:' % (session, idP), result['Message'])
        cls.__db.killSession(session)

    cls.log.notice("Cleaning is done!")
    return S_OK()

  @classmethod
  def initializeHandler(cls, serviceInfo):
    """ Handler initialization
    """
    cls.__db = AuthDB2()
    # return S_OK()
    # cls.__authServ = AuthServerHandler(cls.__db)
    # gThreadScheduler.addPeriodicTask(15 * 60, cls.__refreshReservedSessions)
    #gThreadScheduler.addPeriodicTask(3600, cls.__cleanAuthDB)
    #gThreadScheduler.addPeriodicTask(3600, cls.__updateSessionsFromDB)
    #result = cls.__cleanAuthDB()
    #if result['OK']:
    #  result = cls.__updateSessionsFromDB()
    return cls.__refreshProfiles() #if result['OK'] else result

  @classmethod
  def __refreshProfiles(cls):
    """ Refresh users profiles

        :return: S_OK()/S_ERROR()
    """
    def refreshIdP(idP):
      """ Process to get information from VOMS API

          :param str vo: VO name
      """
      result = IdProviderFactory().getIdProvider(idP, sessionManager=cls.__db)
      if result['OK']:
        provObj = result['Value']
        result = provObj.getIDsMetadata()
        if result['OK']:
          cls.__addProfiles(result['Value'])
      if not result['OK']:
        return result

    result = getProvidersForInstance('Id')
    if not result['OK']:
      return result
    for idP in result['Value']:
      processThread = threading.Thread(target=refreshIdP, args=[idP])
      processThread.start()

    return S_OK()

  def __checkAuth(self, session=None):
    """ Check authorization rules

        :param str session: session number

        :return: S_OK(tuple)/S_ERROR() -- tuple contain username and IDs
    """
    credDict = self.getRemoteCredentials()
    if credDict['group'] == 'hosts':
      return S_OK((None, 'all'))

    user = credDict["username"]
    userIDs = getIDsForUsername(user)
    if not userIDs:
      return S_ERROR('No registred IDs for %s user.' % user)

    if session:
      result = self.__db.getSessionID(session)
      if not result['OK']:
        return result
      sID = result['Value']
      if sID not in userIDs:
        return S_ERROR('%s user not have access to %s ID information.' % (user, sID))

    return S_OK((user, userIDs))

  types_updateProfile = []
  auth_updateProfile = ["authenticated", "TrustedHost"]

  def export_updateProfile(self, userID=None):
    """ Return fresh info from identity providers about users with actual sessions

        :params: str userID: user ID

        :return: S_OK(dict)/S_ERROR()
    """
    result = self.__checkAuth()
    if not result['OK']:
      return result
    user, ids = result["Value"]

    # For host
    if ids == 'all':
      return S_OK(self.__getProfiles(userID=userID))

    # For user
    if userID:
      if userID not in ids:
        return S_ERROR('%s user not have access to %s ID information.' % (user, userID))
      return S_OK(self.__getProfiles(userID=userID))

    data = {}
    for uid in ids:
      idDict = self.__getProfiles(userID=uid)
      if idDict:
        data[uid] = idDict

    return S_OK(data)

  types_getIdProfiles = []
  auth_getIdProfiles = ["authenticated", "TrustedHost"]

  def export_getIdProfiles(self, userID=None):
    """ Return fresh info from identity providers about users with actual sessions

        :params: str userID: user ID

        :return: S_OK(dict)/S_ERROR()
    """
    result = self.__checkAuth()
    if not result['OK']:
      return result
    user, ids = result["Value"]

    # For host
    if ids == 'all':
      return S_OK(self.__getProfiles(userID=userID))

    # For user
    if userID:
      if userID not in ids:
        return S_ERROR('%s user not have access to %s ID information.' % (user, userID))
      return S_OK(self.__getProfiles(userID=userID))

    data = {}
    for uid in ids:
      idDict = self.__getProfiles(userID=uid)
      if idDict:
        data[uid] = idDict

    return S_OK(data)


  types_parseAuthResponse = [six.string_types, string_types, dict]#dict, six.string_types]

  def export_parseAuthResponse(self, providerName, username, userProfile)#response, session):
    """ Fill session by user profile, tokens, comment, OIDC authorize status, etc.
        Prepare dict with user parameters, if DN is absent there try to get it.
        Create new or modify existend DIRAC user and store the session

        :param dict response: authorization response
        :param str session: session number

        :return: S_OK(dict)/S_ERROR()
    """
    # result = IdProviderFactory().getIdProvider(providerName, sessionManager=self.__db)
    # if not result['OK']:
    #   return result
    # provObj = result['Value']
    # result = provObj.parseAuthResponse(response, session)
    # if not result['OK']:
    #   return result
    
    # # FINISHING with IdP auth result
    # username, userProfile = result['Value']

    # Is ID registred?
    result = getUsernameForID(userProfile['ID'])
    if not result['OK']:
      comment = '%s ID is not registred in the DIRAC.' % userProfile['ID']
      result = self.__registerNewUser(providerName, username, userProfile)
      if result['OK']:
        comment += ' Administrators have been notified about you.'
      else:
        comment += ' Please, contact the DIRAC administrators.'
      return S_ERROR(comment)
    self.__addProfiles(userProfile)
    return S_OK((result['Value'], userProfile))

  def __registerNewUser(self, provider, parseDict):
    """ Register new user

        :param str provider: provider
        :param dict parseDict: user information dictionary

        :return: S_OK()/S_ERROR()
    """
    from DIRAC.FrameworkSystem.Client.NotificationClient import NotificationClient

    mail = {}
    mail['subject'] = "[SessionManager] User %s to be added." % parseDict['username']
    mail['body'] = 'User %s was authenticated by ' % parseDict['UsrOptns']['FullName']
    mail['body'] += provider
    mail['body'] += "\n\nAuto updating of the user database is not allowed."
    mail['body'] += " New user %s to be added," % parseDict['username']
    mail['body'] += "with the following information:\n"
    mail['body'] += "\nUser name: %s\n" % parseDict['username']
    mail['body'] += "\nUser profile:\n%s" % pprint.pformat(parseDict['UsrOptns'])
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

  types_createClient = [dict]
  auth_createClient = []#"authenticated", "TrustedHost"]

  def export_createClient(self, kwargs):
    """ Generates a state string to be used in authorizations

        :param str provider: provider
        :param str session: session number

        :return: S_OK(str)/S_ERROR()
    """
    return self.__db.addClient(**kwargs)

  types_getClientByID = [six.string_types]
  auth_getClientByID = []  # "authenticated", "TrustedHost"]

  def export_getClientByID(self, clientID):
    """ Generates a state string to be used in authorizations

        :param str provider: provider
        :param str session: session number

        :return: S_OK(str)/S_ERROR()
    """
    return self.__db.getClientByID(clientID)
  
  types_storeToken = [dict]
  auth_storeToken = ["authenticated"]
  def export_storeToken(self, kwargs):
    """ Generates a state string to be used in authorizations

        :param str provider: provider
        :param str session: session number

        :return: S_OK(str)/S_ERROR()
    """
    return self.__db.storeToken(**kwargs)









  ###########################
  types_getSessionLifetime = [six.string_types]
  auth_getSessionLifetime = ["authenticated", "TrustedHost"]

  def export_getSessionLifetime(self, session):
    """ Get lifetime of session

        :param str session: session number

        :return: S_OK(int)/S_ERROR() -- lifetime in a seconds
    """
    res = self.__checkAuth(session)
    return self.__db.getSessionLifetime(session) if res['OK'] else res

  types_refreshSession = [six.string_types]
  auth_refreshSession = ["authenticated", "TrustedHost"]

  def export_refreshSession(self, session):
    """ Refresh session

        :param str session: session number

        :return: S_OK()/S_ERROR()
    """
    result = self.__checkAuth(session)
    if not result['OK']:
      return result
    result = self.__db.getSessionProvider(session)
    if not result['OK']:
      return result
    provider = result['Value']
    result = IdProviderFactory().getIdProvider(provider, sessionManager=self.__db)
    if not result['OK']:
      return result
    provObj = result['Value']
    return provObj.fetch(session)

  types_getReservedSessions = []
  auth_getReservedSessions = ["authenticated", "TrustedHost"]

  def export_getReservedSessions(self, userIDs=None, idPs=None, check=False):
    """ Get reserved sessions

        :param list userIDs: user IDs
        :param list idPs: IdPs
        :param bool check: if need to check session status by IdP

        :return: S_OK(list)/S_ERROR()
    """
    result = self.__checkAuth()
    if not result['OK']:
      return result
    user, ids = result["Value"]
    if user:
      if userIDs:
        for uid in userIDs:
          if uid not in ids:
            return S_ERROR('%s user not have access to %s ID information.' % (user, userIDs))
      else:
        userIDs = ids
    result = self.__db.getReservedSessions(userIDs, idPs)
    if not result['OK']:
      return result
    data = {}
    for sDict in result['Value']:
      if sDict['Provider'] not in data:
        data[sDict['Provider']] = []
      data[sDict['Provider']].append(sDict['Session'])

    sessionList = []
    for idP, sessions in data.items():
      if not check:
        sessionList += sessions
        continue
      result = IdProviderFactory().getIdProvider(idP, sessionManager=self.__db)
      if not result['OK']:
        return result
      provObj = result['Value']
      for session in sessions:
        if provObj.checkStatus(session)['OK']:
          sessionList.append(session)

    return S_OK(list(set(sessionList)))

  types_updateSession = [six.string_types, dict]
  auth_updateSession = ["authenticated", "TrustedHost"]

  def export_updateSession(self, session, fieldsToUpdate):
    """ Update session record

        :param str session: session number
        :param dict fieldsToUpdate: fields content that need to update

        :return: S_OK()/S_ERROR()
    """
    res = self.__checkAuth(session)
    return self.__db.updateSession(session, fieldsToUpdate) if res['OK'] else res

  types_killSession = [six.string_types]
  auth_killSession = ["authenticated", "TrustedHost"]

  def export_killSession(self, session):
    """ Remove session record from DB

        :param str session: session number

        :return: S_OK()/S_ERROR()
    """
    res = self.__checkAuth(session)
    return self.__db.killSession(session) if res['OK'] else res

  types_logOutSession = [six.string_types]
  auth_logOutSession = ["authenticated", "TrustedHost"]

  def export_logOutSession(self, session):
    """ Remove session record from DB and logout form identity provider

        :param str session: session number

        :return: S_OK()/S_ERROR()
    """
    result = self.__checkAuth(session)
    if not result['OK']:
      return result

    result = self.__db.getSessionProvider(session)
    if not result['OK']:
      return result
    provider = result['Value']
    result = IdProviderFactory().getIdProvider(provider, sessionManager=self.__db)
    if not result['OK']:
      return result
    provObj = result['Value']
    result = provObj.logOut(session)
    if not result['OK']:
      self.log.error(result['Message'])
    return self.__db.killSession(session)

  types_getSessionAuthLink = [six.string_types]

  def export_getSessionAuthLink(self, session):
    """ Get authorization URL by session number

        :param str session: session number

        :return: S_OK(str)/S_ERROR()
    """
    return self.__db.getSessionAuthLink(session)

  types_getSessionStatus = [six.string_types]

  def export_getSessionStatus(self, session):
    """ Listen DB to get status of authorization session

        :param str session: session number

        :return: S_OK(dict)/S_ERROR()
    """
    result = self.__db.getSessionStatus(session)
    if result['OK']:
      if result['Value']['Status'] == 'authed':
        user = getUsernameForID(result['Value']['ID'])
        if user['OK']:
          result['Value']['UserName'] = user['Value']
    return result

  types_getSessionTokens = [six.string_types]
  auth_getSessionTokens = ["authenticated", "TrustedHost"]

  def export_getSessionTokens(self, session):
    """ Get tokens by session number

        :param str session: session number

        :return: S_OK(dict)/S_ERROR()
    """
    res = self.__checkAuth(session)
    return self.__db.getSessionTokens(session) if res['OK'] else res

  types_createNewSession = [six.string_types]
  auth_createNewSession = ["authenticated", "TrustedHost"]

  def export_createNewSession(self, provider, requestedGroup=None, session=None):
    """ Generates a state string to be used in authorizations

        :param str provider: provider
        :param str session: session number

        :return: S_OK(str)/S_ERROR()
    """
    res = self.__checkAuth(session)
    return self.__db.createNewSession(provider, requestedGroup, session) if res['OK'] else res

  def export_getTokenBySession(self, session, group, livetime=24 * 3600):
    """ Generate Bearer access token

        :param str session: session number
        :param str group: requested user group
        :param int livetime: token livetime

        :return: S_OK()/S_ERROR()
    """
    res = self.__checkAuth(session)
    if res['OK']:
      res = self.__db.getSessionStatus(session)
    if not res['OK']:
      return res
    if res['Value']['Status'] != 'authed':
      return S_ERROR("%s session status is %s." % (session, res['Value']['Status']))
    provider = res['Value']['Provider']
    uid = res['Value']['ID']

    privateKey = getPrivateKeyLocation()
    if not privateKey:
      return S_ERROR('Cannot generate token: no private key found.')
    with open(privateKey, 'rb') as f:
      key = f.read()
    header = {'alg': 'HS256'}
    payload = {'idp': provider, 'sub': uid, 'group': group, 'exp': time.time() + livetime}
    try:
      token = jwt.encode(header, payload, key)
    except Exception as e:
      return S_ERROR(repr(e))
    res = self.__db.killSession(session)
    return S_OK(token) if res['OK'] else res
