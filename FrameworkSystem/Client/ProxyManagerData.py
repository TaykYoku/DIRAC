""" ProxyManagementAPI has the functions to "talk" to the ProxyManagement service
"""
import datetime

from DIRAC import S_OK, S_ERROR, gLogger
from DIRAC.Core.Utilities import ThreadSafe, DIRACSingleton
from DIRAC.Core.Utilities.DictCache import DictCache

__RCSID__ = "$Id$"

gUsersSync = ThreadSafe.Synchronizer()
gVOMSUsersSync = ThreadSafe.Synchronizer()


class ProxyManagerData(object):
  """ Proxy manager client

      Contain __VOMSesUsersCache cache, with next structure:
        Key: VOMS VO name
        Value: S_OK(dict)/S_ERROR() -- dictionary contain:
            { <user DN>: {
                Suspended: bool,
                VOMSRoles: [<all roles>],
                ActuelRoles: [<active roles>],
                SuspendedRoles: [<suspended roles>]
              }
            }
  """
  __metaclass__ = DIRACSingleton.DIRACSingleton

  def __init__(self):
    self.__usersCache = DictCache()
    self.__VOMSesUsersCache = DictCache()

  def clearCaches(self):
    """ Clear caches
    """
    self.__usersCache.purgeAll()
    self.__VOMSesUsersCache.purgeAll()

  def __getSecondsLeftToExpiration(self, expiration, utc=True):
    """ Get time left to expiration in a seconds

        :param datetime expiration:
        :param bool utc: time in utc

        :return: datetime
    """
    if utc:
      td = expiration - datetime.datetime.utcnow()
    else:
      td = expiration - datetime.datetime.now()
    return td.days * 86400 + td.seconds

  def __getRPC():
    """ Get RPC
    """
    from DIRAC.Core.DISET.RPCClient import RPCClient
    return RPCClient("Framework/ProxyManager", timeout=120)

  def __refreshUserCache(self, validSeconds=0):
    """ Refresh user cache

        :param int validSeconds: required seconds the proxy is valid for

        :return: S_OK()/S_ERROR()
    """
    retVal = __getRPC.getRegisteredUsers(validSeconds)
    if not retVal['OK']:
      return retVal
    # Update the cache
    for record in retVal['Value']:
      for group in record['groups']:
        cacheKey = (record['user'], group)
        self.__usersCache.add(cacheKey, self.__getSecondsLeftToExpiration(record['expirationtime']),
                              record)
    return S_OK()

  @gVOMSUsersSync
  def __getVOMSUsersDict(self):
    """ Get users dictionary from cache

        :return: dict
    """
    return self.__VOMSesUsersCache.getDict()

  @gVOMSUsersSync
  def __setVOMSUsersDict(self, usersDict):
    """ Set dictionary to cache

        :param dict usersDict: dictionary with VOMS users
    """
    for vo, userInfo in usersDict.items():
      self.__VOMSesUsersCache.add(vo, 3600 * 24, value=userInfo)
    self.__VOMSesUsersCache.add('Fresh', 3600 * 12, value=True)

  def __refreshVOMSesCache(self):
    """ Get fresh info from service about VOMSes

        :return: S_OK()/S_ERROR()
    """
    result = __getRPC.getVOMSesUsers()
    if result['OK']:
      self.__setVOMSUsersDict(result['Value'])
    return result

  def getActualVOMSesDNs(self, voList=None, dnList=None):
    """ Return actual/not suspended DNs from VOMSes

        :param list voList: VOs to get
        :param list dnList: DNs to get

        :return: S_OK(dict)/S_ERROR()
    """
    vomsUsers = self.__getVOMSUsersDict()
    if not vomsUsers.get('Fresh'):
      result = self.__refreshVOMSesCache()
      if not result['OK']:
        return result
      vomsUsers = result['Value']
    vomsUsers.pop('Fresh', None)
    res = {}
    if not vomsUsers:
      # use simulation here for tests
      return S_ERROR('VOMSes has not been updated.')
    for vo, voInfo in vomsUsers.items():
      if voList and vo not in voList:
        continue
      if not voInfo['OK']:
        res[vo] = voInfo
        continue
      res[vo] = S_OK()
      for dn, data in voInfo['Value'].items():
        if dnList and dn not in dnList:
          continue
        if dn not in res[vo]['Value']:
          res[vo]['Value'][dn] = {'Suspended': data['suspended'],
                                      'VOMSRoles': [],
                                      'ActuelRoles': [],
                                      'SuspendedRoles': []}
        res[vo]['Value'][dn]['VOMSRoles'] = list(set(res[vo]['Value'][dn]['VOMSRoles'] + data['Roles']))
        if data['certSuspended'] or data['suspended']:
          res[vo]['Value'][dn]['SuspendedRoles'] = list(set(res[vo]['Value'][dn]['SuspendedRoles'] + data['Roles']))
        else:
          res[vo]['Value'][dn]['ActuelRoles'] = list(set(res[vo]['Value'][dn]['ActuelRoles'] + data['Roles']))
    return S_OK(res)

  @gUsersSync
  def userHasProxy(self, user, group, validSeconds=0):
    """ Check if a user-group has a proxy in the proxy management
        Updates internal cache if needed to minimize queries to the service

        :param str user: user name
        :param str group: user group
        :param int validSeconds: proxy valid time in a seconds

        :return: S_OK()/S_ERROR()
    """
    cacheKey = (user, group)
    if self.__usersCache.exists(cacheKey, validSeconds):
      return S_OK(True)
    # Get list of users from the DB with proxys at least 300 seconds
    gLogger.verbose("Updating list of users in proxy management")
    retVal = self.__refreshUserCache(validSeconds)
    if not retVal['OK']:
      return retVal
    return S_OK(self.__usersCache.exists(cacheKey, validSeconds))

  @gUsersSync
  def getUserPersistence(self, user, group, validSeconds=0):
    """ Check if a user(DN-group) has a proxy in the proxy management
        Updates internal cache if needed to minimize queries to the service

        :param str user: user name
        :param str group: user group
        :param int validSeconds: proxy valid time in a seconds

        :return: S_OK()/S_ERROR()
    """
    cacheKey = (user, group)
    userData = self.__usersCache.get(cacheKey, validSeconds)
    if userData:
      if userData['persistent']:
        return S_OK(True)
    # Get list of users from the DB with proxys at least 300 seconds
    gLogger.verbose("Updating list of users in proxy management")
    retVal = self.__refreshUserCache(validSeconds)
    if not retVal['OK']:
      return retVal
    userData = self.__usersCache.get(cacheKey, validSeconds)
    if userData:
      return S_OK(userData['persistent'])
    return S_OK(False)

  def setPersistency(self, user, group, persistent):
    """ Set the persistency for user/group

        :param str user: user name
        :param str group: user group
        :param bool persistent: presistent flag

        :return: S_OK()/S_ERROR()
    """
    # Hack to ensure bool in the rpc call
    persistentFlag = True
    if not persistent:
      persistentFlag = False
    retVal = __getRPC.setPersistency(user, group, persistentFlag)
    if not retVal['OK']:
      return retVal
    # Update internal persistency cache
    cacheKey = (user, group)
    record = self.__usersCache.get(cacheKey, 0)
    if record:
      record['persistent'] = persistentFlag
      self.__usersCache.add(cacheKey,
                            self.__getSecondsLeftToExpiration(record['expirationtime']),
                            record)
    return retVal

gProxyManager = ProxyManagerData()
