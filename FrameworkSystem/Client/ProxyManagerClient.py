""" ProxyManagementAPI has the functions to "talk" to the ProxyManagement service
"""
from past.builtins import long
import os
import six
import datetime

from DIRAC import S_OK, S_ERROR, gLogger
from DIRAC.ConfigurationSystem.Client.Helpers.Registry import getVOMSAttributeForGroup
from DIRAC.Core.Utilities import ThreadSafe, DIRACSingleton
from DIRAC.Core.Utilities.DictCache import DictCache
from DIRAC.Core.Security.ProxyFile import multiProxyArgument, deleteMultiProxy
from DIRAC.Core.Security.X509Chain import X509Chain  # pylint: disable=import-error
from DIRAC.Core.Security.X509Request import X509Request  # pylint: disable=import-error
from DIRAC.Core.Security.VOMS import VOMS
from DIRAC.Core.Security import Locations
from DIRAC.Core.DISET.RPCClient import RPCClient

__RCSID__ = "$Id$"

gUsersSync = ThreadSafe.Synchronizer()
gProxiesSync = ThreadSafe.Synchronizer()
gVOMSProxiesSync = ThreadSafe.Synchronizer()


class ProxyManagerClient(object):
  """ Proxy manager client
      
      Contain __VOMSesUsersCache cache, with next structure:
      {
        <VOMSVO>: {
          <User DN>: {
                VOMSRoles: [ <VOMS roles> ],
                SuspendedRoles: [ <suspended roles> ]
                ...
              },
          <User DN2>: { ... },
          ...
        }
      }
  """
  __metaclass__ = DIRACSingleton.DIRACSingleton

  def __init__(self):
    self.__usersCache = DictCache()
    self.__proxiesCache = DictCache()
    self.__vomsProxiesCache = DictCache()
    self.__pilotProxiesCache = DictCache()
    self.__VOMSesUsersCache = DictCache()
    self.__filesCache = DictCache(self.__deleteTemporalFile)

  def __deleteTemporalFile(self, filename):
    """ Delete temporal file

        :param str filename: path to file
    """
    try:
      os.unlink(filename)
    except BaseException:
      pass

  def clearCaches(self):
    """ Clear caches
    """
    self.__usersCache.purgeAll()
    self.__proxiesCache.purgeAll()
    self.__vomsProxiesCache.purgeAll()
    self.__pilotProxiesCache.purgeAll()
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

  def __refreshUserCache(self, validSeconds=0):
    """ Refresh user cache

        :param int validSeconds: required seconds the proxy is valid for

        :return: S_OK()/S_ERROR()
    """
    rpcClient = RPCClient("Framework/ProxyManager", timeout=120)
    retVal = rpcClient.getRegisteredUsers(validSeconds)
    if not retVal['OK']:
      return retVal
    # Update the cache
    for record in retVal['Value']:
      for group in record['groups']:
        cacheKey = (record['user'], group)
        self.__usersCache.add(cacheKey, self.__getSecondsLeftToExpiration(record['expirationtime']),
                              record)
    return S_OK()
  
  def __refreshVOMSesCache(self):
    """ Get fresh info from service about VOMSes

        :return: S_OK()/S_ERROR()
    """
    result = RPCClient("Framework/ProxyManager", timeout=120).getVOMSesUsers()
    if not result['OK']:
      return result
    for vo, userInfo in result['Value'].items():
      self.__VOMSesUsersCache.add(vo, 3600 * 24, value=userInfo)
    self.__VOMSesUsersCache.add('Fresh', 3600 * 12, value=True)
    return result

  def getActualVOMSesDNs(self, DNs=None):
    """ Return actual/not suspended DNs from VOMSes

        :param list DNs: DNs fo filter result

        :return: S_OK(dict)/S_ERROR()
    """
    __VOMSesUsersCache = self.__VOMSesUsersCache.getDict()
    if not __VOMSesUsersCache.get('Fresh'):
      result = self.__refreshVOMSesCache()
      if not result['OK']:
        return result
      __VOMSesUsersCache = result['Value']
    __VOMSesUsersCache.pop('Fresh', None)
    vomsActualDNsDict = {}
    if not __VOMSesUsersCache:
      # I can use simulation here
      return S_ERROR('VOMSes is not updated.')
    for vo, voInfo in __VOMSesUsersCache.items():
      for dn, dnDict in voInfo.items():
        if DNs and dn not in DNs:
          continue
        if dn not in vomsActualDNsDict:
          vomsActualDNsDict[dn] = {'VOMSRoles': [], 'SuspendedRoles': [], 'Emails': []}
        vomsActualDNsDict[dn]['VOMSRoles'] = list(set(vomsActualDNsDict[dn]['VOMSRoles'] + dnDict['Roles']))
        if dnDict['certSuspended']:
          vomsActualDNsDict[dn]['SuspendedRoles'] = list(set(vomsActualDNsDict[dn]['SuspendedRoles'] + dnDict['Roles']))
    return S_OK(vomsActualDNsDict)

  @gUsersSync
  def userHasProxy(self, user, userGroup, validSeconds=0):
    """ Check if a user-group has a proxy in the proxy management
        Updates internal cache if needed to minimize queries to the service

        :param str user: user name
        :param str userGroup: user group
        :param int validSeconds: proxy valid time in a seconds

        :return: S_OK()/S_ERROR()
    """
    cacheKey = (user, userGroup)
    if self.__usersCache.exists(cacheKey, validSeconds):
      return S_OK(True)
    # Get list of users from the DB with proxys at least 300 seconds
    gLogger.verbose("Updating list of users in proxy management")
    retVal = self.__refreshUserCache(validSeconds)
    if not retVal['OK']:
      return retVal
    return S_OK(self.__usersCache.exists(cacheKey, validSeconds))

  @gUsersSync
  def getUserPersistence(self, user, userGroup, validSeconds=0):
    """ Check if a user(DN-group) has a proxy in the proxy management
        Updates internal cache if needed to minimize queries to the service

        :param str user: user name
        :param str userGroup: user group
        :param int validSeconds: proxy valid time in a seconds

        :return: S_OK()/S_ERROR()
    """
    cacheKey = (user, userGroup)
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

  def setPersistency(self, user, userGroup, persistent):
    """ Set the persistency for user/group

        :param str user: user name
        :param str userGroup: user group
        :param bool persistent: presistent flag

        :return: S_OK()/S_ERROR()
    """
    # Hack to ensure bool in the rpc call
    persistentFlag = True
    if not persistent:
      persistentFlag = False
    rpcClient = RPCClient("Framework/ProxyManager", timeout=120)
    retVal = rpcClient.setPersistency(user, userGroup, persistentFlag)
    if not retVal['OK']:
      return retVal
    # Update internal persistency cache
    cacheKey = (user, userGroup)
    record = self.__usersCache.get(cacheKey, 0)
    if record:
      record['persistent'] = persistentFlag
      self.__usersCache.add(cacheKey,
                            self.__getSecondsLeftToExpiration(record['expirationtime']),
                            record)
    return retVal

  def uploadProxy(self, proxy=None, restrictLifeTime=0, rfcIfPossible=False):
    """ Upload a proxy to the proxy management service using delegation

        :param X509Chain proxy: proxy as a chain
        :param int restrictLifeTime: proxy live time in a seconds
        :param bool rfcIfPossible: make rfc proxy if possible

        :return: S_OK(dict)/S_ERROR() -- dict contain proxies
    """
    # Discover proxy location
    proxyLocation = proxy if isinstance(proxy, six.string_types) else ""
    if isinstance(proxy, X509Chain):
      chain = proxy
    else:
      if not proxyLocation:
        proxyLocation = Locations.getProxyLocation()
        if not proxyLocation:
          return S_ERROR("Can't find a valid proxy")
      chain = X509Chain()
      result = chain.loadProxyFromFile(proxyLocation)
      if not result['OK']:
        return S_ERROR("Can't load %s: %s " % (proxyLocation, result['Message']))

    # Make sure it's valid
    if chain.hasExpired().get('Value'):
      return S_ERROR("Proxy %s has expired" % proxyLocation)
    if chain.getDIRACGroup().get('Value') or chain.isVOMS().get('Value'):
      return S_ERROR("Cannot upload proxy with DIRAC group or VOMS extensions")
    if proxy:
      rpcClient = RPCClient("Framework/ProxyManager", timeout=120, useCertificates=False, proxyChain=chain)
    else:
      rpcClient = RPCClient("Framework/ProxyManager", timeout=120)
    # Get a delegation request
    # WARN: Since v7r1 requestDelegationUpload method not use arguments!
    result = rpcClient.requestDelegationUpload(None, None)
    if not result['OK']:
      return result
    reqDict = result['Value']
    # Generate delegated chain
    chainLifeTime = chain.getRemainingSecs()['Value'] - 60
    if restrictLifeTime and restrictLifeTime < chainLifeTime:
      chainLifeTime = restrictLifeTime
    retVal = chain.generateChainFromRequestString(reqDict['request'],
                                                  lifetime=chainLifeTime,
                                                  rfc=rfcIfPossible)
    if not retVal['OK']:
      return retVal
    # Upload!
    result = rpcClient.completeDelegationUpload(reqDict['id'], retVal['Value'])
    if not result['OK']:
      return result
    return S_OK(result.get('proxies') or result['Value'])

  @gProxiesSync
  def downloadPersonalProxy(self, user, userGroup, requiredTimeLeft=1200, cacheTime=14400, vomsAttr=False):
    """ Get a proxy Chain from the proxy management

        :param str user: user name
        :param str userGroup: user group
        :param int requiredTimeLeft: required proxy live time in a seconds
        :param int cacheTime: store in a cache time in a seconds
        :param bool vomsAttr: add VOMS attr to the proxy

        :return: S_OK(X509Chain)/S_ERROR()
    """
    cacheKey = (user, userGroup)
    if self.__proxiesCache.exists(cacheKey, requiredTimeLeft):
      return S_OK(self.__proxiesCache.get(cacheKey))
    req = X509Request()
    req.generateProxyRequest()
    rpcClient = RPCClient("Framework/ProxyManager", timeout=120)
    retVal = rpcClient.getProxy(user, userGroup, req.dumpRequest()['Value'],
                                int(cacheTime + requiredTimeLeft), False, vomsAttr, True)
    if not retVal['OK']:
      return retVal
    chain = X509Chain(keyObj=req.getPKey())
    retVal = chain.loadChainFromString(retVal['Value'])
    if not retVal['OK']:
      return retVal
    self.__proxiesCache.add(cacheKey, chain.getRemainingSecs()['Value'], chain)
    return S_OK(chain)

  @gProxiesSync
  def downloadProxy(self, user, userGroup, limited=False, requiredTimeLeft=1200,
                    cacheTime=14400, proxyToConnect=None, token=None):
    """ Get a proxy Chain from the proxy management

        :param str user: user name
        :param str userGroup: user group
        :param bool limited: if need limited proxy
        :param int requiredTimeLeft: required proxy live time in a seconds
        :param int cacheTime: store in a cache time in a seconds
        :param X509Chain proxyToConnect: proxy as a chain
        :param str token: valid token to get a proxy

        :return: S_OK(X509Chain)/S_ERROR()
    """
    cacheKey = (user, userGroup)
    if self.__proxiesCache.exists(cacheKey, requiredTimeLeft):
      return S_OK(self.__proxiesCache.get(cacheKey))
    req = X509Request()
    req.generateProxyRequest(limited=limited)
    if proxyToConnect:
      rpcClient = RPCClient("Framework/ProxyManager", proxyChain=proxyToConnect, timeout=120)
    else:
      rpcClient = RPCClient("Framework/ProxyManager", timeout=120)
    
    retVal = rpcClient.getProxy(user, userGroup, req.dumpRequest()['Value'],
                                int(cacheTime + requiredTimeLeft), token, vomsAttr, False)
    if not retVal['OK']:
      return retVal
    chain = X509Chain(keyObj=req.getPKey())
    retVal = chain.loadChainFromString(retVal['Value'])
    if not retVal['OK']:
      return retVal
    self.__proxiesCache.add(cacheKey, chain.getRemainingSecs()['Value'], chain)
    return S_OK(chain)

  def downloadProxyToFile(self, user, userGroup, limited=False, requiredTimeLeft=1200,
                          cacheTime=14400, filePath=None, proxyToConnect=None, token=None):
    """ Get a proxy Chain from the proxy management and write it to file

        :param str user: user name
        :param str userGroup: user group
        :param bool limited: if need limited proxy
        :param int requiredTimeLeft: required proxy live time in a seconds
        :param int cacheTime: store in a cache time in a seconds
        :param str filePath: path to save proxy
        :param X509Chain proxyToConnect: proxy as a chain
        :param str token: valid token to get a proxy

        :return: S_OK(X509Chain)/S_ERROR()
    """
    retVal = self.downloadProxy(user, userGroup, limited, requiredTimeLeft, cacheTime, proxyToConnect, token)
    if not retVal['OK']:
      return retVal
    chain = retVal['Value']
    retVal = self.dumpProxyToFile(chain, filePath)
    if not retVal['OK']:
      return retVal
    retVal['chain'] = chain
    return retVal

  @gVOMSProxiesSync
  def downloadVOMSProxy(self, user, userGroup, limited=False, requiredTimeLeft=1200,
                        cacheTime=14400, proxyToConnect=None, token=None):
    """ Download a proxy if needed and transform it into a VOMS one

        :param str user: user name
        :param str userGroup: user group
        :param bool limited: if need limited proxy
        :param int requiredTimeLeft: required proxy live time in a seconds
        :param int cacheTime: store in a cache time in a seconds
        :param X509Chain proxyToConnect: proxy as a chain
        :param str token: valid token to get a proxy

        :return: S_OK(X509Chain)/S_ERROR()
    """
    vomsAttr = getVOMSAttributeForGroup(userGroup)
    if not vomsAttr:
      return S_ERROR("No mapping defined for group %s in the CS" % userGroup)

    cacheKey = (user, userGroup, vomsAttr, limited)
    if self.__vomsProxiesCache.exists(cacheKey, requiredTimeLeft):
      return S_OK(self.__vomsProxiesCache.get(cacheKey))
    
    req = X509Request()
    req.generateProxyRequest(limited=limited)
    if proxyToConnect:
      rpcClient = RPCClient("Framework/ProxyManager", proxyChain=proxyToConnect, timeout=120)
    else:
      rpcClient = RPCClient("Framework/ProxyManager", timeout=120)
    retVal = rpcClient.getProxy(user, userGroup, req.dumpRequest()['Value'],
                                int(cacheTime + requiredTimeLeft), token, True, False)
    if not retVal['OK']:
      return retVal
    
    chain = X509Chain(keyObj=req.getPKey())
    retVal = chain.loadChainFromString(retVal['Value'])
    if not retVal['OK']:
      return retVal
    self.__vomsProxiesCache.add(cacheKey, chain.getRemainingSecs()['Value'], chain)
    return S_OK(chain)

  def downloadVOMSProxyToFile(self, user, userGroup, limited=False, requiredTimeLeft=1200,
                              cacheTime=14400, filePath=None, proxyToConnect=None, token=None):
    """ Download a proxy if needed, transform it into a VOMS one and write it to file

        :param str user: user name
        :param str userGroup: user group
        :param bool limited: if need limited proxy
        :param int requiredTimeLeft: required proxy live time in a seconds
        :param int cacheTime: store in a cache time in a seconds
        :param str filePath: path to save proxy
        :param X509Chain proxyToConnect: proxy as a chain
        :param str token: valid token to get a proxy

        :return: S_OK(X509Chain)/S_ERROR()
    """
    retVal = self.downloadVOMSProxy(user, userGroup, limited, requiredTimeLeft, cacheTime,
                                    proxyToConnect, token)
    if not retVal['OK']:
      return retVal
    chain = retVal['Value']
    retVal = self.dumpProxyToFile(chain, filePath)
    if not retVal['OK']:
      return retVal
    retVal['chain'] = chain
    return retVal

  def downloadCorrectProxy(self, user, userGroup, requiredTimeLeft=43200, proxyToConnect=None, token=None, personal=False):
    """ Download a proxy with VOMS extensions depending on the group or simple proxy
        if group without VOMS extensions

        :param str user: user name
        :param str userGroup: user group
        :param int requiredTimeLeft: required proxy live time in a seconds
        :param X509Chain proxyToConnect: proxy as a chain
        :param str token: valid token to get a proxy
        :param bool personal: get personal proxy

        :return: S_OK(X509Chain)/S_ERROR()
    """
    if not getVOMSAttributeForGroup(userGroup):
      gLogger.verbose("No voms attribute assigned to group %s when requested pilot proxy" % userGroup)
      return self.downloadProxy(user, userGroup, limited=False, requiredTimeLeft=requiredTimeLeft,
                                proxyToConnect=proxyToConnect, personal=personal)
    else:
      return self.downloadVOMSProxy(user, userGroup, limited=False, requiredTimeLeft=requiredTimeLeft,
                                    proxyToConnect=proxyToConnect, personal=personal)

  def dumpProxyToFile(self, chain, destinationFile=None, requiredTimeLeft=600):
    """ Dump a proxy to a file. It's cached so multiple calls won't generate extra files

        :param X509Chain chain: proxy as a chain
        :param str destinationFile: path to store proxy
        :param int requiredTimeLeft: required proxy live time in a seconds

        :return: S_OK(str)/S_ERROR()
    """
    result = chain.hash()
    if not result['OK']:
      return result
    cHash = result['Value']
    if self.__filesCache.exists(cHash, requiredTimeLeft):
      filepath = self.__filesCache.get(cHash)
      if filepath and os.path.isfile(filepath):
        return S_OK(filepath)
      self.__filesCache.delete(cHash)
    retVal = chain.dumpAllToFile(destinationFile)
    if not retVal['OK']:
      return retVal
    filename = retVal['Value']
    self.__filesCache.add(cHash, chain.getRemainingSecs()['Value'], filename)
    return S_OK(filename)

  def deleteGeneratedProxyFile(self, chain):
    """ Delete a file generated by a dump

        :param X509Chain chain: proxy as a chain

        :return: S_OK()
    """
    self.__filesCache.delete(chain)
    return S_OK()

  def requestToken(self, requester, requesterGroup, numUses=1):
    """ Request a number of tokens. usesList must be a list of integers and each integer is the number of uses a token
        must have

        :param str requester: user name
        :param str requesterGroup: user group
        :param int numUses: number of uses

        :return: S_OK(tuple)/S_ERROR() -- tuple contain token, number uses
    """
    rpcClient = RPCClient("Framework/ProxyManager", timeout=120)
    return rpcClient.generateToken(requester, requesterGroup, numUses)

  def renewProxy(self, proxyToBeRenewed=None, minLifeTime=3600, newProxyLifeTime=43200, proxyToConnect=None):
    """ Renew a proxy using the ProxyManager

        :param X509Chain proxyToBeRenewed: proxy to renew
        :param int minLifeTime: if proxy life time is less than this, renew. Skip otherwise
        :param int newProxyLifeTime: life time of new proxy
        :param X509Chain proxyToConnect: proxy to use for connecting to the service

        :return: S_OK(X509Chain)/S_ERROR()
    """
    retVal = multiProxyArgument(proxyToBeRenewed)
    if not retVal['Value']:
      return retVal
    proxyToRenewDict = retVal['Value']

    secs = proxyToRenewDict['chain'].getRemainingSecs()['Value']
    if secs > minLifeTime:
      deleteMultiProxy(proxyToRenewDict)
      return S_OK()

    if not proxyToConnect:
      proxyToConnectDict = {'chain': False, 'tempFile': False}
    else:
      retVal = multiProxyArgument(proxyToConnect)
      if not retVal['Value']:
        deleteMultiProxy(proxyToRenewDict)
        return retVal
      proxyToConnectDict = retVal['Value']

    userDN = proxyToRenewDict['chain'].getIssuerCert()['Value'].getSubjectDN()['Value']
    retVal = proxyToRenewDict['chain'].getDIRACGroup()
    if not retVal['OK']:
      deleteMultiProxy(proxyToRenewDict)
      deleteMultiProxy(proxyToConnectDict)
      return retVal
    userGroup = retVal['Value']
    limited = proxyToRenewDict['chain'].isLimitedProxy()['Value']

    voms = VOMS()
    retVal = voms.getVOMSAttributes(proxyToRenewDict['chain'])
    if not retVal['OK']:
      deleteMultiProxy(proxyToRenewDict)
      deleteMultiProxy(proxyToConnectDict)
      return retVal
    vomsAttrs = retVal['Value']
    if vomsAttrs:
      retVal = self.downloadVOMSProxy(userDN,
                                      userGroup,
                                      limited=limited,
                                      requiredTimeLeft=newProxyLifeTime,
                                      requiredVOMSAttribute=vomsAttrs[0],
                                      proxyToConnect=proxyToConnectDict['chain'])
    else:
      retVal = self.downloadProxy(userDN,
                                  userGroup,
                                  limited=limited,
                                  requiredTimeLeft=newProxyLifeTime,
                                  proxyToConnect=proxyToConnectDict['chain'])

    deleteMultiProxy(proxyToRenewDict)
    deleteMultiProxy(proxyToConnectDict)

    if not retVal['OK']:
      return retVal

    chain = retVal['Value']

    if not proxyToRenewDict['tempFile']:
      return chain.dumpAllToFile(proxyToRenewDict['file'])

    return S_OK(chain)

  def getDBContents(self, condDict={}):
    """ Get the contents of the db

        :param dict condDict: search condition

        :return: S_OK(dict)/S_ERROR() -- dict contain fields, record list, total records
    """
    rpcClient = RPCClient("Framework/ProxyManager", timeout=120)
    return rpcClient.getContents(condDict, [['UserDN', 'DESC']], 0, 0)

  def getVOMSAttributes(self, chain):
    """ Get the voms attributes for a chain

        :param X509Chain chain: proxy as a chain

        :return: S_OK(str)/S_ERROR()
    """
    return VOMS().getVOMSAttributes(chain)

  def getUploadedProxyLifeTime(self, DN, group):
    """ Get the remaining seconds for an uploaded proxy

        :param str DN: user DN
        :param str group: group

        :return: S_OK(int)/S_ERROR()
    """
    result = self.getDBContents({'UserDN': [DN], 'UserGroup': [group]})
    if not result['OK']:
      return result
    data = result['Value']
    if len(data['Records']) == 0:
      return S_OK(0)
    pNames = list(data['ParameterNames'])
    dnPos = pNames.index('UserDN')
    groupPos = pNames.index('UserGroup')
    expiryPos = pNames.index('ExpirationTime')
    for row in data['Records']:
      if DN == row[dnPos] and group == row[groupPos]:
        td = row[expiryPos] - datetime.datetime.utcnow()
        secondsLeft = td.days * 86400 + td.seconds
        return S_OK(max(0, secondsLeft))
    return S_OK(0)

  def getUserProxiesInfo(self):
    """ Get the user proxies uploaded info

        :return: S_OK(dict)/S_ERROR()
    """
    result = RPCClient("Framework/ProxyManager", timeout=120).getUserProxiesInfo()
    if 'rpcStub' in result:
      result.pop('rpcStub')
    return result

gProxyManager = ProxyManagerClient()
