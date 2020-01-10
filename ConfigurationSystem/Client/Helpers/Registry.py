""" Helper for /Registry section
"""
import six
import errno

from DIRAC import S_OK, S_ERROR
from DIRAC.Core.Utilities import DErrno
from DIRAC.ConfigurationSystem.Client.Config import gConfig
from DIRAC.ConfigurationSystem.Client.Helpers.CSGlobals import getVO
from DIRAC.ConfigurationSystem.Client.Helpers.Resources import getInfoAboutProviders

try:
  from DIRAC.Resources.ProxyProvider.ProxyProviderFactory import ProxyProviderFactory
except ImportError:
  pass
try:
  from DIRAC.FrameworkSystem.Client.ProxyManagerClient import gProxyManager
except ImportError:
  pass
try:
  from OAuthDIRAC.FrameworkSystem.Client.OAuthManagerClient import gSessionManager
except ImportError:
  pass

__RCSID__ = "$Id$"

gBaseRegistrySection = "/Registry"

def getVOMSAttributeForGroup(group):
  """ Search VOMS attribute for group

      :param basestring group: group name

      :return: basestring
  """
  return gConfig.getValue("%s/Groups/%s/VOMSRole" % (gBaseRegistrySection, group), getDefaultVOMSAttribute())

def getIDsForUsername(username):
  """ Return IDs for DIRAC user

      :param basestring username: DIRAC user

      :return: list -- contain IDs
  """
  return gConfig.getValue("%s/Users/%s/ID" % (gBaseRegistrySection, username), [])

def getUsernameForID(ID, usersList=None):
  """ Get user name by ID

      :param basestring ID: user ID
      :param list usersList: list of user names

      :return: S_OK(basestring)/S_ERROR()
  """
  if not usersList:
    retVal = gConfig.getSections("%s/Users" % gBaseRegistrySection)
    if not retVal['OK']:
      return retVal
    usersList = retVal['Value']
  for username in usersList:
    if ID in gConfig.getValue("%s/Users/%s/ID" % (gBaseRegistrySection, username), []):
      return S_OK(username)
  return S_ERROR("No username found for ID %s" % ID)

def __getGroupsWithAttr(attrName, value):
  """ Get all posible groups with some attribute

      :param basestirng attrName: attribute name
      :param basestring value: attribute value

      :return: S_OK(list)/S_ERROR() -- contain list of groups
  """
  retVal = gConfig.getSections("%s/Groups" % gBaseRegistrySection)
  if not retVal['OK']:
    return retVal
  groupsList = retVal['Value']
  groups = []
  for group in groupsList:
    if value in gConfig.getValue("%s/Groups/%s/%s" % (gBaseRegistrySection, group, attrName), []):
      groups.append(group)
  if not groups:
    return S_ERROR("No groups found for %s=%s" % (attrName, value))
  groups.sort()
  return S_OK(groups)

def getDNForHost(host):
  """ Get host DN

      :param basestring host: host domain

      :return: S_OK(list)/S_ERROR() -- list of DNs
  """
  dnList = gConfig.getValue("%s/Hosts/%s/DN" % (gBaseRegistrySection, host), [])
  if dnList:
    return S_OK(dnList)
  return S_ERROR("No DN found for host %s" % host)

def getGroupsForVO(vo):
  """ Get groups for VO

      :param basestring vo: DIRAC VO name

      :return: S_OK(list)/S_ERROR()
  """
  if getVO():
    return gConfig.getSections("%s/Groups" % gBaseRegistrySection)
  return __getGroupsWithAttr('VO', vo)

def getGroupsWithProperty(propName):
  """ Search groups by property

      :param basestring propName: property name

      :return: S_OK(list)/S_ERROR()
  """
  return __getGroupsWithAttr("Properties", propName)

def getHostnameForDN(dn):
  """ Search host name for host DN

      :param basestring dn: host DN

      :return: S_OK()/S_ERROR()
  """
  retVal = gConfig.getSections("%s/Hosts" % gBaseRegistrySection)
  if not retVal['OK']:
    return retVal
  hostList = retVal['Value']
  for hostname in hostList:
    if dn in gConfig.getValue("%s/Hosts/%s/DN" % (gBaseRegistrySection, hostname), []):
      return S_OK(hostname)
  return S_ERROR("No hostname found for dn %s" % dn)

def getDefaultUserGroup():
  """ Search general default group

      :return: basestring
  """
  return gConfig.getValue("/%s/DefaultGroup" % gBaseRegistrySection, "user")

def getAllUsers():
  """ Get all users

      :return: list
  """
  retVal = gConfig.getSections("%s/Users" % gBaseRegistrySection)
  if not retVal['OK']:
    return []
  return retVal['Value']

def getAllGroups():
  """ Get all users

      :return: list
  """
  retVal = gConfig.getSections("%s/Groups" % gBaseRegistrySection)
  if not retVal['OK']:
    return []
  return retVal['Value']

def getPropertiesForGroup(groupName, defaultValue=None):
  """ Return group properties

      :param basestring groupName: group name
      :param basestring,list defaultValue: default value

      :return: list or basestring
  """
  option = "%s/Groups/%s/Properties" % (gBaseRegistrySection, groupName)
  return gConfig.getValue(option, [] if defaultValue is None else defaultValue)

def getPropertiesForHost(hostName, defaultValue=None):
  """ Return host properties

      :param basestring groupName: host name
      :param basestring,list defaultValue: default value

      :return: list or basestring
  """
  option = "%s/Hosts/%s/Properties" % (gBaseRegistrySection, hostName)
  return gConfig.getValue(option, [] if defaultValue is None else defaultValue)

def getPropertiesForEntity(group, name="", dn="", defaultValue=None):
  """ Return some entity properties

      :param basestring groupName: group name
      :param basestring name: entity name
      :param basestring dn: DN
      :param basestring,list defaultValue: default value

      :return: list or basestring
  """
  if group == 'hosts':
    if not name:
      result = getHostnameForDN(dn)
      if not result['OK']:
        return [] if defaultValue is None else defaultValue
      name = result['Value']
    return getPropertiesForHost(name, defaultValue)
  else:
    return getPropertiesForGroup(group, defaultValue)

def __matchProps(sProps, rProps):
  """ Match properties

      :param sProps: submited properties
      :param rProps: required properties

      :return: list -- contain matched properties
  """
  foundProps = []
  for prop in sProps:
    if prop in rProps:
      foundProps.append(prop)
  return foundProps

def groupHasProperties(groupName, propList):
  """ Match required properties with group properties

      :param basestring groupName: group name
      :param list propList: required properties

      :return: list -- contain matched properties
  """
  if isinstance(propList, six.string_types):
    propList = [propList]
  return __matchProps(propList, getPropertiesForGroup(groupName))

def hostHasProperties(hostName, propList):
  """ Match required properties with host properties

      :param basestring hostName: host name
      :param list propList: required properties

      :return: list -- contain matched properties
  """
  if isinstance(propList, six.string_types):
    propList = [propList]
  return __matchProps(propList, getPropertiesForHost(hostName))

def getUserOption(username, optName, defaultValue=""):
  """ Get user option

      :param basestring username: user name
      :param basestring optName: option name
      :param basestring,list defaultValue: default value

      :return: basestring or list
  """
  return gConfig.getValue("%s/Users/%s/%s" % (gBaseRegistrySection, username, optName), defaultValue)

def getGroupOption(groupName, optName, defaultValue=""):
  """ Get group option

      :param basestring groupName: group name
      :param basestring optName: option name
      :param basestring,list defaultValue: default value

      :return: basestring or list
  """
  return gConfig.getValue("%s/Groups/%s/%s" % (gBaseRegistrySection, groupName, optName), defaultValue)

def getHostOption(hostName, optName, defaultValue=""):
  """ Get host option

      :param basestring hostName: host name
      :param basestring optName: option name
      :param basestring,list defaultValue: default value

      :return: basestring or list
  """
  return gConfig.getValue("%s/Hosts/%s/%s" % (gBaseRegistrySection, hostName, optName), defaultValue)

def getHosts():
  """ Get all hosts

      :return: S_OK()/S_ERROR()
  """
  return gConfig.getSections('%s/Hosts' % gBaseRegistrySection)

def getVOOption(voName, optName, defaultValue=""):
  """ Get VO option

      :param basestring voName: DIRAC VO name
      :param basestring optName: option name
      :param basestring,list defaultValue: default value

      :return: basestring or list
  """
  return gConfig.getValue("%s/VO/%s/%s" % (gBaseRegistrySection, voName, optName), defaultValue)

def getBannedIPs():
  """ Get banned IPs

      :return: list
  """
  return gConfig.getValue("%s/BannedIPs" % gBaseRegistrySection, [])

def getVOForGroup(group):
  """ Search VO name for group

      :param basestring group: group name

      :return: basestring
  """
  voName = getVO()
  if voName:
    return voName
  return gConfig.getValue("%s/Groups/%s/VO" % (gBaseRegistrySection, group), "")

def getDefaultVOMSAttribute():
  """ Get default VOMS attribute

      :return: basestring
  """
  return gConfig.getValue("%s/DefaultVOMSAttribute" % gBaseRegistrySection, "")

def getDefaultVOMSVO():
  """ Get default VOMS VO

      :return: basestring
  """
  vomsVO = gConfig.getValue("%s/DefaultVOMSVO" % gBaseRegistrySection, "")
  if vomsVO:
    return vomsVO
  return getVO()

def getVOMSVOForGroup(group):
  """ Search VOMS VO for group

      :param basestring group: group name

      :return: basestring
  """
  vomsVO = gConfig.getValue("%s/Groups/%s/VOMSVO" % (gBaseRegistrySection, group), getDefaultVOMSVO())
  if not vomsVO:
    vo = getVOForGroup(group)
    vomsVO = getVOOption(vo, 'VOMSName', '')
  return vomsVO

def getGroupsWithVOMSAttribute(vomsAttr):
  """ Search groups with VOMS attribute

      :param basestring vomsAttr: VOMS attribute

      :return: list
  """
  retVal = gConfig.getSections("%s/Groups" % (gBaseRegistrySection))
  if not retVal['OK']:
    return []
  groups = []
  for group in retVal['Value']:
    if vomsAttr == gConfig.getValue("%s/Groups/%s/VOMSRole" % (gBaseRegistrySection, group), ""):
      groups.append(group)
  return groups

def getVOs():
  """ Get all the configured VOs

      :return: S_OK(list)/S_ERROR()
  """
  voName = getVO()
  if voName:
    return S_OK([voName])
  return gConfig.getSections('%s/VO' % gBaseRegistrySection)

def getVOMSServerInfo(requestedVO=''):
  """ Get information on VOMS servers for the given VO or for all of them

      :param basestring requestedVO: requested VO

      :return: S_OK()/S_ERROR()
  """
  vomsDict = {}
  result = getVOs()
  if result['OK']:
    voNames = result['Value']
    for vo in voNames:
      if requestedVO and vo != requestedVO:
        continue
      vomsName = getVOOption(vo, 'VOMSName', '')
      if not vomsName:
        continue
      vomsDict.setdefault(vo, {})
      vomsDict[vo]['VOMSName'] = getVOOption(vo, 'VOMSName', '')
      result = gConfig.getSections('%s/VO/%s/VOMSServers' % (gBaseRegistrySection, vo))
      if result['OK']:
        serverList = result['Value']
        vomsDict[vo].setdefault("Servers", {})
        for server in serverList:
          vomsDict[vo]['Servers'].setdefault(server, {})
          DN = gConfig.getValue('%s/VO/%s/VOMSServers/%s/DN' % (gBaseRegistrySection, vo, server), '')
          CA = gConfig.getValue('%s/VO/%s/VOMSServers/%s/CA' % (gBaseRegistrySection, vo, server), '')
          port = gConfig.getValue('%s/VO/%s/VOMSServers/%s/Port' % (gBaseRegistrySection, vo, server), 0)
          vomsDict[vo]['Servers'][server]['DN'] = DN
          vomsDict[vo]['Servers'][server]['CA'] = CA
          vomsDict[vo]['Servers'][server]['Port'] = port

  return S_OK(vomsDict)

def getVOMSRoleGroupMapping(vo=''):
  """ Get mapping of the VOMS role to the DIRAC group

      :param basestring vo: perform the operation for the given VO

      :return: S_OK(dict)/S_ERROR() -- dictionary have standard structure with two mappings: 
               VOMS-DIRAC { <VOMS_Role>: [<DIRAC_Group>] },
               DIRAC-VOMS { <DIRAC_Group>: <VOMS_Role> }
               and a list of DIRAC groups without mapping
  """
  result = getGroupsForVO(vo)
  if not result['OK']:
    return result

  groupList = result['Value']

  vomsGroupDict = {}
  groupVomsDict = {}
  noVOMSGroupList = []
  noVOMSSyncGroupList = []

  for group in groupList:
    vomsRole = getGroupOption(group, 'VOMSRole')
    if vomsRole:
      vomsGroupDict.setdefault(vomsRole, [])
      vomsGroupDict[vomsRole].append(group)
      groupVomsDict[group] = vomsRole
      syncVOMS = getGroupOption(group, 'AutoSyncVOMS', True)
      if not syncVOMS:
        noVOMSSyncGroupList.append(group)

  for group in groupList:
    if group not in groupVomsDict:
      noVOMSGroupList.append(group)

  return S_OK({"VOMSDIRAC": vomsGroupDict,
               "DIRACVOMS": groupVomsDict,
               "NoVOMS": noVOMSGroupList,
               "NoSyncVOMS": noVOMSSyncGroupList})

def isDownloadableGroup(groupName):
  """ Get permission to download proxy with group in a argument

      :params basestring groupName: DIRAC group

      :return: bool
  """
  if getGroupOption(groupName, 'DownloadableProxy') in [False, 'False', 'false', 'no']:
    return False
  return True

def getDNsForUsernameFromSC(username):
  """ Find all DNs for DIRAC user
  
      :param basestring username: DIRAC user
      :param bool active: if need to search only DNs with active sessions
      
      :return: list -- contain DNs
  """
  return gConfig.getValue("%s/Users/%s/DN" % (gBaseRegistrySection, username), [])

def getUsersInGroup(group):
  """ Find all users for group

      :param basestring group: group name
  
      :return: list
  """
  users = getGroupOption(group, 'Users', [])
  for ID in getGroupOption(group, 'IDs', []):
    users += getUsernameForID(ID)
  for dn in getGroupOption(group, 'DNs', []):
    users += getUsernameForDN(dn)
  users.sort()
  return list(set(users))

def getProviderForID(ID):
  """ Search identity provider for user ID

      :param basestring ID: user ID

      :return: S_OK(list)/S_ERROR()
  """
  try:
    gSessionManager
  except Exception:
    try:
      from OAuthDIRAC.FrameworkSystem.Client.OAuthManagerClient import gSessionManager
    except Exception as ex:
      return S_ERROR('Session manager not found:', ex)
  result = gSessionManager.getIdPsCache([ID])
  if not result['OK']:
    return result
  providers = []
  for ID, idDict in result['Value'].items():
    providers += idDict.get('Providers') or []
  if not providers:
    return S_ERROR('Cannot find identity providers for %s' % ID)
  return S_OK(list(set(providers)))

def getDNsForUsername(username, active=False):
  """ Find all DNs for DIRAC user
  
      :param basestring username: DIRAC user
      :param bool active: if need to search only DNs with active sessions
      
      :return: S_OK(list)/S_ERROR() -- contain DNs
  """
  try:
    gSessionManager
  except Exception:
    try:
      from OAuthDIRAC.FrameworkSystem.Client.OAuthManagerClient import gSessionManager
    except Exception:
      pass
  try:
    result = gSessionManager.getIdPsCache(getIDsForUsername(username))
    if not result['OK']:
      return result
    IdPsDict = result['Value']
  except Exception:
    IdPsDict = {}
  
  DNs = getDNsForUsernameFromSC(username)
  for ID, idDict in IdPsDict.items():
    if idDict.get('DNs'):
      # if active:
      #   for prov in infoDict['Providers']:
      #     if not idDict[ID][prov]:
      #       continue
      DNs += idDict['DNs'].keys()
  return S_OK(list(set(DNs)))

def getUsernameForDN(dn, usersList=None):
  """ Find DIRAC user for DN
  
      :param basestring dn: user DN
      :param list usersList: list of posible users
      
      :return: S_OK()/S_ERROR()
  """
  for username in (usersList or getAllUsers()):
    result = getDNsForUsername(username)
    if not result['OK']:
      return result
    if dn in result['Value']:
      return S_OK(username)
  return S_ERROR("No username found for dn %s" % dn)

def getGroupsForUser(username):
  """ Find groups for user
  
      :param basestring username: user name
      
      :return: S_OK(list)/S_ERROR()
  """
  groups = []
  result = getDNsForUsername(username)
  if not result['OK']:
    return result
  userDNs = result['Value']
  userIDs = getIDsForUsername(username)
  for group in getAllGroups():
    if username in getGroupOption(group, 'Users', []):
      groups.append(group)
    elif any(dn in getGroupOption(group, 'DNs', []) for dn in userDNs):
      groups.append(group)
    elif any(ID in getGroupOption(group, 'IDs', []) for ID in userIDs):
      groups.append(group)
  if not groups:
    return S_ERROR('No groups found for %s user' % username)
  groups.sort()
  return S_OK(list(set(groups)))

def findDefaultGroupForDN(dn):
  """ Search defaut group for DN

      :param basestring dn: DN

      :return: S_OK()/S_ERROR()
  """
  result = getUsernameForDN(dn)
  if not result['OK']:
    return result
  return findDefaultGroupForUser(result['Value'])

def findDefaultGroupForUser(username):
  """ Get default group for user

      :param basestring username: user name

      :return: S_OK(basestring)/S_ERROR()
  """
  userDefGroups = getUserOption(username, "DefaultGroup", [])
  defGroups = userDefGroups + gConfig.getValue("%s/DefaultGroup" % gBaseRegistrySection, ["user"])
  result = getGroupsForUser(username)
  if not result['OK']:
    return result
  userGroups = result['Value']
  for group in defGroups:
    if group in userGroups:
      return S_OK(group)
  return S_OK(userGroups[0])

def getProxyProviderForDN(userDN):
  """ Get proxy providers by user DN

      :param basestring userDN: user DN

      :return: S_OK(basestring)/S_ERROR()
  """
  result = getUsernameForDN(userDN)
  if not result['OK']:
    return result
  username = result['Value']

  try:
    gSessionManager
  except Exception:
    try:
      from OAuthDIRAC.FrameworkSystem.Client.OAuthManagerClient import gSessionManager
    except Exception:
      pass
  try:
    result = gSessionManager.getIdPsCache(getIDsForUsername(username))
    if not result['OK']:
      return result
    IDsDict = result['Value']
  except Exception:
    IDsDict = {}

  provider = None
  for ID, idDict in IDsDict.items():
    if userDN in (idDict.get('DNs') or []):
      provider = idDict['DNs'][userDN].get('ProxyProvider')
  
  if not provider:
    # Get providers
    result = getInfoAboutProviders(of='Proxy')
    if not result['OK']:
      return result
      
    # Try to use getUserDN method if exist
    try:
      ProxyProviderFactory()
    except Exception:
      from DIRAC.Resources.ProxyProvider.ProxyProviderFactory import ProxyProviderFactory
    for providerName in result['Value']:
      providerObj = ProxyProviderFactory().getProxyProvider(providerName)
      if providerObj['OK'] and 'getUserDN' in dir(providerObj['Value']):
        result = providerObj['Value'].getUserDN(userDN=userDN)
        if result['OK']:
          return S_OK(providerName)

  return S_OK(provider or 'Certificate')

def getUsersInVO(vo):
  """ Search users in VO

      :param basestring vo: DIRAC VO name

      :return: list
  """
  userList = []
  result = getGroupsForVO(vo)
  if not result['OK'] or not result['Value']:
    return userList
  for group in result['Value']:
    userList += getUsersInGroup(group)
  userList.sort()
  return userList

def getEmailsForGroup(groupName):
  """ Get email list of users in group

      :param basestring groupName: DIRAC group name

      :return: list(list) -- inner list contains emails for a user
  """
  emails = []
  for username in getUsersInGroup(groupName):
    email = getUserOption(username, 'Email', [])
    emails.append(email)
  return emails

def getGroupsForDN(userDN):
  """ Get all posible groups for DN

      :param basestirng userDN: user DN

      :return: S_OK(list)/S_ERROR() -- contain list of groups
  """
  try:
    gProxyManager
  except Exception:
    from DIRAC.FrameworkSystem.Client.ProxyManagerClient import gProxyManager
  result = gProxyManager.getActualVOMSesDNs(userDN)
  vomsInfo = result['Value'] if result['OK'] else {}

  groups = []
  vomsRoles = userDN in vomsInfo and vomsInfo[userDN].get('VOMSRoles') or []
  for vomsRole in vomsRoles:
    groups += getGroupsWithVOMSAttribute(vomsRole)

  result = getUsernameForDN(userDN)
  if not result['OK']:
    return result
  username = result['Value']

  for group in getAllGroups():
    if userDN in getGroupOption(group, 'DNs', []):
      groups.append(group)
    elif username in getGroupOption(group, 'Users', []):
      groups.append(group)

  return S_OK(list(set(groups)))
  
def getDNForUsernameInGroup(username, group):
  """ Get user DN for user in group

      :param basestirng username: user name
      :param basestring group: group name

      :return: S_OK(basestring)/S_ERROR()
  """
  result = getDNsForUsername(username)
  if not result['OK']:
    return result
  userDNs = result['Value']
  for dn in getDNsInGroup(group):
    if dn in userDNs:
      return S_OK(dn)
  return S_ERROR('For %s@%s not found DN.' % (username, group))

def getDNsInGroup(group):
  """ Find user DNs for DIRAC group
  
      :param basestring group: group name
      
      :return: list
  """
  try:
    gProxyManager
  except Exception:
    from DIRAC.FrameworkSystem.Client.ProxyManagerClient import gProxyManager
  result = gProxyManager.getActualVOMSesDNs()
  vomsInfo = result['Value'] if result['OK'] else {}

  DNs = getGroupOption(group, 'DNs', [])
  vomsRole = getGroupOption(group, 'VOMSRole', '')
  for dn, infoDict in vomsInfo.items():
    if vomsRole in infoDict['VOMSRoles']:
      DNs.append(dn)
  
  for username in getGroupOption(group, 'Users', []):
    result = getDNsForUsername(username)
    if not result['OK']:
      return result
    if not any(dn in result['Value'] for dn in DNs):
      result = findSomeDNToUseForGroupsThatNotNeedDN(username)
      if not result['OK']:
        return result
      DNs.append(result['Value'])
    
  return list(set(DNs))

def getGroupsStatusByUsername(username):
  """ Get status of every group for DIRAC user

      :param basestring username: user name

      :return: S_OK(dict)/S_ERROR()
  """
  statusDict = {}
  result = getGroupsForUser(username)
  if not result['OK']:
    return result
  for group in result['Value']:
    result = getStatusGroupByUsername(group, username)
    if not result['OK']:
      return result
    statusDict[group] = result['Value']
  return S_OK(statusDict)

def getStatusGroupByUsername(group, username):
  """ Get status of group for DIRAC user

      :param basestring group: group name
      :param basestring username: user name

      :return: S_OK(dict)/S_ERROR() -- dict contain next structure:
               {'Status': <status of group>, 'Comment': <information what need to do>}
  """
  result = getDNForUsernameInGroup(username, group)
  if not result['OK']:
    return result
  dn = result['Value']

  try:
    gProxyManager
  except Exception:
    from DIRAC.FrameworkSystem.Client.ProxyManagerClient import gProxyManager
  
  vomsRole = getGroupOption(group, 'VOMSRole')
  if vomsRole:
    result = gProxyManager.getActualVOMSesDNs([dn])
    vomsInfo = result['Value'] if result['OK'] else {}
    if not any(dnDict.get('VOMSRoles') for dnDict in vomsInfo.values()):
      return S_OK({'Status': 'failed', 'Comment': 'Not found VOMS role'})
    if any(vomsRole in dnDict['SuspendedRoles'] for dnDict in vomsInfo.values()):
      return S_OK({'Status': 'suspended', 'Comment': 'User suspended'})

  result = gProxyManager.userHasProxy(username, group)
  if not result['OK']:
    return result
  if not result['Value']:
    result = getProxyProviderForDN(dn)
    if not result['OK']:
      return result
    proxyProvider = result['Value']
    if proxyProvider == 'Certificate':
      return S_OK({'Status': 'needToUpload', 'Comment': 'Need to upload %s certificate' % dn})

    try:
      ProxyProviderFactory()
    except Exception:
      from DIRAC.Resources.ProxyProvider.ProxyProviderFactory import ProxyProviderFactory
    providerRes = ProxyProviderFactory().getProxyProvider(proxyProvider)
    if not providerRes['OK']:
      return providerRes
    return providerRes['Value'].checkStatus(dn)
    
  return S_OK({'Status': 'ready', 'Comment': 'Proxy uploaded'})

def findSomeDNToUseForGroupsThatNotNeedDN(username):
  """ This method is HACK for groups that not need DN from user, like as dirac_user, dirac_admin
      In this cause we will search first DN in CS or any DN that we can to find

      :param basestring username: user name

      :return: S_OK(basestring)/S_ERROR()
  """
  defDNs = getDNsForUsernameFromSC(username)
  if not defDNs:
    result = getDNsForUsername(username)
    if not result['OK']:
      return result
    defDNs = result['Value']
  return S_OK(defDNs[0])