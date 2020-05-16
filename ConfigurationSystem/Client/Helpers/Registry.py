""" Helper for /Registry section
"""
import six
import errno

from DIRAC import S_OK, S_ERROR
from DIRAC.Core.Utilities import DErrno
from DIRAC.ConfigurationSystem.Client.Config import gConfig
from DIRAC.ConfigurationSystem.Client.Helpers.CSGlobals import getVO
from DIRAC.ConfigurationSystem.Client.Helpers.Resources import getProviderInfo

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

# pylint: disable=missing-docstring

gBaseRegistrySection = "/Registry"


def getVOMSInfo(vo=None, dn=None):
  """ Get cached information from VOMS API
  
      :param list dn: requested DN

      :return: S_OK(dict)/S_ERROR()
  """
  try:
    gProxyManager
  except Exception:
    from DIRAC.FrameworkSystem.Client.ProxyManagerClient import gProxyManager
  return gProxyManager.getActualVOMSesDNs(voList=[vo] if vo else vo, dnList=[dn] if dn else dn)


def getUsernameForDN(dn, usersList=None):
  """ Find DIRAC user for DN

      :param str dn: user DN
      :param list usersList: list of possible users

      :return: S_OK(str)/S_ERROR()
  """
  if not usersList:
    result = gConfig.getSections("%s/Users" % gBaseRegistrySection)
    if not result['OK']:
      return result
    usersList = result['Value']
  for username in usersList:
    if dn in gConfig.getValue("%s/Users/%s/DN" % (gBaseRegistrySection, username), []):
      return S_OK(username)
  
  try:
    gSessionManager
  except Exception:
    try:
      from OAuthDIRAC.FrameworkSystem.Client.OAuthManagerClient import gSessionManager  # pylint: disable=import-error
    except Exception as ex:
      return S_ERROR("No username found for dn %s" % dn)
  
  result = gSessionManager.getIdPsCache()
  if not result['OK']:
    return result
  idPsDict = result['Value']

  for oid, data in idPsDict.items():
    if dn in data['DNs']:
      result = getUsernameForID(oid)
      if result['OK']:
        return result

  return S_ERROR("No username found for dn %s" % dn)


def getDNForHost(host):
  """ Get host DN

      :param str host: host domain

      :return: S_OK(list)/S_ERROR() -- list of DNs
  """
  dnList = gConfig.getValue("%s/Hosts/%s/DN" % (gBaseRegistrySection, host), [])
  return S_OK(dnList) if dnList else S_ERROR("No DN found for host %s" % host)


def getGroupsForDN(dn, groupsList=None):
  """ Get all possible groups for DN

      :param str dn: user DN
      :param list groupsList: group list where need to search

      :return: S_OK(list)/S_ERROR() -- contain list of groups
  """
  groups = []
  if not groupsList:
    result = gConfig.getSections("%s/Groups" % gBaseRegistrySection)
    if not result['OK']:
      return result
    groupsList = result['Value']

  result = getUsernameForDN(dn)
  if not result['OK']:
    return result
  user = result['Value']

  result = getVOMSInfo(dn=dn)
  if not result['OK']:
    return result
  vomsData = result['Value']

  result = getVOsWithVOMS()
  if not result['OK']:
    return result
  vomsVOs = result['Value']

  for group in groupsList:
    if user in getGroupOption(group, 'Users', []):
      vo = getGroupOption(group, 'VO')
      if vo in vomsVOs and vomsData[vo]['OK']:
        voData = vomsData[vo]['Value']
        role = getGroupOption(group, 'VOMSRole')
        if not role or role in voData[dn]['VOMSRoles']:
          groups.append(group)
      else:
        # What we know more about VO?
        groups.append(group)

  groups.sort()
  return S_OK(list(set(groups))) if groups else S_ERROR('No groups found for %s' % dn)


def __getGroupsWithAttr(attrName, value):
  """ Get all possible groups with some attribute

      :param str attrName: attribute name
      :param str value: attribute value

      :return: S_OK(list)/S_ERROR() -- contain list of groups
  """
  result = gConfig.getSections("%s/Groups" % gBaseRegistrySection)
  if not result['OK']:
    return result
  groupsList = result['Value']
  groups = []
  for group in groupsList:
    if value in gConfig.getValue("%s/Groups/%s/%s" % (gBaseRegistrySection, group, attrName), []):
      groups.append(group)
  groups.sort()
  return S_OK(groups) if groups else S_ERROR("No groups found for %s=%s" % (attrName, value))


def getGroupsForUser(username, groupsList=None):
  """ Find groups for user or if set reseachedGroup check it for user

      :param str username: user name
      :param list groupsList: groups

      :return: S_OK(list or bool)/S_ERROR() -- contain list of groups or status group for user
  """
  if not groupsList:
    retVal = gConfig.getSections("%s/Groups" % gBaseRegistrySection)
    if not retVal['OK']:
      return retVal
    groupsList = retVal['Value']

  groups = []
  for group in groupsList:
    if username in getGroupOption(group, 'Users', []):
      groups.append(group)

  groups.sort()
  return S_OK(list(set(groups))) if groups else S_ERROR('No groups found for %s user' % username)

def getGroupsForVO(vo):
  """ Get groups for VO

      :param str vo: DIRAC VO name

      :return: S_OK(list)/S_ERROR()
  """
  if getVO(): 
    return gConfig.getSections("%s/Groups" % gBaseRegistrySection)
  return __getGroupsWithAttr('VO', vo)


def getGroupsWithProperty(propName):
  """ Search groups by property

      :param str propName: property name

      :return: S_OK(list)/S_ERROR()
  """
  return __getGroupsWithAttr("Properties", propName)


def getHostnameForDN(dn):
  """ Search host name for host DN

      :param str dn: host DN

      :return: S_OK()/S_ERROR()
  """
  result = gConfig.getSections("%s/Hosts" % gBaseRegistrySection)
  if not result['OK']:
    return result
  hostList = result['Value']
  for hostname in hostList:
    if dn in gConfig.getValue("%s/Hosts/%s/DN" % (gBaseRegistrySection, hostname), []):
      return S_OK(hostname)
  return S_ERROR("No hostname found for dn %s" % dn)


def getDefaultUserGroup():
  """ Search general default group

      :return: str
  """
  return gConfig.getValue("/%s/DefaultGroup" % gBaseRegistrySection, "user")


def findDefaultGroupForDN(dn):
  """ Search defaut group for DN

      :param str dn: DN

      :return: S_OK()/S_ERROR()
  """
  result = getUsernameForDN(dn)
  if not result['OK']:
    return result
  return findDefaultGroupForUser(result['Value'])


def findDefaultGroupForUser(userName):
  """ Get default group for user

      :param str userName: user name

      :return: S_OK(str)/S_ERROR()
  """
  defGroups = getUserOption(userName, "DefaultGroup", [])
  defGroups += gConfig.getValue("%s/DefaultGroup" % gBaseRegistrySection, ["user"])
  result = getGroupsForUser(userName)
  if not result['OK']:
    return result
  userGroups = result['Value']
  for group in defGroups:
    if group in userGroups:
      return S_OK(group)
  return S_OK(userGroups[0]) if userGroups else S_ERROR("User %s has no groups" % userName)


def getAllUsers():
  """ Get all users

      :return: list
  """
  result = gConfig.getSections("%s/Users" % gBaseRegistrySection)
  return result['Value'] if result['OK'] else []


def getAllGroups():
  """ Get all groups

      :return: list
  """
  result = gConfig.getSections("%s/Groups" % gBaseRegistrySection)
  return result['Value'] if result['OK'] else []


def getUsersInGroup(group, defaultValue=None):
  """ Find all users for group

      :param str group: group name
      :param defaultValue: default value

      :return: list
  """
  users = getGroupOption(group, 'Users', [])
  users.sort()
  return list(set(users)) or [] if defaultValue is None else defaultValue


def getUsersInVO(vo, defaultValue=None):
  """ Search users in VO

      :param str vo: DIRAC VO name
      :param defaultValue: default value

      :return: list
  """
  users = []
  result = getGroupsForVO(vo)
  if result['OK'] and result['Value']:
    for group in result['Value']:
      users += getUsersInGroup(group)

  users.sort()
  return users or [] if defaultValue is None else defaultValue


def getDNsInGroup(group, checkStatus=False):
  """ Find user DNs for DIRAC group

      :param str group: group name
      :param bool checkStatus: don't add suspended DNs

      :return: list
  """
  vo = getGroupOption(group, 'VO')
  
  result = getVOMSInfo(vo=vo)
  if not result['OK']:
    return result
  vomsData = result['Value']

  result = getVOsWithVOMS()
  if not result['OK']:
    return result
  vomsVOs = result['Value']

  DNs = []
  for username in getGroupOption(group, 'Users', []):
    result = getDNsForUsername(username)
    if not result['OK']:
      return result
    userDNs = result['Value']
    if vo in vomsVOs and vomsData[vo]['OK']:
      voData = vomsData[vo]['Value']
      role = getGroupOption(group, 'VOMSRole')
      for dn in userDNs:
        if not role or role in voData[dn]['ActuelRoles' if checkStatus else 'VOMSRoles']:
          DNs.append(dn)
    else:
      DNs += userDNs

  return list(set(DNs))


def getPropertiesForGroup(groupName, defaultValue=None):
  """ Return group properties

      :param str groupName: group name
      :param defaultValue: default value

      :return: defaultValue or list
  """
  option = "%s/Groups/%s/Properties" % (gBaseRegistrySection, groupName)
  return gConfig.getValue(option, [] if defaultValue is None else defaultValue)


def getPropertiesForHost(hostName, defaultValue=None):
  """ Return host properties

      :param str hostName: host name
      :param defaultValue: default value

      :return: defaultValue or list
  """
  option = "%s/Hosts/%s/Properties" % (gBaseRegistrySection, hostName)
  return gConfig.getValue(option, [] if defaultValue is None else defaultValue)


def getPropertiesForEntity(group, name="", dn="", defaultValue=None):
  """ Return some entity properties

      :param str group: group name
      :param str name: entity name
      :param str dn: DN
      :param defaultValue: default value

      :return: defaultValue or list
  """
  if group == 'hosts':
    if not name:
      result = getHostnameForDN(dn)
      if not result['OK']:
        return [] if defaultValue is None else defaultValue
      name = result['Value']
    return getPropertiesForHost(name, defaultValue)
  return getPropertiesForGroup(group, defaultValue)


def __matchProps(sProps, rProps):
  """ Match properties

      :param sProps: submitted properties
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

      :param str groupName: group name
      :param list propList: required properties

      :return: list -- contain matched properties
  """

  if isinstance(propList, six.string_types):
    propList = [propList]
  return __matchProps(propList, getPropertiesForGroup(groupName))


def hostHasProperties(hostName, propList):
  """ Match required properties with host properties

      :param str hostName: host name
      :param list propList: required properties

      :return: list -- contain matched properties
  """
  if isinstance(propList, six.string_types):
    propList = [propList]
  return __matchProps(propList, getPropertiesForHost(hostName))


def getUserOption(userName, optName, defaultValue=""):
  """ Get user option

      :param str userName: user name
      :param str optName: option name
      :param defaultValue: default value

      :return: defaultValue or str
  """
  return gConfig.getValue("%s/Users/%s/%s" % (gBaseRegistrySection, userName, optName), defaultValue)


def getGroupOption(groupName, optName, defaultValue=""):
  """ Get group option

      :param str groupName: group name
      :param str optName: option name
      :param defaultValue: default value

      :return: defaultValue or str
  """
  return gConfig.getValue("%s/Groups/%s/%s" % (gBaseRegistrySection, groupName, optName), defaultValue)


def getHostOption(hostName, optName, defaultValue=""):
  """ Get host option

      :param str hostName: host name
      :param str optName: option name
      :param defaultValue: default value

      :return: defaultValue or str
  """
  return gConfig.getValue("%s/Hosts/%s/%s" % (gBaseRegistrySection, hostName, optName), defaultValue)


def getHosts():
  """ Get all hosts

      :return: S_OK()/S_ERROR()
  """
  return gConfig.getSections('%s/Hosts' % gBaseRegistrySection)


def getVOOption(voName, optName, defaultValue=""):
  """ Get VO option

      :param str voName: DIRAC VO name
      :param str optName: option name
      :param defaultValue: default value

      :return: defaultValue or str
  """
  return gConfig.getValue("%s/VO/%s/%s" % (gBaseRegistrySection, voName, optName), defaultValue)


def getBannedIPs():
  """ Get banned IPs

      :return: list
  """
  return gConfig.getValue("%s/BannedIPs" % gBaseRegistrySection, [])


def getVOForGroup(group):
  """ Search VO name for group

      :param str group: group name

      :return: str
  """
  return getVO() or gConfig.getValue("%s/Groups/%s/VO" % (gBaseRegistrySection, group), "")


def getDefaultVOMSAttribute():
  """ Get default VOMS attribute

      :return: str
  """
  return gConfig.getValue("%s/DefaultVOMSAttribute" % gBaseRegistrySection, "")


def getVOMSAttributeForGroup(group):
  """ Search VOMS attribute for group

      :param str group: group name

      :return: str
  """
  return gConfig.getValue("%s/Groups/%s/VOMSRole" % (gBaseRegistrySection, group), getDefaultVOMSAttribute())


def getDefaultVOMSVO():
  """ Get default VOMS VO

      :return: str
  """
  return gConfig.getValue("%s/DefaultVOMSVO" % gBaseRegistrySection, "") or getVO()


def getVOMSVOForGroup(group):
  """ Search VOMS VO for group

      :param str group: group name

      :return: str
  """
  vomsVO = gConfig.getValue("%s/Groups/%s/VOMSVO" % (gBaseRegistrySection, group), getDefaultVOMSVO())
  if not vomsVO:
    vo = getVOForGroup(group)
    vomsVO = getVOOption(vo, 'VOMSName', '')
  return vomsVO


def getGroupsWithVOMSAttribute(vomsAttr, groupsList=None):
  """ Search groups with VOMS attribute

      :param str vomsAttr: VOMS attribute
      :param list groupsList: groups where need to search

      :return: list
  """
  groups = []
  for group in groupsList or getAllGroups():
    if vomsAttr == gConfig.getValue("%s/Groups/%s/VOMSRole" % (gBaseRegistrySection, group), ""):
      groups.append(group)
  return groups


def getVOs():
  """ Get all the configured VOs

      :return: S_OK(list)/S_ERROR()
  """
  voName = getVO()
  return S_OK([voName]) if voName else gConfig.getSections('%s/VO' % gBaseRegistrySection)


def getVOMSServerInfo(requestedVO=''):
  """ Get information on VOMS servers for the given VO or for all of them

      :param str requestedVO: requested VO

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

      :param str vo: perform the operation for the given VO

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


def getUsernameForID(ID, usersList=None):
  """ Get DIRAC user name by ID

      :param str ID: user ID
      :param list usersList: list of DIRAC user names

      :return: S_OK(str)/S_ERROR()
  """
  if not usersList:
    result = gConfig.getSections("%s/Users" % gBaseRegistrySection)
    if not result['OK']:
      return result
    usersList = result['Value']
  for username in usersList:
    if ID in gConfig.getValue("%s/Users/%s/ID" % (gBaseRegistrySection, username), []):
      return S_OK(username)
  return S_ERROR("No username found for ID %s" % ID)


def isDownloadableGroup(groupName):
  """ Get permission to download proxy with group in a argument

      :params str groupName: DIRAC group

      :return: boolean
  """
  if getGroupOption(groupName, 'DownloadableProxy') in [False, 'False', 'false', 'no']:
    return False
  return True


def getEmailsForGroup(groupName):
  """ Get email list of users in group

      :param str groupName: DIRAC group name

      :return: list(list) -- inner list contains emails for a user
  """
  emails = []
  for username in getUsersInGroup(groupName):
    email = getUserOption(username, 'Email', [])
    emails.append(email)
  return emails


def getIDsForUsername(username):
  """ Return IDs for DIRAC user

      :param str username: DIRAC user

      :return: list -- contain IDs
  """
  return gConfig.getValue("%s/Users/%s/ID" % (gBaseRegistrySection, username), [])


def getVOsWithVOMS(voList=None):
  """ Get all the configured VOMS VOs

      :param list voList: VOs where to look

      :return: S_OK(list)/S_ERROR()
  """
  vos = []
  if not voList:
    result = getVOs()
    if not result['OK']:
      return result
    voList = result['Value']
  for vo in voList:
    if getVOOption(vo, 'VOMSName'):
      vos.append(vo)
  return S_OK(vos)


def getDNsForUsernameFromSC(username):
  """ Find all DNs for DIRAC user

      :param str username: DIRAC user
      :param bool active: if need to search only DNs with active sessions

      :return: list -- contain DNs
  """
  return gConfig.getValue("%s/Users/%s/DN" % (gBaseRegistrySection, username), [])


def getProviderForID(userID):
  """ Search identity provider for user ID

      :param str ID: user ID

      :return: S_OK(list)/S_ERROR()
  """
  try:
    gSessionManager
  except Exception:
    try:
      from OAuthDIRAC.FrameworkSystem.Client.OAuthManagerClient import gSessionManager  # pylint: disable=import-error
    except Exception as ex:
      return S_ERROR('Session manager not found:', ex)
  result = gSessionManager.getIdPsCache([userID])
  if not result['OK']:
    return result
  providers = []
  for userID, idDict in result['Value'].items():
    providers += idDict.get('Providers') or []
  if not providers:
    return S_ERROR('Cannot find identity providers for %s' % userID)
  return S_OK(list(set(providers)))


def getDNsForUsername(username):
  """ Find all DNs for DIRAC user

      :param str username: DIRAC user

      :return: S_OK(list)/S_ERROR() -- contain DNs
  """
  try:
    gSessionManager
  except Exception:
    try:
      from OAuthDIRAC.FrameworkSystem.Client.OAuthManagerClient import gSessionManager  # pylint: disable=import-error
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
  for userID, idDict in IdPsDict.items():
    if idDict.get('DNs'):
      DNs += idDict['DNs'].keys()
  return S_OK(list(set(DNs)))


def getProxyProviderForDN(userDN):
  """ Get proxy providers by user DN

      :param str userDN: user DN

      :return: S_OK(str)/S_ERROR()
  """
  result = getDNProperty(userDN, 'ProxyProviders')
  if not result['OK']:
    return result
  if result['Value']:
    return S_OK(result['Value'])

  result = getUsernameForDN(userDN)
  if not result['OK']:
    return result
  username = result['Value']

  try:
    gSessionManager
  except Exception:
    try:
      from OAuthDIRAC.FrameworkSystem.Client.OAuthManagerClient import gSessionManager  # pylint: disable=import-error
    except Exception:
      pass
  try:
    result = gSessionManager.getIdPsCache(getIDsForUsername(username))
    if not result['OK']:
      return result
    IDsDict = result['Value']
  except Exception:
    IDsDict = {}

  # provider = None
  for userID, idDict in IDsDict.items():
    if userDN in (idDict.get('DNs') or []):
      if idDict['DNs'][userDN].get('ProxyProvider'):
        return S_OK(idDict['DNs'][userDN]['ProxyProvider'])

  # if not provider:
  #   result = getDNProperty(userDN, 'ProxyProvider')
  #   if not result['OK']:
  #     return result
    
    # # Get providers
    # result = getInfoAboutProviders(of='Proxy')
    # if result['OK']:
    #   try:
    #     ProxyProviderFactory()
    #   except Exception:
    #     from DIRAC.Resources.ProxyProvider.ProxyProviderFactory import ProxyProviderFactory
    #   for providerName in result['Value']:
    #     providerObj = ProxyProviderFactory().getProxyProvider(providerName)
    #     if providerObj['OK'] and 'getUserDN' in dir(providerObj['Value']):
    #       result = providerObj['Value'].getUserDN(userDN=userDN)
    #       if result['OK']:
    #         return S_OK(providerName)

  return S_OK('Certificate')


def getDNForUsernameInGroup(username, group, checkStatus=False):
  """ Get user DN for user in group

      :param str username: user name
      :param str group: group name
      :param bool checkStatus: don't add suspended DNs

      :return: S_OK(str)/S_ERROR()
  """
  result = getDNsForUsername(username)
  if not result['OK']:
    return result
  userDNs = result['Value']
  for dn in getDNsInGroup(group, checkStatus):
    if dn in userDNs:
      return S_OK(dn)
  return S_ERROR('For %s@%s not found DN%s.' % (username, group, ' or it suspended' if checkStatus else ''))


def getGroupsStatusByUsername(username):
  """ Get status of every group for DIRAC user

      :param str username: user name

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

      :param str group: group name
      :param str username: user name

      :return: S_OK(dict)/S_ERROR() -- dict contain next structure:
               {'Status': <status of group>, 'Comment': <information what need to do>}
  """
  result = getDNForUsernameInGroup(username, group)
  if not result['OK']:
    return result
  dn = result['Value']
  
  vo = getGroupOption(group, 'VO')

  # Check VOMS VO
  result = getVOsWithVOMS(voList=[vo])
  if not result['OK']:
    return result
  if result['Value']:
    role = getGroupOption(group, 'VOMSRole')
    
    result = getVOMSInfo(vo=vo, dn=dn)
    if not result['OK']:
      return result
    vomsData = result['Value']

      # return S_OK({'Status': 'unknown',
      #              'Comment': 'Research process crashed: %s.' % resVOMSInfo['Message']})
    # data = resVOMSInfo['Value']
    if vo in vomsData:
      if not vomsData[vo]['OK']:
        return S_OK({'Status': 'unknown', 'Comment': vomsData[vo]['Messages']})
    else:
      return S_OK({'Status': 'unknown',
                   'Comment': 'Fail to get %s VOMS VO information depended for this group' % vo})
    voData = vomsData[vo]['Value']
    if dn not in voData:
      return S_OK({'Status': 'failed',
                   'Comment': 'You are not a member of %s VOMS VO depended for this group' % vo})
    if not role:
      if voData[dn]['Suspended']:
        return S_OK({'Status': 'suspended', 'Comment': 'User suspended'})
    else: 
      if role not in voData[dn]['VOMSRoles']:
        return S_OK({'Status': 'failed',
                     'Comment': 'You have no %s VOMS role depended for this group' % role})
      if role in voData[dn]['SuspendedRoles']:
        return S_OK({'Status': 'suspended',
                     'Comment': 'User suspended for %s VOMS role.' % role})

  # vomsRole = getGroupOption(group, 'VOMSRole')
  # if vomsRole:
  #   result = gProxyManager.getActualVOMSesDNs([dn])
  #   dnDict = result['Value'].get(dn, {}) if result['OK'] else {}
  #   if vomsRole not in dnDict.get('VOMSRoles', []):
  #     return S_OK({'Status': 'failed',
  #                  'Comment': 'You have no %s VOMS role depended for this group' % vomsRole})
  #   if (vomsRole in dnDict.get('SuspendedRoles', [])) or dnDict.get('suspended'):
  #     return S_OK({'Status': 'suspended', 'Comment': 'User suspended'})

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

      :param str username: user name

      :return: S_OK(str)/S_ERROR()
  """
  defDNs = getDNsForUsernameFromSC(username)
  if not defDNs:
    result = getDNsForUsername(username)
    return S_OK(result['Value'][0]) if result['OK'] else result
  return S_OK(defDNs[0])

def getDNProperty(dn, prop, defaultValue=None):
  """ Get user DN property

      :param str dn: user DN
      :param str prop: property name
      :param defaultValue: default value

      :return: S_OK()/S_ERROR()
  """
  result = getUsernameForDN(dn)
  if not result['OK']:
    return result
  root = "%s/Users/%s/DNProperties" % (gBaseRegistrySection, result['Value'])
  result = gConfig.getSections(root)
  if not result['OK']:
    return result
  for section in result['Value']:
    if dn == gConfig.getValue("%s/%s/DN" % (root, section)):
      return S_OK(gConfig.getValue("%s/%s/%s" % (root, section, prop), defaultValue))
  return S_OK(defaultValue)
