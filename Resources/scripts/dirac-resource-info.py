#!/usr/bin/env python
"""
  Get information on resources: Computing and Storage
"""

__RCSID__ = "$Id$"

from DIRAC.Core.Base import Script
from DIRAC import S_OK, gLogger, exit as DIRACExit

Script.setUsageMessage( '\n'.join( ['Get information on resources',
                                    'Usage:',
                                    '%s [option]...' % Script.scriptName ] ) )

ceFlag = False
seFlag = False
voName = None

def setCEFlag(args_):
  global ceFlag
  ceFlag = True

def setSEFlag(args_):
  global seFlag
  seFlag = True

def setVOName(args):
  global voName
  voName = args

Script.registerSwitch("C", "ce", "Get CE info", setCEFlag)
Script.registerSwitch("S", "se", "Get SE info", setSEFlag)
Script.registerSwitch("V:", "vo=", "Get resources for the given VO", setVOName)


Script.parseCommandLine( ignoreErrors = True )

from DIRAC.Core.Security.ProxyInfo import getVOfromProxyGroup
from DIRAC.ConfigurationSystem.Client.Helpers import Resources
from DIRAC.Core.Utilities.PrettyPrint import printTable
from DIRAC.Resources.Storage.StorageElement import StorageElement
from DIRAC.ResourceStatusSystem.Client.ResourceStatus import ResourceStatus
from DIRAC.ResourceStatusSystem.Client.SiteStatus import SiteStatus

def printCEInfo(voName):

  resultQueues = Resources.getQueues(community = voName)
  if not resultQueues['OK']:
    gLogger.error('Failed to get CE information')
    DIRACExit(-1)

  fields = ("Site",'CE','CEType','Queue', 'Status')
  records = []

  # get list of usable sites within this cycle
  resultMask = SiteStatus().getUsableSites()
  if not resultMask['OK']:
    return resultMask
  siteMaskList = resultMask.get('Value', [])

  rssClient = ResourceStatus()

  for site in resultQueues['Value']:
    siteStatus = "Active" if site in siteMaskList else "InActive"
    siteNew = True
    for ce in resultQueues['Value'][site]:

      ceStatus = siteStatus
      if rssClient.rssFlag:
        result = rssClient.getElementStatus(ce, "ComputingElement")
        if result['OK']:
          ceStatus = result['Value'][ce]['all']

      ceNew = True
      for queue in resultQueues['Value'][site][ce]['Queues']:
        pSite = site if siteNew else ''
        pCE = ''
        ceType = ''
        if ceNew:
          pCE = ce
          ceType = resultQueues['Value'][site][ce]['CEType']
        records.append((pSite, pCE, ceType, queue, ceStatus))
        ceNew = False
        siteNew = False

  gLogger.notice(printTable(fields, records, printOut=False, columnSeparator = '  '))
  return S_OK()

def printSEInfo(voName):

  result = Resources.getStorageElements(vo=voName)
  if not result['OK']:
    gLogger.error('Failed to get SE information')
    DIRACExit(-1)
  seDict = result['Value']

  fields = ('SE','Status', 'Protocols', 'Aliases')
  records = []

  for se in seDict:
    seObject = StorageElement(se)
    result = seObject.status()
    status = []
    for statusType in ['Write', 'Read']:
      if result[statusType]:
        status.append(statusType)

    if status:
      status = '/'.join(status)
    else:
      status = "InActive"

    records.append((se, status,
                    ",".join(seDict[se]["Protocols"]),
                    ",".join(seDict[se]["Aliases"])))

  gLogger.notice(printTable(fields, records, printOut=False, columnSeparator = '  '))
  return S_OK()

if __name__ == '__main__':
  if not voName:
    # Get the current VO
    result = getVOfromProxyGroup()
    if not result['OK']:
      gLogger.error('No proxy found, please login')
      DIRACExit(-1)
    voName = result['Value']

  if not (ceFlag or seFlag):
    gLogger.error('Resource type is not specified')
    DIRACExit(-1)

  if ceFlag:
    result = printCEInfo(voName)
    if not result['OK']:
      gLogger.error(result['Message'])
      DIRACExit(-1)
  if seFlag:
    result = printSEInfo(voName)
    if not result['OK']:
      gLogger.error(result['Message'])
      DIRACExit(-1)

  DIRACExit(0)