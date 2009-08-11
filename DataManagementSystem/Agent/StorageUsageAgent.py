"""  StorageUsageAgent takes the LFC as the primary source of information to determine storage usage.
"""
# $Header: /tmp/libdirac/tmp.stZoy15380/dirac/DIRAC3/DIRAC/DataManagementSystem/Agent/StorageUsageAgent.py,v 1.12 2009/08/11 14:18:48 acsmith Exp $
__RCSID__ = "$Id: StorageUsageAgent.py,v 1.12 2009/08/11 14:18:48 acsmith Exp $"

from DIRAC  import gLogger, gMonitor, S_OK, S_ERROR, rootPath
from DIRAC.Core.Base.AgentModule import AgentModule

from DIRAC.Core.DISET.RPCClient import RPCClient
from DIRAC.Core.Utilities.Shifter import setupShifterProxyInEnv

from DIRAC.DataManagementSystem.Agent.NamespaceBrowser import NamespaceBrowser
from DIRAC.DataManagementSystem.Client.ReplicaManager import CatalogDirectory
from DIRAC.Core.Utilities.List import sortList

import time,os
from types import *

AGENT_NAME = 'DataManagement/StorageUsageAgent'

class StorageUsageAgent(AgentModule):

  def initialize(self):
    self.catalog = CatalogDirectory() # FileCatalog(['LcgFileCatalogCombined'])
    self.StorageUsageDB = RPCClient('DataManagement/StorageUsage')
    self.am_setModuleParam("shifterProxy", "DataManager")
    self.am_setModuleParam("shifterProxyLocation","%s/runit/%s/proxy" % (rootPath,AGENT_NAME))
    return S_OK()

  def execute(self):
    res = self.StorageUsageDB.getStorageSummary()
    if res['OK']:
      gLogger.info("StorageUsageAgent: Storage Usage Summary")
      gLogger.info("============================================================")
      gLogger.info("StorageUsageAgent: %s %s %s" % ('Storage Element'.ljust(40),'Number of files'.rjust(20),'Total size'.rjust(20)))
      for se in sortList(res['Value'].keys()):
        usage = res['Value'][se]['Size']
        files = res['Value'][se]['Files']
        site = se.split('_')[0].split('-')[0]
        gLogger.info("StorageUsageAgent: %s %s %s" % (se.ljust(40),str(files).rjust(20),str(usage).rjust(20)))
        gMonitor.registerActivity("%s-used" % se, "%s usage" % se,"StorageUsage/%s usage" % site,"",gMonitor.OP_MEAN,bucketLength = 600)
        gMonitor.addMark("%s-used" % se, usage )
        gMonitor.registerActivity("%s-files" % se, "%s files" % se,"StorageUsage/%s files" % site,"Files",gMonitor.OP_MEAN, bucketLength = 600)
        gMonitor.addMark("%s-files" % se, files )

    
    baseDir = self.am_getOption('BaseDirectory','/lhcb')
    ignoreDirectories = self.am_getOption('Ignore',[])
    oNamespaceBrowser = NamespaceBrowser(baseDir)
    gLogger.info("StorageUsageAgent: Initiating with %s as base directory." % baseDir)

    # Loop over all the directories and sub-directories
    while (oNamespaceBrowser.isActive()):
      currentDir = oNamespaceBrowser.getActiveDir()
      gLogger.info("StorageUsageAgent: Getting usage for %s." % currentDir)
      numberOfFiles = 0
      res = self.catalog.getCatalogDirectorySize(currentDir)
      if not res['OK']:
        gLogger.error("StorageUsageAgent: Completely failed to get usage.", "%s %s" % (currentDir,res['Message']))
        subDirs = [currentDir]
      elif res['Value']['Failed'].has_key(currentDir):
        gLogger.error("StorageUsageAgent: Failed to get usage.", "%s %s" % (currentDir,res['Value']['Failed'][currentDir]))
        subDirs = [currentDir]
      else:
        directoryMetadata = res['Value']['Successful'][currentDir]
        subDirs = directoryMetadata['SubDirs']
        closedDirs = directoryMetadata['ClosedDirs']
        gLogger.info("StorageUsageAgent: Found %s sub-directories." % len(subDirs))
        if closedDirs:
          gLogger.info("StorageUsageAgent: %s sub-directories are closed (ignored)." % len(closedDirs))
          for dir in closedDirs:
            gLogger.info("StorageUsageAgent: %s" % dir)
            subDirs.remove(dir)
        numberOfFiles = int(directoryMetadata['Files'])
        gLogger.info("StorageUsageAgent: Found %s files in the directory." % numberOfFiles)
        totalSize = long(directoryMetadata['TotalSize'])

        siteUsage = directoryMetadata['SiteUsage']
        if numberOfFiles > 0:
          res = self.StorageUsageDB.insertDirectory(currentDir,numberOfFiles,totalSize)
          if not res['OK']:
            gLogger.error("StorageUsageAgent: Failed to insert the directory.", "%s %s" % (currentDir,res['Message']))
            subDirs = [currentDir]
          else:
            gLogger.info("StorageUsageAgent: Successfully inserted directory.\n")
            gLogger.info("StorageUsageAgent: %s %s %s" % ('Storage Element'.ljust(40),'Number of files'.rjust(20),'Total size'.rjust(20)))
            for storageElement in sortList(siteUsage.keys()):
              usageDict = siteUsage[storageElement]
              res = self.StorageUsageDB.publishDirectoryUsage(currentDir,storageElement,long(usageDict['Size']),usageDict['Files'])
              if not res['OK']:
                gLogger.error("StorageUsageAgent: Failed to update the Storage Usage database.", "%s %s" % (storageElement,res['Message']))
                subDirs = [currentDir]
              else:
                gLogger.info("StorageUsageAgent: %s %s %s" % (storageElement.ljust(40),str(usageDict['Files']).rjust(20),str(usageDict['Size']).rjust(20)))

      # If there are no subdirs
      if (len(subDirs) ==  0) and (len(closedDirs) == 0) and (numberOfFiles == 0):
        gLogger.info("StorageUsageAgent: Attempting to remove empty directory from Storage Usage database")
        res = self.StorageUsageDB.publishEmptyDirectory(currentDir)
        if not res['OK']:
          gLogger.error("StorageUsageAgent: Failed to remove empty directory from Storage Usage database.",res['Message'])
        else:
          res = self.catalog.removeCatalogDirectory(currentDir)
          if not res['OK']:
            gLogger.error("StorageUsageAgent: Failed to remove empty directory from File Catalog.",res['Message'])
          elif res['Value']['Failed'].has_key(currentDir):
            gLogger.error("StorageUsageAgent: Failed to remove empty directory from File Catalog.",res['Value']['Failed'][currentDir])
          else:
            gLogger.info("StorageUsageAgent: Successfully removed empty directory from File Catalog.")

      chosenDirs = []
      for subDir in subDirs:
        if subDir not in ignoreDirectories:
          chosenDirs.append(subDir)
      oNamespaceBrowser.updateDirs(chosenDirs)
      gLogger.info("StorageUsageAgent: There are %s active directories to be searched." % oNamespaceBrowser.getNumberActiveDirs())

    gLogger.info("StorageUsageAgent: Finished recursive directory search.")
    return S_OK()


