"""
Create and put Requests to move files.

List of operations:

#. ReplicateAndRegister LFNs
#. Check for Migration
#. Remove all other replicas for these files
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import os

import DIRAC
from DIRAC import gLogger
from DIRAC.Core.Utilities.DIRACScript import DIRACScript
from DIRAC.Core.Utilities.List import breakListIntoChunks
from DIRAC.Core.Utilities.ReturnValues import returnSingleResult
from DIRAC.FrameworkSystem.private.standardLogging.LogLevels import LogLevels
from DIRAC.RequestManagementSystem.Client.File import File
from DIRAC.RequestManagementSystem.Client.Request import Request
from DIRAC.RequestManagementSystem.Client.Operation import Operation

__RCSID__ = '$Id$'


class CreateMovingRequest(DIRACScript):
  """Create the request to move files from one SE to another."""

  def initParameters(self):
    """Constructor."""
    self.log = gLogger.getSubLogger('CreateMoving')
    self.requests = []
    self._reqClient = None
    self._fcClient = None
    self._requestName = 'Moving_'
    self.switches = {}
    self.options = [('L', 'List', 'File containing list of LFNs to move'),
                    ('P', 'Path', 'LFN path to folder, all files in the folder will be moved'),
                    ('S', 'SourceSE', 'Where to remove the LFNs from'),
                    ('T', 'TargetSE', 'Where to move the LFNs to'),
                    ('N', 'Name', 'Name of the Request'),
                    ]
    self.flags = [('C', 'CheckMigration',
                   'Ensure the LFNs are migrated to tape before removing any replicas'),
                  ('X', 'Execute', 'Put Requests, else dryrun'),
                  ]
    self.registerSwitchesAndParseCommandLine()
    self.getLFNList()
    self.getLFNMetadata()

  @property
  def fcClient(self):
    """Return FileCatalogClient."""
    if not self._fcClient:
      from DIRAC.Resources.Catalog.FileCatalog import FileCatalog
      self._fcClient = FileCatalog()
    return self._fcClient

  @property
  def reqClient(self):
    """Return RequestClient."""
    if not self._reqClient:
      from DIRAC.RequestManagementSystem.Client.ReqClient import ReqClient
      self._reqClient = ReqClient()
    return self._reqClient

  @property
  def dryRun(self):
    """Return dry run flag."""
    return self.switches['DryRun']

  @property
  def targetSE(self):
    """Return the list of targetSE."""
    return self.switches['TargetSE']

  @property
  def sourceSEs(self):
    """Return the list of sourceSEs."""
    return self.switches['SourceSE']

  @property
  def lfnFolderPath(self):
    """Return the lfn folder path where to find the files of the request."""
    return self.switches.get('Path', None)

  def registerSwitchesAndParseCommandLine(self):
    """Register the default plus additional parameters and parse options.

    :param list options: list of three tuple for options to add to the script
    :param list flags:  list of three tuple for flags to add to the script
    :param str opName
    """
    for short, longOption, doc in self.options:
      self.registerSwitch(short + ':' if short else '', longOption + '=', doc)
    for short, longOption, doc in self.flags:
      self.registerSwitch(short, longOption, doc)
      self.switches[longOption] = False
    self.parseCommandLine()
    if self.getPositionalArgs():
      self.showHelp(exitCode=1)

    for switch in self.getUnprocessedSwitches():
      for short, longOption, doc in self.options:
        if switch[0] == short or switch[0].lower() == longOption.lower():
          self.log.verbose('Found switch %r with value %r' % (longOption, switch[1]))
          self.switches[longOption] = switch[1]
          break
      for short, longOption, doc in self.flags:
        if switch[0] == short or switch[0].lower() == longOption.lower():
          self.switches[longOption] = True
          break

    self.checkSwitches()
    self.switches['DryRun'] = not self.switches.get('Execute', False)
    self.switches['SourceSE'] = self.switches.get('SourceSE', '').split(',')

  def checkSwitches(self):
    """Check the switches, set autoName if needed."""
    if not self.switches.get('SourceSE'):
      raise RuntimeError('Have to set "SourceSE"')
    if not self.switches.get('TargetSE'):
      raise RuntimeError('Have to set "TargetSE"')
    if not self.switches.get('List') and not self.switches.get('Path'):
      raise RuntimeError('Have to set "List" or "Path"')

  def getLFNList(self):
    """Get list of LFNs.

    Either read the provided file, or get the files found beneath the provided folder.

    :returns: list of lfns
    :raises: RuntimeError, ValueError
    """
    if self.switches.get('List'):
      if os.path.exists(self.switches.get('List')):
        self.lfnList = list(set([line.split()[0]
                                 for line in open(self.switches.get('List')).read().splitlines()]))
      else:
        raise ValueError('%s not a file' % self.switches.get('List'))
    elif self.lfnFolderPath:
      path = self.lfnFolderPath
      self.log.debug('Check if %r is a directory' % path)
      isDir = returnSingleResult(self.fcClient.isDirectory(path))
      self.log.debug('Result: %r' % isDir)
      if not isDir['OK'] or not isDir['Value']:
        self.log.error('Path is not a directory', isDir.get('Message', ''))
        raise RuntimeError('Path %r is not a directory' % path)
      self.log.notice('Looking for files in %r' % path)

      metaDict = {'SE': self.sourceSEs[0]} if self.switches.get('SourceOnly') else {}
      lfns = self.fcClient.findFilesByMetadata(metaDict=metaDict, path=path)
      if not lfns['OK']:
        self.log.error('Could not find files')
        raise RuntimeError(lfns['Message'])
      self.lfnList = lfns['Value']

    if self.lfnList:
      self.log.notice('Will create request(s) with %d lfns' % len(self.lfnList))
      if len(self.lfnList) == 1:
        raise RuntimeError('Only 1 file in the list, aborting!')
      return

    raise ValueError('"Path" or "List" need to be provided!')

  def getLFNMetadata(self):
    """Get the metadata for all the LFNs."""
    metaData = self.fcClient.getFileMetadata(self.lfnList)
    error = False
    if not metaData['OK']:
      self.log.error('Unable to read metadata for lfns: %s' % metaData['Message'])
      raise RuntimeError('Could not read metadata: %s' % metaData['Message'])

    self.metaData = metaData['Value']
    for failedLFN, reason in self.metaData['Failed'].items():
      self.log.error('skipping %s: %s' % (failedLFN, reason))
      error = True
    if error:
      raise RuntimeError('Could not read all metadata')

    for lfn in self.metaData['Successful'].keys():
      self.log.verbose('found %s' % lfn)

  def run(self):
    """Perform checks and create the request."""
    from DIRAC.RequestManagementSystem.private.RequestValidator import RequestValidator
    for count, lfnChunk in enumerate(breakListIntoChunks(self.lfnList, 100)):
      if not lfnChunk:
        self.log.error('LFN list is empty!!!')
        return 1

      requestName = '%s_%d' % (self.switches.get('Name'), count)
      request = self.createRequest(requestName, lfnChunk)
      valid = RequestValidator().validate(request)
      if not valid['OK']:
        self.log.error('putRequest: request not valid', '%s' % valid['Message'])
        return 1
      else:
        self.requests.append(request)

    self.putOrRunRequests()
    return 0

  def createRequest(self, requestName, lfnChunk):
    """Create the Request."""
    request = Request()
    request.RequestName = requestName

    replicate = Operation()
    replicate.Type = 'ReplicateAndRegister'
    replicate.TargetSE = self.switches.get('TargetSE')
    self.addLFNs(replicate, lfnChunk, addPFN=True)
    request.addOperation(replicate)

    if self.switches.get('CheckMigration'):
      checkMigration = Operation()
      checkMigration.Type = 'CheckMigration'
      checkMigration.TargetSE = self.switches.get('TargetSE')
      self.addLFNs(checkMigration, lfnChunk, addPFN=True)
      request.addOperation(checkMigration)

    removeReplicas = Operation()
    removeReplicas.Type = 'RemoveReplica'
    removeReplicas.TargetSE = ','.join(self.switches.get('SourceSE', []))
    self.addLFNs(removeReplicas, lfnChunk)
    request.addOperation(removeReplicas)

    return request

  def addLFNs(self, operation, lfns, addPFN=False):
    """Add lfns to operation.

    :param operation: the operation instance to which the files will be added
    :param list lfns: list of lfns
    :param bool addPFN: if true adds PFN to each File
    """
    if not self.metaData:
      self.getLFNMetadata()

    for lfn in lfns:
      metaDict = self.metaData['Successful'][lfn]
      opFile = File()
      opFile.LFN = lfn
      if addPFN:
        opFile.PFN = lfn
      opFile.Size = metaDict['Size']
      if 'Checksum' in metaDict:
        # should check checksum type, now assuming Adler32 (metaDict['ChecksumType'] = 'AD')
        opFile.Checksum = metaDict['Checksum']
        opFile.ChecksumType = 'ADLER32'
      operation.addFile(opFile)

  def putOrRunRequests(self):
    """Run or put requests."""
    requestIDs = []

    if self.dryRun:
      self.log.notice('Would have created %d requests' % len(self.requests))
      for reqID, req in enumerate(self.requests):
        self.log.notice('Request %d:' % reqID)
        for opID, op in enumerate(req):
          self.log.notice('        Operation %d: %s #lfn %d' % (opID, op.Type, len(op)))
      return 0
    for request in self.requests:
      putRequest = self.reqClient.putRequest(request)
      if not putRequest['OK']:
        self.log.error('unable to put request %r: %s' % (request.RequestName, putRequest['Message']))
        continue
      requestIDs.append(str(putRequest['Value']))
      self.log.always('Request %r has been put to ReqDB for execution.' % request.RequestName)

    if requestIDs:
      self.log.always('%d requests have been put to ReqDB for execution' % len(requestIDs))
      self.log.always('RequestID(s): %s' % ' '.join(requestIDs))
      self.log.always('You can monitor the request status using the command: dirac-rms-request <requestName/ID>')
      return 0

    self.log.error('No requests created')
    return 1


@CreateMovingRequest()
def main(self):
  try:
    self.run()
  except Exception as e:
    if LogLevels.getLevelValue(self.log.getLevel()) <= LogLevels.VERBOSE:
      self.log.exception('Failed to create Moving Request')
    else:
      self.log.error('ERROR: Failed to create Moving Request:', str(e))
    exit(1)
  exit(0)


if __name__ == "__main__":
  main()  # pylint: disable=no-value-for-parameter
