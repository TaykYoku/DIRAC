""" This is a test of using PilotManagerClient

    In order to run this test we need the following DBs installed:
    - PilotAgentsDB

    And the following services should also be on:
    - Pilots

   this is pytest!

"""

from DIRAC.Core.Base.Script import parseCommandLine
parseCommandLine()


from DIRAC import gLogger
from DIRAC.WorkloadManagementSystem.Client.PilotManagerClient import PilotManagerClient


gLogger.setLevel('VERBOSE')


def test_PilotsDB():

  pilots = PilotManagerClient()

  res = pilots.addPilotTQReference(['aPilot'], 1, '/a/ownerDN', 'a/owner/Group')
  if not res['OK']:
    raise Exception(res['Message'])
  res = pilots.getCurrentPilotCounters({})
  if not res['OK']:
    raise Exception(res['Message'])
  if not res['Value'] == {'Submitted': 1}:
    raise Exception(res)
  res = pilots.deletePilots('aPilot')
  if not res['OK']:
    raise Exception(res['Message'])
  res = pilots.getCurrentPilotCounters({})
  if not res['OK']:
    raise Exception(res['Message'])
  if not res['Value'] == {}:
    raise Exception(res)

  res = pilots.addPilotTQReference(['anotherPilot'], 1, '/a/ownerDN', 'a/owner/Group')
  if not res['OK']:
    raise Exception(res['Message'])
  res = pilots.storePilotOutput('anotherPilot', 'This is an output', 'this is an error')
  if not res['OK']:
    raise Exception(res['Message'])
  res = pilots.getPilotOutput('anotherPilot')
  if not res['OK']:
    raise Exception(res['Message'])
  if not res['Value'] == {'OwnerDN': '/a/ownerDN',
                                     'OwnerGroup': 'a/owner/Group',
                                     'StdErr': 'this is an error',
                                     'FileList': [],
                                     'StdOut': 'This is an output'}:
    raise Exception(res)
  res = pilots.getPilotInfo('anotherPilot')
  if not res['OK']:
    raise Exception(res['Message'])
  if not res['Value']['anotherPilot']['AccountingSent'] == 'False':
    raise Exception(res)
  if not res['Value']['anotherPilot']['PilotJobReference'] == 'anotherPilot':
    raise Exception(res)

  res = pilots.selectPilots({})
  if not res['OK']:
    raise Exception(res['Message'])
  res = pilots.getPilotSummary('', '')
  if not res['OK']:
    raise Exception(res['Message'])
  if not res['Value']['Total']['Submitted'] == 1:
    raise Exception(res)
  res = pilots.getPilotMonitorWeb({}, [], 0, 100)
  if not res['OK']:
    raise Exception(res['Message'])
  if not res['Value']['TotalRecords'] == 1:
    raise Exception(res)
  res = pilots.getPilotMonitorSelectors()
  if not res['OK']:
    raise Exception(res['Message'])
  if not res['Value'] == {'GridType': ['DIRAC'],
                          'OwnerGroup': ['a/owner/Group'],
                          'DestinationSite': ['NotAssigned'],
                          'Broker': ['Unknown'], 'Status': ['Submitted'],
                          'OwnerDN': ['/a/ownerDN'],
                          'GridSite': ['Unknown'],
                          'Owner': []}:
    raise Exception(res)
  res = pilots.getPilotSummaryWeb({}, [], 0, 100)
  if not res['OK']:
    raise Exception(res['Message'])
  if not res['Value']['TotalRecords'] == 1:
    raise Exception(res)

  res = pilots.setAccountingFlag('anotherPilot', 'True')
  if not res['OK']:
    raise Exception(res['Message'])
  res = pilots.setPilotStatus('anotherPilot', 'Running')
  if not res['OK']:
    raise Exception(res['Message'])
  res = pilots.getPilotInfo('anotherPilot')
  if not res['OK']:
    raise Exception(res['Message'])
  if not res['Value']['anotherPilot']['AccountingSent'] == 'True':
    raise Exception(res)
  if not res['Value']['anotherPilot']['Status'] == 'Running':
    raise Exception(res)

  res = pilots.setJobForPilot(123, 'anotherPilot')
  if not res['OK']:
    raise Exception(res['Message'])
  res = pilots.setPilotBenchmark('anotherPilot', 12.3)
  if not res['OK']:
    raise Exception(res['Message'])
  res = pilots.countPilots({})
  if not res['OK']:
    raise Exception(res['Message'])
#     res = pilots.getCounters()
#     # getPilotStatistics

  res = pilots.deletePilots('anotherPilot')
  if not res['OK']:
    raise Exception(res['Message'])
  res = pilots.getCurrentPilotCounters({})
  if not res['OK']:
    raise Exception(res['Message'])
  if not res['Value'] == {}:
    raise Exception(res)

test_PilotsDB()
