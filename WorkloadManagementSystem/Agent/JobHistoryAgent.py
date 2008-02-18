########################################################################
# $Header: /tmp/libdirac/tmp.stZoy15380/dirac/DIRAC3/DIRAC/WorkloadManagementSystem/Agent/JobHistoryAgent.py,v 1.3 2008/02/18 10:10:11 atsareg Exp $


"""  JobHistoryAgent sends periodically numbers of jobs in various states for various
     sites to the Monitoring system to create historical plots.
"""

from DIRAC  import gLogger, gConfig, gMonitor,S_OK, S_ERROR
from DIRAC.Core.Base.Agent import Agent
from DIRAC.WorkloadManagementSystem.DB.JobDB import JobDB

import time,os

AGENT_NAME = 'WorkloadManagement/JobHistoryAgent'
MONITOR_SITES = ['LCG.CERN.ch','LCG.IN2P3.fr','LCG.RAL.uk','LCG.CNAF.it',
                 'LCG.GRIDKA.de','LCG.NIKHEF.nl','LCG.PIC.es','All sites']
MONITOR_STATUS = ['Running','Stalled','Done','Failed']

class JobHistoryAgent(Agent):

  def __init__(self):
    """ Standard constructor
    """
    Agent.__init__(self,AGENT_NAME)

  def initialize(self):
    result = Agent.initialize(self)
    self.jobDB = JobDB()

    for status in MONITOR_STATUS:
      for site in MONITOR_SITES:
        gLogger.verbose("Registering activity %s-%s" % (status,site)) 
        gMonitor.registerActivity("%s-%s" % (status,site),"%s jos" % status,"JobHistoryAgent","Jobs",gMonitor.OP_MEAN)

    return S_OK()

  def execute(self):
    """ Main execution method
    """

    result = self.jobDB.getCounters(['Status','Site'],{},'')    
    if not result['OK']:
      return S_ERROR('Failed to get data from the Job Database')

    totalDict = {}
    for status in MONITOR_STATUS:
      totalDict[status] = 0

    for row in result['Value']:
      dict = row[0]
      site = dict['Site']
      status = dict['Status']
      count = row[1]
      if site in MONITOR_SITES and status in MONITOR_STATUS:
        gLogger.verbose("Adding mark %s-%s: " % (status,site)+str(count))
        gMonitor.addMark("%s-%s" % (status,site),count)
        totalDict[status] += count

    for status in MONITOR_STATUS:
      gLogger.verbose("Adding mark %s-All sites: " % status + str(totalDict[status]))
      gMonitor.addMark("%s-All sites" % status,totalDict[status])

    return S_OK()
