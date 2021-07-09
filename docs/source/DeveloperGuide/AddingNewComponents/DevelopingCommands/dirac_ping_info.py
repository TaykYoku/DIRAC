#!/usr/bin/env python
"""
Ping a list of services and show the result

Example:
  $ dirac-ping-info MySystem
  Ping MySystem!
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

__RCSID__ = "$Id$"

import sys

from DIRAC import S_OK, S_ERROR, gLogger, exit as DIRACExit
from DIRAC.Core.Utilities.DIRACScript import DIRACScript


# Define a simple class to hold the script parameters
class MyPing(DIRACScript):

  def initParameters(self):
    self.raw = False
    self.pingsToDo = 1

  def setRawResult(self, value):
    self.raw = True
    return S_OK()

  def setNumOfPingsToDo(self, value):
    try:
      self.pingsToDo = max(1, int(value))
    except ValueError:
      return S_ERROR("Number of pings to do has to be a number")
    return S_OK()


@MyPing()
def main(self):
  # Register accepted switches and their callbacks
  self.registerSwitch("r", "showRaw", "show raw result from the query", self.setRawResult)
  self.registerSwitch("p:", "numPings=", "Number of pings to do (by default 1)", self.setNumOfPingsToDo)
  self.registerArgument(['System: system names'])

  # Parse the command line and initialize DIRAC
  swithes, servicesList = self.parseCommandLine(ignoreErrors=False)

  # Get the list of services
  servicesList = self.getPositionalArgs()

  # Do something!
  gLogger.notice('Ping %s!' % ', '.join(servicesList))

if __name__ == "__main__":
  main()  # pylint: disable=no-value-for-parameter