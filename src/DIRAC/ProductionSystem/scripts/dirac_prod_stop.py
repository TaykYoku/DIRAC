#!/usr/bin/env python
"""
Stop a given production

Example:
  $ dirac-prod-stop 381
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

__RCSID__ = "$Id$"

import DIRAC
from DIRAC.Core.Utilities.DIRACScript import DIRACScript


@DIRACScript()
def main():
  # Registering arguments will automatically add their description to the help menu
  DIRACScript.registerArgument("prodID: Production ID")
  _, args = DIRACScript.parseCommandLine()

  from DIRAC.ProductionSystem.Client.ProductionClient import ProductionClient

  # get arguments
  prodID = args[0]

  prodClient = ProductionClient()

  res = prodClient.setProductionStatus(prodID, 'Stopped')
  if res['OK']:
    DIRAC.gLogger.notice('Production %s successully stopped' % prodID)
  else:
    DIRAC.gLogger.error(res['Message'])
    DIRAC.exit(-1)

  DIRAC.exit(0)


if __name__ == "__main__":
  main()
