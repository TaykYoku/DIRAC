#!/usr/bin/env python
########################################################################
# File :    dirac-dms-pfn-metadata
# Author :  Stuart Paterson
########################################################################
"""
Retrieve metadata for a PFN given a valid DIRAC SE
"""
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division

__RCSID__ = "$Id$"

import DIRAC
from DIRAC.Core.Base import Script
from DIRAC.Core.Utilities.DIRACScript import DIRACScript


@DIRACScript()
def main():
  Script.registerArgument("PFN:      Physical File Name or file containing PFNs")
  Script.registerArgument("SE:       Valid DIRAC SE")
  Script.parseCommandLine(ignoreErrors=True)
  args = Script.getPositionalArgs()

  if len(args) > 2:
    print('Only one PFN SE pair will be considered')

  from DIRAC.Interfaces.API.Dirac import Dirac
  dirac = Dirac()
  exitCode = 0

  pfn = args[0]
  seName = args[1]
  try:
    f = open(pfn, 'r')
    pfns = f.read().splitlines()
    f.close()
  except BaseException:
    pfns = [pfn]

  for pfn in pfns:
    result = dirac.getPhysicalFileMetadata(pfn, seName, printOutput=True)
    if not result['OK']:
      print('ERROR: ', result['Message'])
      exitCode = 2

  DIRAC.exit(exitCode)


if __name__ == "__main__":
  main()
