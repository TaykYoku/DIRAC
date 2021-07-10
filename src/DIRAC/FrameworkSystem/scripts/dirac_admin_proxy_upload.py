#!/usr/bin/env python
########################################################################
# File :    dirac-admin-proxy-upload.py
# Author :  Adrian Casajus
########################################################################
"""
Upload proxy.

Example:
  $ dirac-admin-proxy-upload
"""
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division

__RCSID__ = "$Id$"

import sys

from DIRAC.Core.Utilities.DIRACScript import DIRACScript
from DIRAC.FrameworkSystem.Client.ProxyUpload import CLIParams, uploadProxy


@DIRACScript()
def main(self):
  cliParams = CLIParams()
  cliParams.registerCLISwitches(self)

  self.parseCommandLine()

  retVal = uploadProxy(cliParams)
  if not retVal['OK']:
    print(retVal['Message'])
    sys.exit(1)
  sys.exit(0)


if __name__ == "__main__":
  main()  # pylint: disable=no-value-for-parameter
