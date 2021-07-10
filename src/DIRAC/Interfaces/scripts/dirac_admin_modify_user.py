#!/usr/bin/env python
########################################################################
# File :    dirac-admin-modify-user
# Author :  Adrian Casajus
########################################################################
"""
Modify a user in the CS.

Example:
  $ dirac-admin-modify-user vhamar /C=FR/O=Org/CN=User dirac_user
"""
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division

__RCSID__ = "$Id$"

import DIRAC
from DIRAC.Core.Utilities.DIRACScript import DIRACScript


@DIRACScript()
def main(self):
  self.registerSwitch("p:", "property=", "Add property to the user <name>=<value>")
  self.registerSwitch("f", "force", "create the user if it doesn't exist")
  # Registering arguments will automatically add their description to the help menu
  self.registerArgument(" user:     User name")
  self.registerArgument(" DN:       DN of the User")
  self.registerArgument(["group:    Add the user to the group"])
  self.parseCommandLine(ignoreErrors=True)

  from DIRAC.Interfaces.API.DiracAdmin import DiracAdmin
  diracAdmin = DiracAdmin()
  exitCode = 0
  forceCreation = False
  errorList = []

  userProps = {}
  for unprocSw in self.getUnprocessedSwitches():
    if unprocSw[0] in ("f", "force"):
      forceCreation = True
    elif unprocSw[0] in ("p", "property"):
      prop = unprocSw[1]
      pl = prop.split("=")
      if len(pl) < 2:
        errorList.append(("in arguments", "Property %s has to include a '=' to separate name from value" % prop))
        exitCode = 255
      else:
        pName = pl[0]
        pValue = "=".join(pl[1:])
        print("Setting property %s to %s" % (pName, pValue))
        userProps[pName] = pValue

  userName, userProps['DN'], userProps['Groups'] = self.getPositionalArgs(group=True)

  if not diracAdmin.csModifyUser(userName, userProps, createIfNonExistant=forceCreation):
    errorList.append(("modify user", "Cannot modify user %s" % userName))
    exitCode = 255
  else:
    result = diracAdmin.csCommitChanges()
    if not result['OK']:
      errorList.append(("commit", result['Message']))
      exitCode = 255

  for error in errorList:
    print("ERROR %s: %s" % error)

  DIRAC.exit(exitCode)


if __name__ == "__main__":
  main()  # pylint: disable=no-value-for-parameter
