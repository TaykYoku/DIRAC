""" Collection of utilities for dealing with security files (i.e. proxy files)
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

__RCSID__ = "$Id$"

import six
import os
import json
import stat
import tempfile

from DIRAC import S_OK, S_ERROR
from DIRAC.Core.Utilities import DErrno
from DIRAC.Core.Security.Locations import getTokenLocation


def readTokenFromFile(fileName=None):
  """ Read token from a file

      arguments:
        - fileName : filename to read
  """
  try:
    with open(fileName or getTokenLocation(), 'r') as f:
      data = f.read()
    return S_OK(json.loads(data))
  except Exception as e:
    return S_ERROR('Cannot read token.')


def writeToTokenFile(tokenContents, fileName=False):
  """ Write a proxy string to file

      arguments:
        - tokenContents : string object to dump to file
        - fileName : filename to dump to
  """
  if not fileName:
    try:
      fd, tokenLocation = tempfile.mkstemp()
      os.close(fd)
    except IOError:
      return S_ERROR(DErrno.ECTMPF)
    fileName = tokenLocation
  try:
    with open(fileName, 'wb') as fd:
      fd.write(tokenContents)
  except Exception as e:
    return S_ERROR(DErrno.EWF, " %s: %s" % (fileName, repr(e).replace(',)', ')')))
  try:
    os.chmod(fileName, stat.S_IRUSR | stat.S_IWUSR)
  except Exception as e:
    return S_ERROR(DErrno.ESPF, "%s: %s" % (fileName, repr(e).replace(',)', ')')))
  return S_OK(fileName)


def writeTokenDictToTokenFile(tokenDict, fileName=None):
  """
  Write an dict to file

  arguments:
    - tokenDict : dict object to dump to file
    - fileName : filename to dump to
  """
  try:
    retVal = json.dumps(tokenDict)
  except Exception as e:
    return S_ERROR('Cannot read token.')
  print(fileName or getTokenLocation())
  return writeToTokenFile(retVal, fileName or getTokenLocation())


def writeTokenDictToTemporaryFile(tokenDict):
  """
  Write a token dict to a temporary file
  return S_OK( string with name of file )/ S_ERROR
  """
  try:
    fd, tokenLocation = tempfile.mkstemp()
    os.close(fd)
  except IOError:
    return S_ERROR(DErrno.ECTMPF)
  retVal = writeTokenDictToTokenFile(tokenDict, tokenLocation)
  if not retVal['OK']:
    try:
      os.unlink(tokenLocation)
    except Exception:
      pass
    return retVal
  return S_OK(tokenLocation)
