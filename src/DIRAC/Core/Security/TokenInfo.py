"""
 Set of utilities to retrieve Information from proxy
"""
from __future__ import division
from __future__ import absolute_import
from __future__ import print_function

import jwt as _jwt
import six
import time

from DIRAC import S_OK, S_ERROR, gLogger
from DIRAC.Core.Utilities import DErrno
from DIRAC.Core.Security import Locations

from DIRAC.Core.Security.TokenFile import readTokenFromFile
from DIRAC.ConfigurationSystem.Client.Helpers import Registry
from DIRAC.FrameworkSystem.private.authorization.utils.Tokens import OAuth2Token

__RCSID__ = "$Id$"


def getTokenInfo(token=False):
  """ Return token info

      :param token: token location or token as dict

      :return: dict
  """
  # Discover token location
  if isinstance(token, dict):
    token = OAuth2Token(token)
  else:
    tokenLocation = token if isinstance(token, six.string_types) else Locations.getTokenLocation()
    if not tokenLocation:
      return S_ERROR("Cannot find token location.")
    result = readTokenFromFile()
    if not result['OK']:
      return result
    token = OAuth2Token(result['Value'])

  payload = _jwt.decode(token['access_token'], options=dict(verify_signature=False))
  result = Registry.getUsernameForDN('/O=DIRAC/CN=%s' % payload['sub'])
  if not result['OK']:
    return result
  payload['username'] = result['Value']
  if payload.get('group'):
    payload['properties'] = Registry.getPropertiesForGroup(payload['group'])
  return S_OK(payload)


def formatTokenInfoAsString(infoDict):
  """ Convert a token infoDict into a string
  """
  contentList = []
  contentList.append('subject: %s' % infoDict['sub'])
  contentList.append('issuer: %s' % infoDict['iss'])
  contentList.append('timeleft: %s' % int((int(infoDict['exp']) - time.time()) / 3600))
  contentList.append('username: %s' % infoDict['username'])
  if infoDict.get('group'):
    contentList.append('DIRAC group: %s' % infoDict['group'])
  if infoDict.get('properties'):
    contentList.append('groupProperties: %s' % infoDict['properties'])
  return "\n".join(contentList)
