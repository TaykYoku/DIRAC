""" IdProvider based on OAuth2 protocol
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import six
import re
import pprint
import time
import requests
from authlib.oauth2.rfc6749.util import scope_to_list, list_to_scope
from authlib.oauth2.rfc8628 import DEVICE_CODE_GRANT_TYPE

from DIRAC import S_ERROR, S_OK
from DIRAC.Resources.IdProvider.OAuth2IdProvider import OAuth2IdProvider
from DIRAC.ConfigurationSystem.Client.Helpers.Registry import getVOMSRoleGroupMapping, getVOForGroup, getGroupOption, getDNForID

__RCSID__ = "$Id$"


def claimParser(claimDict, attributes):
  """ Parse claims to write it as DIRAC profile

      :param dict claimDict: claims
      :param dict attributes: contain claim and regex to parse it
      :param dict profile: to fill parsed data

      :return: dict
  """
  profile = {}
  result = None
  for claim, reg in attributes.items():
    if claim not in claimDict:
      continue
    profile[claim] = {}
    if isinstance(claimDict[claim], dict):
      result = claimParser(claimDict[claim], reg)
      if result:
        profile[claim] = result
    elif isinstance(claimDict[claim], six.string_types):
      result = re.compile(reg).match(claimDict[claim])
      if result:
        for k, v in result.groupdict().items():
          profile[claim][k] = v
    else:
      profile[claim] = []
      for claimItem in claimDict[claim]:
        if isinstance(reg, dict):
          result = claimParser(claimItem, reg)
          if result:
            profile[claim].append(result)
        else:
          result = re.compile(reg).match(claimItem)
          if result:
            profile[claim].append(result.groupdict())

  return profile


class CheckInIdProvider(OAuth2IdProvider):

  # urn:mace:egi.eu:group:registry:training.egi.eu:role=member#aai.egi.eu'
  NAMESPACE = 'urn:mace:egi.eu:group:registry'
  SIGN = '#aai.egi.eu'
  PARAM_SCOPE = 'eduperson_entitlement?value='

  # def getScopeForGroup(self, group):
  #   """
  #   """
  #   vo = getVOForGroup(group)
  #   result = getVOMSRoleGroupMapping(vo)
  #   if not result['OK']:
  #     return result
  #   role = result['Value']['DIRACVOMS'].get(group)
  #   if not role:
  #     return S_ERROR('%s group role is not found.' % group)
  #   role = role.strip('/')
  #   return S_OK('{scope}{namespace}:{vo}:role={role}{sign}'.format(
  #       scope=self.PARAM_SCOPE, namespace=self.NAMESPACE, vo=vo, role=role, sign=self.SIGN
  #   ))

  def researchScopeForGroup(self, group):
    """ Research group
    """
    pass

  def researchGroup(self, payload, token):
    """ Research group
    """
    if not payload.get('eduperson_unique_id') or not payload.get('eduperson_entitlement'):
      r = requests.get(self.metadata['userinfo_endpoint'], headers=dict(Authorization="Bearer %s" % token))
      r.raise_for_status()
      # payload = self.get(self.metadata['userinfo_endpoint'],
      #                    auth=dict(headers=dict(Authorization="Bearer %s" % token))).json()
      payload = r.json()
    credDict = self.parseEduperson(payload)
    credDict = self.userDiscover(credDict)
    credDict['provider'] = self.name
    return credDict

  def parseEduperson(self, claimDict):
    """ Parse eduperson claims

        :return: dict
    """
    credDict = {}
    attributes = {
        'eduperson_unique_id': '^(?P<ID>.*)',
        'eduperson_entitlement': '^(?P<NAMESPACE>[A-z,.,_,-,:]+):(group:registry|group):\
                                  (?P<VO>[A-z,.,_,-]+):role=(?P<VORole>[A-z,.,_,-]+)[:#].*'
    }
    if 'eduperson_entitlement' not in claimDict:
      claimDict = self.getUserProfile()
    resDict = claimParser(claimDict, attributes)
    if not resDict:
      return credDict
    credDict['ID'] = resDict['eduperson_unique_id']['ID']
    credDict['DN'] = self.convertIDToDN(credDict['ID'])
    credDict['VOs'] = {}
    for voDict in resDict['eduperson_entitlement']:
      if voDict['VO'] not in credDict['VOs']:
        credDict['VOs'][voDict['VO']] = {'VORoles': []}
      if voDict['VORole'] not in credDict['VOs'][voDict['VO']]['VORoles']:
        credDict['VOs'][voDict['VO']]['VORoles'].append(voDict['VORole'])
    return credDict

  def userDiscover(self, credDict):
    credDict['DIRACGroups'] = []
    for vo, voData in credDict.get('VOs', {}).items():
      result = getVOMSRoleGroupMapping(vo)
      if result['OK']:
        avilGroups = result['Value']['VOMSDIRAC']
        for role in voData['VORoles']:
          groups = result['Value']['VOMSDIRAC'].get('/%s' % role)
          if groups:
            credDict['DIRACGroups'] = list(set(credDict['DIRACGroups'] + groups))
    if credDict['DIRACGroups']:
      credDict['group'] = credDict['DIRACGroups'][0]
    return credDict

  def convertIDToDN(self, uid):
    """
    """
    result = getDNForID(uid)
    if result['OK']:
      return result['Value']
    return None
      