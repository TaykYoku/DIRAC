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
from DIRAC.Resources.IdProvider.OAuth2IdProvider import OAuth2IdProvider, claimParser
from DIRAC.ConfigurationSystem.Client.Helpers.Registry import getVOMSRoleGroupMapping, getVOForGroup, getGroupOption, getDNForID

__RCSID__ = "$Id$"


class CheckInIdProvider(OAuth2IdProvider):

  # urn:mace:egi.eu:group:registry:training.egi.eu:role=member#aai.egi.eu'
  NAMESPACE = 'urn:mace:egi.eu:group:registry'
  SIGN = '#aai.egi.eu'
  PARAM_SCOPE = 'eduperson_entitlement?value='

  def getGroupScopes(self, group):
    """ Get group scopes

        :param str group: DIRAC group

        :return: list
    """
    return S_OK(['eduperson_entitlement?value=urn:mace:egi.eu:group:checkin-integration:role=member#aai.egi.eu'])

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
        'eduperson_entitlement': '^(?P<NAMESPACE>[A-z,.,_,-,:]+):(group:registry|group):(?P<VO>[A-z,.,_,-]+):role=(?P<VORole>[A-z,.,_,-]+)[:#].*'
    }
    print('==> getUserProfile 1')
    pprint.pprint(claimDict)
    if 'eduperson_entitlement' not in claimDict:
      print('==> getUserProfile 2')
      claimDict = self.getUserProfile()
    pprint.pprint(claimDict)
    resDict = claimParser(claimDict, attributes)
    print('++..')
    pprint.pprint(resDict)
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
      pprint.pprint(result)
      if result['OK']:
        for role in voData['VORoles']:
          groups = result['Value']['VOMSDIRAC'].get('/%s' % role)
          if groups:
            credDict['DIRACGroups'] = list(set(credDict['DIRACGroups'] + groups))
    if credDict['DIRACGroups']:
      credDict['group'] = credDict['DIRACGroups'][0]
    return credDict
