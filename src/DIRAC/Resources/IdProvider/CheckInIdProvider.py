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
