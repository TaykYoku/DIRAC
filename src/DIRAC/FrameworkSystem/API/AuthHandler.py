""" This handler basically provides a REST interface to interact with the OAuth 2 authentication server
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import json
import pprint
import requests

from dominate import document, tags as dom
from tornado.template import Template

from authlib.jose import jwk, jwt

from DIRAC import S_OK, S_ERROR
from DIRAC.Core.Tornado.Server.TornadoREST import TornadoREST
from DIRAC.ConfigurationSystem.Client.Helpers import Registry
from DIRAC.ConfigurationSystem.Client.Helpers.Resources import getProviderInfo
from DIRAC.FrameworkSystem.Client.ProxyManagerClient import gProxyManager
from DIRAC.Resources.IdProvider.IdProviderFactory import IdProviderFactory

__RCSID__ = "$Id$"


class AuthHandler(TornadoREST):

  SYSTEM = 'Framework'
  LOCATION = "/DIRAC/auth"

  @classmethod
  def initializeHandler(cls, serviceInfo):
    """ This method is called only one time, at the first request

        :param dict ServiceInfoDict: infos about services
    """
    cls.idps = IdProviderFactory()

  def web_device(self):
    """ The device authorization endpoint can be used to request device and user codes.
        This endpoint is used to start the device flow authorization process and user code verification.

    """
    if self.request.method == 'POST':
      group = self.get_argument('group', None)
      if group:
        provider = Registry.getIdPForGroup(group)
        if not provider:
          return S_ERROR('No provider found for %s' % group)
        result = getProviderInfo(provider)
        if not result['OK']:
          return result
        
        result = self.idps.getIdProvider(provider)
        if result['OK']:
          idPObj = result['Value']
          result = idPObj.submitDeviceCodeAuthorizationFlow(group)
        if not result['OK']:
          return result
        return result['Value']
