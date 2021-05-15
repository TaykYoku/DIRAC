#!/usr/bin/env python
########################################################################
# File :    dirac-proxy-init.py
# Author :  Adrian Casajus
########################################################################
"""
Creating a proxy.

Example:
  $ dirac-proxy-init -g dirac_user -t --rfc
  Enter Certificate password:
"""
from __future__ import division
from __future__ import absolute_import
from __future__ import print_function

import os
import sys
import urllib3
import requests
import threading

import DIRAC
from DIRAC import gLogger, S_OK, S_ERROR
from DIRAC.Core.Base import Script
from DIRAC.Core.Utilities.DIRACScript import DIRACScript
from DIRAC.Core.Security.TokenFile import readTokenFromFile, writeTokenDictToTokenFile
from DIRAC.Core.Security.ProxyFile import writeToProxyFile
from DIRAC.Resources.IdProvider.OAuth2IdProvider import OAuth2IdProvider
from DIRAC.FrameworkSystem.Client.BundleDeliveryClient import BundleDeliveryClient
from DIRAC.ConfigurationSystem.Client.Utilities import getAuthorisationServerMetadata, getDIRACClient

__RCSID__ = "$Id$"


class Params(object):

  def __init__(self):
    self.proxy = False
    self.group = None
    self.lifetime = None
    self.provider = 'DIRAC_AS'
    self.issuer = None
    self.proxyLoc = '/tmp/x509up_u%s' % os.getuid()

  def returnProxy(self, _arg):
    """ Set email

        :return: S_OK()
    """
    self.proxy = True
    return S_OK()
  
  def setGroup(self, arg):
    """ Set email

        :param str arg: group

        :return: S_OK()
    """
    self.group = arg
    return S_OK()
  
  def setProvider(self, arg):
    """ Set email

        :param str arg: provider

        :return: S_OK()
    """
    self.provider = arg
    return S_OK()
  
  def setIssuer(self, arg):
    """ Set email

        :param str arg: issuer

        :return: S_OK()
    """
    self.issuer = arg
    return S_OK()
  
  def setLivetime(self, arg):
    """ Set email

        :param str arg: lifetime

        :return: S_OK()
    """
    self.lifetime = arg
    return S_OK()

  def registerCLISwitches(self):
    """ Register CLI switches """
    Script.registerSwitch(
        "P",
        "proxy",
        "return with an access token also a proxy certificate with DIRAC group extension",
        self.returnProxy)
    Script.registerSwitch(
        "g:",
        "group=",
        "set DIRAC group",
        self.setGroup)
    Script.registerSwitch(
        "O",
        "provider",
        "set identity provider",
        self.setProvider)
    Script.registerSwitch(
        "I",
        "issuer",
        "set issuer",
        self.setIssuer)
    Script.registerSwitch(
        "T",
        "lifetime",
        "set proxy lifetime",
        self.setLivetime)

  def doOAuthMagic(self):
    """ Magic method with tokens

        :return: S_OK()/S_ERROR()
    """
    # token = None
    # result = readTokenFromFile()
    # if not result['OK']:
    #   gLogger.warn(result['Message'])
    # else:
    #   token = result['Value']

    result = getDIRACClient()
    if not result['OK']:
      return result
    clientConfig = result['Value']
    result = getAuthorisationServerMetadata(self.issuer)
    if not result['OK']:
      return result
    clientConfig.update(result['Value'])
    clientConfig['ProviderName'] = 'DIRAC_CLI'

    idpObj = OAuth2IdProvider(**clientConfig)
    if self.group:
      idpObj.scope += '+g:%s' % self.group
    if self.proxy:
      idpObj.scope += '+proxy'
    # idpObj.scope += 'origin_token'
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Submit Device authorisation flow
    # Get IdP
    result = idpObj.authorization()
    if not result['OK']:
      return result
    
    if self.proxy:
      result = writeToProxyFile(idpObj.token['proxy'].encode("UTF-8"), self.proxyLoc)
      if not result['OK']:
        return result
      gLogger.notice('Proxy is saved to %s.' % self.proxyLoc)
    else:
      result = writeTokenDictToTokenFile(idpObj.token)
      if not result['OK']:
        return result
      gLogger.notice('Token is saved in %s.' % result['Value'])

    result = Script.enableCS()
    if not result['OK']:
      gLogger.debug(result['Message'])
      return S_ERROR("Cannot contact CS to get user list")
    DIRAC.gConfig.forceRefresh()

    return S_OK(self.proxyLoc)


@DIRACScript()
def main():
  piParams = Params()
  piParams.registerCLISwitches()

  Script.disableCS()
  Script.parseCommandLine(ignoreErrors=True)
  DIRAC.gConfig.setOptionValue("/DIRAC/Security/UseServerCertificate", "False")

  resultDoMagic = piParams.doOAuthMagic()
  if not resultDoMagic['OK']:
    gLogger.fatal(resultDoMagic['Message'])
    sys.exit(1)

  sys.exit(0)


if __name__ == "__main__":
  main()
