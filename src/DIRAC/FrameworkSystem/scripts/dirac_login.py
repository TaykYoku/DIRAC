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
import stat
import glob
import time
import pickle
import datetime

import DIRAC
from DIRAC import gConfig, gLogger, S_OK, S_ERROR
from DIRAC.Core.Base import Script
from DIRAC.Core.Security import X509Chain, ProxyInfo, Properties, VOMS  # pylint: disable=import-error
from DIRAC.Core.Utilities.DIRACScript import DIRACScript
from DIRAC.ConfigurationSystem.Client.Helpers import Registry
from DIRAC.FrameworkSystem.Client import ProxyGeneration, ProxyUpload
from DIRAC.FrameworkSystem.Client.BundleDeliveryClient import BundleDeliveryClient
from DIRAC.ConfigurationSystem.Client.Utilities import getAuthorisationServerMetadata

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
        "g",
        "group",
        "set DIRAC group",
        self.setGroup)
    Script.registerSwitch(
        "O",
        "provider",
        "set identity provider",
        self.setProvider)
    Script.registerSwitch(
        "T",
        "lifetime",
        "set proxy lifetime",
        self.setLivetime)

  def doOAuthMagic(self):
    """ Magic method with tokens

        :return: S_OK()/S_ERROR()
    """
    import urllib3
    import threading
    import webbrowser
    import requests
    import json

    from DIRAC.Core.Utilities.JEncode import encode
    from DIRAC.Core.Security.TokenFile import readTokenFromFile, writeTokenDictToTokenFile
    from DIRAC.Core.Security.ProxyFile import writeToProxyFile
    from DIRAC.ConfigurationSystem.Client.Utilities import getProxyAPI
    from DIRAC.Resources.IdProvider.OAuth2IdProvider import OAuth2IdProvider
    from DIRAC.Resources.IdProvider.IdProviderFactory import IdProviderFactory
    # from DIRAC.FrameworkSystem.Client.TokenManagerClient import gTokenManager

    token = None
    result = readTokenFromFile()
    if not result['OK']:
      gLogger.warn(result['Message'])
    else:
      token = result['Value']
    
    args = Script.getPositionalArgs()
    if args:
      issuer = args[0]
    else:
      issuer = input("Enter DIRAC Authorisation server URL:")

    result = getAuthorisationServerMetadata(issuer)
    if not result['OK']:
      return result

    clientConfig = result['Value']
    clientConfig['client_id'] = 'DIRAC_CLI'
    clientConfig['redirect_uri'] = 'https://diracclient'
    clientConfig['ProviderName'] = 'DIRAC_CLI'

    idpObj = OAuth2IdProvider(**clientConfig)
    
    # result = IdProviderFactory().getIdProvider(self.provider, token=token)
    # if not result['OK']:
    #   return result
    # idpObj = result['Value']

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Submit Device authorisation flow
    # Get IdP
    result = idpObj.authorization(scopes=self.group and 'g:%s' % self.group)
    #   if result['OK']:
    #     result = idpObj.exchangeGroup(self.group)
    # else:
    #   result = idpObj.authorization(self.group)
    if not result['OK']:
      return result
    
    result = writeTokenDictToTokenFile(idpObj.token)
    if not result['OK']:
      return result
    gLogger.notice('Token is saved.')
    
    # # Check user tokens
    # result = gTokenManager.delegateUserToken()
    # if not result['OK']:
    #   return result

    if not self.proxy:
      return S_OK()

    r = idpObj.get('%s?lifetime=%s' % (getProxyAPI(), self.lifetime))
    r.raise_for_status()
    proxy = r.text
    if not proxy:
      return S_ERROR("Something went wrong, the proxy is empty.")

    gLogger.notice('Saving proxy.. to %s..' % self.proxyLoc)
    result = writeToProxyFile(proxy.encode("UTF-8"), self.proxyLoc)
    gLogger.notice('Proxy is saved to %s.' % self.proxyLoc)

    result = Script.enableCS()
    if not result['OK']:
      return S_ERROR("Cannot contact CS to get user list")
    threading.Thread(target=self.checkCAs).start()
    gConfig.forceRefresh(fromMaster=True)
    return S_OK(self.proxyLoc)


@DIRACScript()
def main():
  piParams = Params()
  piParams.registerCLISwitches()

  Script.disableCS()
  Script.parseCommandLine(ignoreErrors=True)
  DIRAC.gConfig.setOptionValue("/DIRAC/Security/UseServerCertificate", "False")

  gLogger.info(gConfig.getConfigurationTree())
  resultDoMagic = piParams.doOAuthMagic()
  if not resultDoMagic['OK']:
    gLogger.fatal(resultDoMagic['Message'])
    sys.exit(1)

  sys.exit(0)


if __name__ == "__main__":
  main()
