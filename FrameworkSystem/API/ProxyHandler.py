""" Handler to serve the DIRAC proxy data
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import re
import time
import base64

from tornado import web, gen
from tornado.template import Template

from DIRAC import S_OK, S_ERROR, gConfig, gLogger
# from DIRAC.Core.Web.WebHandler import WebHandler, asyncGen, WErr
from DIRAC.FrameworkSystem.Client.ProxyManagerClient import ProxyManagerClient
from DIRAC.ConfigurationSystem.Client.Helpers.Registry import getDNForUsernameInGroup
from DIRAC.Core.Tornado.Server.TornadoREST import TornadoREST

__RCSID__ = "$Id$"


class ProxyHandler(TornadoREST):
  AUTH_PROPS = "authenticated"
  LOCATION = "/"

  METHOD_PREFIX = "web_"

  @classmethod
  def initializeHandler(cls, serviceInfo):
    """
      This may be overwritten when you write a DIRAC service handler
      And it must be a class method. This method is called only one time,
      at the first request

      :param dict ServiceInfoDict: infos about services, it contains
                                    'serviceName', 'serviceSectionPath',
                                    'csPaths' and 'URL'
    """
    pass
  
  def initializeRequest(self):
    self.proxyCli = ProxyManagerClient(delegatedGroup=self.getUserGroup(),
                                       delegatedID=self.getID(), delegatedDN=self.getDN())

  path_proxy = ['([a-z]*)[\/]?([a-z]*)']
  def web_proxy(self, user=None, group=None):
    """ REST endpoints to user proxy management

        **GET** /proxy?<options> -- retrieve personal proxy
        
          Options:
            * *voms* -- to get user proxy with VOMS extension(optional)
            * *lifetime* -- requested proxy live time(optional)
          
          Response is a proxy certificate as text

        **GET** /proxy/<user>/<group>?<options> -- retrieve proxy  
          * *user* -- user name
          * *group* -- group name
        
          Options:
            * *voms* -- to get user proxy with VOMS extension(optional)
            * *lifetime* -- requested proxy live time(optional)
          
          Response is a proxy certificate as text

        **GET** /proxy/metadata?<options> -- retrieve proxy metadata..
    """
    voms = self.get_argument('voms', None)
    try:
      proxyLifeTime = int(self.get_argument('lifetime', 3600 * 12))
    except Exception:
      return S_ERROR('Cannot read "lifetime" argument.') 

    # GET
    if self.request.method == 'GET':
      # # Return content of Proxy DB
      # if 'metadata' in optns:
      #   pass

      # Return personal proxy
      if not user and not group: #self.overpath:
        result = self.proxyCli.downloadPersonalProxy(self.getUserName(), self.getUserGroup(),
                                                     requiredTimeLeft=proxyLifeTime, voms=voms)
        if result['OK']:
          self.log.notice('Proxy was created.')
          result = result['Value'].dumpAllToString()
        return result
        # if not result['OK']:
        #   return result
        # self.finishJEncode(result['Value'])

      # Return proxy
      elif user and group:
        # user = optns[0]
        # group = optns[1]

        # Get proxy to string
        result = getDNForUsernameInGroup(user, group)
        if not result['OK'] or not result.get('Value'):
          return S_ERROR('%s@%s has no registred DN: %s' % (user, group, result.get('Message') or ""))

        if voms:
          result = self.proxyCli.downloadVOMSProxy(user, group, requiredTimeLeft=proxyLifeTime)
        else:
          result = self.proxyCli.downloadProxy(user, group, requiredTimeLeft=proxyLifeTime)
        if result['OK']:
          self.log.notice('Proxy was created.')
          result = result['Value'].dumpAllToString()
        return result
        # if not result['OK']:
        #   return result
        # self.finishJEncode(result['Value'])

      else:
        return S_ERROR("Wrone way")
