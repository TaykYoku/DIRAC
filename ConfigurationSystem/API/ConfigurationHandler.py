""" HTTP API of the DIRAC configuration data, rewrite from the RESTDIRAC project
"""
import re
import json

from tornado import web, gen
from tornado.template import Template

from DIRAC import S_OK, S_ERROR, gConfig, gLogger
from DIRAC.ConfigurationSystem.Client.Helpers import Resources, Registry
from DIRAC.ConfigurationSystem.Client.ConfigurationData import gConfigurationData
from DIRAC.FrameworkSystem.Client.ProxyManagerClient import gProxyManager

from DIRAC.Core.Web.WebHandler import WebHandler, asyncGen, WErr
from DIRAC.Core.Tornado.Server.TornadoREST import TornadoREST


__RCSID__ = "$Id$"


class ConfigurationHandler(TornadoREST):#WebHandler):
  AUTH_PROPS = "all"
  LOCATION = "/DIRAC/"
  METHOD_PREFIX = 'web_'

  path_conf = ['([a-z]+)']
  @asyncGen
  def web_conf(self, key):
    """ REST endpoint for configuration system:

        **GET** /conf/<key>?<options> -- get configuration information

          Options:
            * *path* -- path in the configuration structure, by default it's "/". 
            * *version* -- the configuration version of the requester, if *version* is newer
                           than the one present on the server, an empty result will be returned 
        
          Response:
            +-----------+---------------------------------------+------------------------+
            | *key*     | Description                           | Type                   |
            +-----------+---------------------------------------+------------------------+
            | dump      | Current CFG()                         | encoded in json format |
            +-----------+---------------------------------------+------------------------+
            | option    | Option value                          | text                   |
            +-----------+---------------------------------------+------------------------+
            | options   | Options list in a section             | encoded in json format |
            +-----------+---------------------------------------+------------------------+
            | dict      | Options with values in a section      | encoded in json format |
            +-----------+---------------------------------------+------------------------+
            | sections  | Sections list in a section            | text                   |
            +-----------+---------------------------------------+------------------------+
    """
    self.log.notice('Request configuration information')
    # optns = self.overpath.strip('/').split('/')
    # path = self.args.get('path', '/')
    # if not optns or len(optns) > 1:
    #   raise WErr(404, "You forgot to set attribute.")
    path = self.get_argument('path', '/')

    result = S_ERROR('%s request unsuported' % key)
    version = self.get_argument('version', None)
    if version and (version or '0') >= gConfigurationData.getVersion():
      self.finish()
    if key == 'dump':
      # remoteCFG = yield self.threadTask(gConfigurationData.getRemoteCFG)
      result = gConfigurationData.getRemoteCFG()
      result['Value'] = str(remoteCFG)
    elif key == 'option':
      # result = yield self.threadTask(gConfig.getOption, path)
      result = gConfig.getOption(path)
    elif key == 'dict':
      # result = yield self.threadTask(gConfig.getOptionsDict, path)
      result = gConfig.getOptionsDict(path)
    elif key == 'options':
      # result = yield self.threadTask(gConfig.getOptions, path)
      result = gConfig.getOptions(path)
    elif key == 'sections':
      # result = yield self.threadTask(gConfig.getSections, path)
      result = gConfig.getSections(path)
    elif key == 'getGroupsStatusByUsername':
      # result = yield self.threadTask(gProxyManager.getGroupsStatusByUsername, **self.get_arguments)
      result = gProxyManager.getgetGroupsStatusByUsername(**self.get_arguments)
    elif any([key == m and re.match('^[a-z][A-z]+', m) for m in dir(Registry)]) and self.isRegisteredUser():
      # result = yield self.threadTask(getattr(Registry, key), **self.get_arguments)
      method = getattr(Registry, key)
      result = method(**self.get_arguments)
    else:
      raise WErr(500, '%s request unsuported' % key)
      # result = yield self.threadTask(getattr(Registry, key), **self.args)

    if not result['OK']:
      raise WErr(404, result['Message'])
    self.finishJEncode(result['Value'])

  @asyncGen
  def post(self):
    """ Post method
    """
    pass
