"""
TornadoServer create a web server and load services.
It may work better with TornadoClient but as it accepts HTTPS you can create your own client
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

__RCSID__ = "$Id$"

import time
import datetime
import os

import M2Crypto

import tornado.iostream
tornado.iostream.SSLIOStream.configure(
    'tornado_m2crypto.m2iostream.M2IOStream')  # pylint: disable=wrong-import-position

from tornado.httpserver import HTTPServer
from tornado.web import Application as _Application, url
from tornado.ioloop import IOLoop
import tornado.ioloop

import DIRAC
from DIRAC import gConfig, gLogger
from DIRAC.Core.Security import Locations
from DIRAC.Core.Utilities import MemStat
from DIRAC.Core.Tornado.Server.HandlerManager import HandlerManager
from DIRAC.ConfigurationSystem.Client import PathFinder
from DIRAC.FrameworkSystem.Client.MonitoringClient import MonitoringClient

## FROM WEB
import sys
import signal
import tornado.process
import tornado.autoreload

from diraccfg import CFG

from DIRAC.ConfigurationSystem.Client.Helpers import CSGlobals
from DIRAC.Core.Web.HandlerMgr import HandlerMgr
from DIRAC.Core.Web.TemplateLoader import TemplateLoader
from DIRAC.Core.Web.SessionData import SessionData
from DIRAC.Core.Web import Conf
from DIRAC.FrameworkSystem.private.authorization.utils.Sessions import SessionManager

class Application(_Application, SessionManager):
  def __init__(self, *args, **kwargs):
    _Application.__init__(self, *args, **kwargs)
    SessionManager.__init__(self)
##

sLog = gLogger.getSubLogger(__name__)


class TornadoServer(object):
  """
    Tornado webserver

    Initialize and run an HTTPS Server for DIRAC services.
    By default it load all https services defined in the CS,
    but you can also give an explicit list.

    The listening port is either:

    * Given as parameter
    * Loaded from the CS ``/Systems/Tornado/<instance>/Port``
    * Default to 8443


    Example 1: Easy way to start tornado::

      # Initialize server and load services
      serverToLaunch = TornadoServer()

      # Start listening when ready
      serverToLaunch.startTornado()

    Example 2:We want to debug service1 and service2 only, and use another port for that ::

      services = ['component/service1:port1', 'component/service2']
      endpoints = ['component/endpoint1:port1', 'component/endpoint2']
      serverToLaunch = TornadoServer(services=services, endpoints=endpoints, port=1234)
      serverToLaunch.startTornado()

  """

  def __init__(self, services=None, endpoints=None, port=None, balancer=None, processes=None):
    """ C'r

        :param list services: (default None) List of service handlers to load.
            If ``None``, loads all described in the CS
        :param list endpoints: (default None) List of endpoint handlers to load.
            If ``None``, loads all described in the CS
        :param int port: Port to listen to.
            If ``None``, the port is resolved following the logic described in the class documentation
        :param str balancer: if need to use balancer, e.g.:: `nginx`
        :param int processes: number of processes
    """
    self.__balancer = balancer
    self.__processes = processes or 0
    self.__portRoutes = {}

    if port is None:
      port = gConfig.getValue("/Systems/Tornado/%s/Port" % PathFinder.getSystemInstance('Tornado'), 8443)

    if services and not isinstance(services, list):
      services = [services]

    # URLs for services.
    # Contains Tornado :py:class:`tornado.web.url` object
    self.urls = []
    # Other infos
    self.port = port
    self.handlerManager = HandlerManager(services, endpoints)

    # Monitoring attributes

    self._monitor = MonitoringClient()
    # temp value for computation, used by the monitoring
    self.__report = None
    # Last update time stamp
    self.__monitorLastStatsUpdate = None
    self.__monitoringLoopDelay = 60  # In secs

    # If services are defined, load only these ones (useful for debug purpose or specific services)
    retVal = self.handlerManager.loadServicesHandlers()
    if not retVal['OK']:
      sLog.error(retVal['Message'])
      raise ImportError("Some services can't be loaded, check the service names and configuration.")

    retVal = self.handlerManager.loadEndpointsHandlers()
    if not retVal['OK']:
      sLog.error(retVal['Message'])
      raise ImportError("Some endpoints can't be loaded, check the endpoint names and configuration.")

    # if no service list is given, load services from configuration
    handlerDict = self.handlerManager.getHandlersDict()
    for _url, data in handlerDict.items():
      handler, _port = data
      tURL = url(_url, handler)
      self.urls.append(tURL)
      port = _port or self.port
      if port not in self.__portRoutes:
        self.__portRoutes[port] = {'URLs': [], 'settings': {}}
      if tURL not in self.__portRoutes[port]['URLs']:
        self.__portRoutes[port]['URLs'].append(tURL)
  
  def loadWeb(self, name=None):
    from DIRAC.Core.Web.HandlerMgr import HandlerMgr

    self.__handlerMgr = HandlerMgr('WebApp.handler', Conf.rootURL())

    # Load required CFG files
    if not self._loadDefaultWebCFG():
      # if we have a web.cfg under etc directory we use it, otherwise
      # we use the configuration file defined by the developer
      self._loadWebAppCFGFiles()

    # Calculating routes
    result = self.__handlerMgr.getRoutes()
    if not result['OK']:
      return result
    routes = result['Value']
    port = Conf.HTTPPort()
    # Initialize the session data
    SessionData.setHandlers(self.__handlerMgr.getHandlers()['Value'])
    # Create the app
    tLoader = TemplateLoader(self.__handlerMgr.getPaths("template"))

    if port not in self.__portRoutes:
      self.__portRoutes[port] = {'URLs': [], 'settings': {}}
    self.__portRoutes[port]['settings'] = dict(debug=Conf.devMode(),
                                               template_loader=tLoader,
                                               cookie_secret=str(Conf.cookieSecret()))
    for _url in routes:
      if not isinstance(_url, url):
        _url = url(_url)
      if _url not in self.__portRoutes[port]['URLs']:
        self.__portRoutes[port]['URLs'].append(_url)

  def stopChildProcesses(self, sig, frame):
    """
    It is used to properly stop tornado when more than one process is used.
    In principle this is doing the job of runsv....

    :param int sig: the signal sent to the process
    :param object frame: execution frame which contains the child processes
    """
    # tornado.ioloop.IOLoop.instance().add_timeout(time.time()+5, sys.exit)
    for child in frame.f_locals.get('children', []):
      gLogger.info("Stopping child processes: %d" % child)
      os.kill(child, signal.SIGTERM)
    # tornado.ioloop.IOLoop.instance().stop()
    # gLogger.info('exit success')
    sys.exit(0)

  def startTornado(self):
    """
      Starts the tornado server when ready.
      This method never returns.
    """

    # If there is no services loaded:
    if not self.__portRoutes:
      raise ImportError("There is no services loaded, please check your configuration")

    sLog.debug("Starting Tornado")

    ### NGINX ###
    Conf.generateRevokedCertsFile()  # it is used by nginx....
    # when NGINX is used then the Conf.HTTPS return False, it means tornado
    # does not have to be configured using 443 port
    Conf.generateCAFile()  # if we use Nginx we have to generate the cas as well...
    #############

    certs = Locations.getHostCertificateAndKeyLocation()
    if certs is False:
      sLog.fatal("Host certificates not found ! Can't start the Server")
      raise ImportError("Unable to load certificates")
    ca = Locations.getCAsLocation()
    ssl_options = {
        'certfile': certs[0],
        'keyfile': certs[1],
        'cert_reqs': M2Crypto.SSL.verify_peer,
        'ca_certs': ca,
        'sslDebug': False,  # Set to true if you want to see the TLS debug messages
    }

    self._initMonitoring()
    self.__monitorLastStatsUpdate = time.time()
    self.__report = self.__startReportToMonitoringLoop()

    # Configure server.
    settings = dict(debug=False, compress_response=True,
                    # Use gLogger instead tornado log
                    log_function=self._logRequest, autoreload=self.__processes < 2)

    ############
    # please do no move this lines. The lines must be before the fork_processes
    signal.signal(signal.SIGTERM, self.stopChildProcesses)
    signal.signal(signal.SIGINT, self.stopChildProcesses)

    # Check processes if we're under a load balancert
    if self.__balancer and self.__processes not in (0, 1):
      tornado.process.fork_processes(self.__processes, max_restarts=0)
      settings['debug'] = False
    #############

    # Starting monitoring, IOLoop waiting time in ms, __monitoringLoopDelay is defined in seconds
    tornado.ioloop.PeriodicCallback(self.__reportToMonitoring, self.__monitoringLoopDelay * 1000).start()

    for port, app in self.__portRoutes.items():
      sLog.debug(" - %s" % "\n - ".join(["%s = %s" % (k, ssl_options[k]) for k in ssl_options]))

      settings.update(app['settings'])

      # Start server
      router = Application(app['URLs'], settings)
      server = HTTPServer(router, ssl_options=ssl_options, decompress_request=True, xheaders=True)
      try:
        server.listen(port)
      except Exception as e:  # pylint: disable=broad-except
        sLog.exception("Exception starting HTTPServer", e)
        raise
      if settings['debug']:
        sLog.info("Configuring in developer mode...")
      sLog.always("Listening on https://127.0.0.1:%s" % port)
      for service in app['URLs']:
        sLog.debug("Available service: %s" % service)

    tornado.autoreload.add_reload_hook(lambda: sLog.verbose("\n == Reloading web app...\n"))
    IOLoop.current().start()

  def _initMonitoring(self):
    """
      Initialize the monitoring
    """

    self._monitor.setComponentType(MonitoringClient.COMPONENT_TORNADO)
    self._monitor.initialize()
    self._monitor.setComponentName('Tornado')

    self._monitor.registerActivity('CPU', "CPU Usage", 'Framework', "CPU,%", MonitoringClient.OP_MEAN, 600)
    self._monitor.registerActivity('MEM', "Memory Usage", 'Framework', 'Memory,MB', MonitoringClient.OP_MEAN, 600)

    self._monitor.setComponentExtraParam('DIRACVersion', DIRAC.version)
    self._monitor.setComponentExtraParam('platform', DIRAC.getPlatform())
    self._monitor.setComponentExtraParam('startTime', datetime.datetime.utcnow())

  def __reportToMonitoring(self):
    """
      Periodically report to the monitoring of the CPU and MEM
    """

    # Calculate CPU usage by comparing realtime and cpu time since last report
    self.__endReportToMonitoringLoop(*self.__report)

    # Save memory usage and save realtime/CPU time for next call
    self.__report = self.__startReportToMonitoringLoop()

  def __startReportToMonitoringLoop(self):
    """
      Snapshot of resources to be taken at the beginning
      of a monitoring cycle.
      Also sends memory snapshot to the monitoring.

      This is basically copy/paste of Service.py

      :returns: tuple (<time.time(), cpuTime )

    """
    now = time.time()  # Used to calulate a delta
    stats = os.times()
    cpuTime = stats[0] + stats[2]
    if now - self.__monitorLastStatsUpdate < 0:
      return (now, cpuTime)
    # Send CPU consumption mark
    self.__monitorLastStatsUpdate = now
    # Send Memory consumption mark
    membytes = MemStat.VmB('VmRSS:')
    if membytes:
      mem = membytes / (1024. * 1024.)
      self._monitor.addMark('MEM', mem)
    return (now, cpuTime)

  def __endReportToMonitoringLoop(self, initialWallTime, initialCPUTime):
    """
      Snapshot of resources to be taken at the end
      of a monitoring cycle.

      This is basically copy/paste of Service.py

      Determines CPU usage by comparing walltime and cputime and send it to monitor
    """
    wallTime = time.time() - initialWallTime
    stats = os.times()
    cpuTime = stats[0] + stats[2] - initialCPUTime
    percentage = cpuTime / wallTime * 100.
    if percentage > 0:
      self._monitor.addMark('CPU', percentage)

  def _logRequest(self, handler):
    """ This function will be called at the end of every request to log the result
        
        :param object handler: RequestHandler object
    """
    status = handler.get_status()
    if status < 400:
      logm = sLog.notice
    elif status < 500:
      logm = sLog.warn
    else:
      logm = sLog.error
    request_time = 1000.0 * handler.request.request_time()
    logm("%d %s %.2fms" % (status, handler._request_summary(), request_time))

  #### LOAD WEB CFG ####
  def _loadWebAppCFGFiles(self):
    """
    Load WebApp/web.cfg definitions
    """
    exts = []
    for ext in CSGlobals.getCSExtensions():
      if ext == "DIRAC":
        continue
      if ext[-5:] != "DIRAC":
        ext = "%sDIRAC" % ext
      if ext != "WebAppDIRAC":
        exts.append(ext)
    exts.append("DIRAC")
    exts.append("WebAppDIRAC")
    webCFG = CFG()
    for modName in reversed(exts):
      try:
        modPath = imp.find_module(modName)[1]
      except ImportError:
        continue
      gLogger.verbose("Found module %s at %s" % (modName, modPath))
      cfgPath = os.path.join(modPath, "WebApp", "web.cfg")
      if not os.path.isfile(cfgPath):
        gLogger.verbose("Inexistant %s" % cfgPath)
        continue
      try:
        modCFG = CFG().loadFromFile(cfgPath)
      except Exception as excp:
        gLogger.error("Could not load %s: %s" % (cfgPath, excp))
        continue
      gLogger.verbose("Loaded %s" % cfgPath)
      expl = [Conf.BASECS]
      while len(expl):
        current = expl.pop(0)
        if not modCFG.isSection(current):
          continue
        if modCFG.getOption("%s/AbsoluteDefinition" % current, False):
          gLogger.verbose("%s:%s is an absolute definition" % (modName, current))
          try:
            webCFG.deleteKey(current)
          except BaseException:
            pass
          modCFG.deleteKey("%s/AbsoluteDefinition" % current)
        else:
          for sec in modCFG[current].listSections():
            expl.append("%s/%s" % (current, sec))
      # Add the modCFG
      webCFG = webCFG.mergeWith(modCFG)
    gConfig.loadCFG(webCFG)

  def _loadDefaultWebCFG(self):
    """ This method reloads the web.cfg file from etc/web.cfg

        :return: bool
    """
    modCFG = None
    cfgPath = os.path.join(DIRAC.rootPath, 'etc', 'web.cfg')
    isLoaded = True
    if not os.path.isfile(cfgPath):
      isLoaded = False
    else:
      try:
        modCFG = CFG().loadFromFile(cfgPath)
      except Exception as excp:
        isLoaded = False
        gLogger.error("Could not load %s: %s" % (cfgPath, excp))

    if modCFG:
      if modCFG.isSection("/Website"):
        gLogger.warn("%s configuration file is not correct. It is used by the old portal!" % (cfgPath))
        isLoaded = False
      else:
        gConfig.loadCFG(modCFG)
    else:
      isLoaded = False

    return isLoaded
