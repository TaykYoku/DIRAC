"""
  This module contains the necessary tools to discover and load
  the handlers for serving HTTPS
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

__RCSID__ = "$Id$"

from tornado.web import url as TornadoURL, RequestHandler

from DIRAC import gConfig, gLogger, S_ERROR, S_OK
from DIRAC.ConfigurationSystem.Client import PathFinder
from DIRAC.Core.Base.private.ModuleLoader import ModuleLoader
from DIRAC.Core.Utilities.ObjectLoader import ObjectLoader


def urlFinder(module):
  """
    Tries to guess the url from module name.
    The URL would be of the form ``/System/Component`` (e.g. ``DataManagement/FileCatalog``)
    We search something which looks like ``<...>.<component>System.<...>.<service>Handler``

    :param module: full module name (e.g. "DIRAC.something.something")

    :returns: the deduced URL or None
  """
  sections = module.split('.')
  for section in sections:
    # This condition is a bit long
    # We search something which look like <...>.<component>System.<...>.<service>Handler
    # If find we return /<component>/<service>
    if section.endswith("System") and sections[-1].endswith("Handler"):
      return "/".join(["", section[:-len("System")], sections[-1][:-len("Handler")]])


class HandlerManager(object):
  """
    This utility class allows to load the handlers, generate the appropriate route,
    and discover the handlers based on the CS.
    In order for a service to be considered as using HTTPS, it must have
    ``protocol = https`` as an option.

    Each of the Handler will have one associated route to it:

    * Directly specified as ``LOCATION`` in the handler module
    * automatically deduced from the module name, of the form
      ``System/Component`` (e.g. ``DataManagement/FileCatalog``)
  """

  def __init__(self, services=None, endpoints=None):
    """
      Initialization function, you can set autoDiscovery=False to prevent automatic
      discovery of handler. If disabled you can use loadHandlersByServiceName() to
      load your handlers or loadHandlerInHandlerManager()

      :param services: (default True) List of service handlers to load. If ``True``, loads all
      :type services: bool or list
      :param endpoints: (default False) List of endpoint handlers to load. If ``True``, loads all
      :type endpoints: bool or list
    """
    # list of services, e.g. ['Framework/Hello', 'Configuration/Server']
    if isinstance(services, string_types):
      services = [services]
    # list of endpoints, e.g. ['Framework/Hello', 'Configuration/Server'] 
    if isinstance(endpoints, string_types):
      endpoints = [endpoints]

    # list of services. If __services is ``True`` than list of services will dicover from CS
    self.__services = True if services is None else services if services else []
    # list of endpoints. If __endpoints is ``True`` than list of endpoints will dicover from CS
    self.__endpoints = [] if endpoints is None else endpoints if endpoints else []

    self.__handlers = {}
    self.__objectLoader = ObjectLoader()
    
    self.loader = None

  def __addHandler(self, handlerTuple, url=None):
    """
      Function which add handler to list of known handlers


      :param handlerTuple: (path, class)
    """
    # Check if handler not already loaded
    if not url or url not in self.__handlers:
      gLogger.debug("Find new handler %s" % (handlerTuple[0]))

      # If url is not given, try to discover it
      if url is None:
        # FIRST TRY: Url is hardcoded
        try:
          url = handlerTuple[1].LOCATION
        # SECOND TRY: URL can be deduced from path
        except AttributeError:
          gLogger.debug("No location defined for %s try to get it from path" % handlerTuple[0])
          url = urlFinder(handlerTuple[0])

      # We add "/" if missing at begin, e.g. we found "Framework/Service"
      # URL can't be relative in Tornado
      if url and not url.startswith('/'):
        url = "/%s" % url
      elif not url:
        gLogger.warn("URL not found for %s" % (handlerTuple[0]))
        return S_ERROR("URL not found for %s" % (handlerTuple[0]))

      # Finally add the URL to handlers
      if url not in self.__handlers:
        self.__handlers[url] = handlerTuple[1]
        gLogger.info("New handler: %s with URL %s" % (handlerTuple[0], url))
    else:
      gLogger.debug("Handler already loaded %s" % (handlerTuple[0]))
    return S_OK()

  def discoverHandlers(self, instance):
    """
      Force the discovery of URL, automatic call when we try to get handlers for the first time.
      You can disable the automatic call with autoDiscovery=False at initialization
    """
    urls = []
    gLogger.debug("Trying to auto-discover the %s handlers for Tornado" % instance)

    # Look in config
    diracSystems = gConfig.getSections('/Systems')
    if diracSystems['OK']:
      for system in diracSystems['Value']:
        try:
          sysInstance = PathFinder.getSystemInstance(system)
          result = gConfig.getSections('/Systems/%s/%s/%s' % (system, sysInstance, instance))
          if result['OK']:
            for inst in result['Value']:
              newInst = ("%s/%s" % (system, inst))

              if instance == 'Service':
                # We search in the CS all handlers which used HTTPS as protocol
                isHTTPS = gConfig.getValue('/Systems/%s/%s/Services/%s/Protocol' % (system, sysInstance, inst))
                if isHTTPS and isHTTPS.lower() == 'https':
                  urls.append(newInst)
              else:
                urls.append(newInst)
        # On systems sometime you have things not related to services...
        except RuntimeError:
          pass
    return urls

  def loadServicesHandlers(self):
    """
      Load a list of handler from list of service using DIRAC moduleLoader
      Use :py:class:`DIRAC.Core.Base.private.ModuleLoader`
    """
    if self.__services == True:
      self.__services = self.discoverHandlers(instance='Services')

    if self.__services:
      self.loader = ModuleLoader("Service", PathFinder.getServiceSection, RequestHandler, moduleSuffix="Handler")

      # Use DIRAC system to load: search in CS if path is given and if not defined
      # it search in place it should be (e.g. in DIRAC/FrameworkSystem/Service)

      load = self.loader.loadModules(self.__services)
      if not load['OK']:
        return load
      for module in self.loader.getModules().values():
        url = module['loadName']

        # URL can be like https://domain:port/service/name or just service/name
        # Here we just want the service name, for tornado
        serviceTuple = url.replace('https://', '').split('/')[-2:]
        url = "%s/%s" % (serviceTuple[0], serviceTuple[1])
        self.__addHandler((module['loadName'], module['classObj']), url)
    return S_OK()
  
  def loadEndpointsHandlers(self):
    """
      Load a list of handler from list of endpoints using DIRAC moduleLoader
      Use :py:class:`DIRAC.Core.Base.private.ModuleLoader`
    """
    if self.__endpoints == True:
      self.__endpoints = self.discoverHandlers(instance='APIs')
    
    if self.__endpoints:
      self.loader = ModuleLoader("API", PathFinder.getAPISection, RequestHandler, moduleSuffix="Handler")

      # Use DIRAC system to load: search in CS if path is given and if not defined
      # it search in place it should be (e.g. in DIRAC/FrameworkSystem/API)

      load = self.loader.loadModules(self.__endpoints)
      if not load['OK']:
        return load
      for module in self.loader.getModules().values():
        handler = module['classObj']
        if not handler.LOCATION:
          handler.LOCATION = urlFinder(module['loadName'])
        url = handler.LOCATION
        # Look for methods that are exported
        for mName, mObj in inspect.getmembers(handler):
          if inspect.ismethod(mObj) and mName.find(handler.METHOD_PREFIX) == 0:
            methodName = mName[len(handler.METHOD_PREFIX):]
            args = getattr(handler, 'path_%s' % methodName, [])
            # argObj = inspect.getargspec(mObj)
            # args = '/'.join(['([A-z0-9_.-]+)'] * (len(argObj.args) - 1 - len(argObj.defaults or [])))
            # defs = '/'.join(['([A-z0-9_.-]*)'] * len(argObj.defaults or []))
            gLogger.debug(" - Route %s/%s ->  %s.%s" % (handler.LOCATION, methodName, module['loadName'], mName))
            url = "%s/%s" % (handler.LOCATION, methodName)
            if args:
              url += '/%s' % '/'.join(args)
            gLogger.debug("  * %s" % url)
            self.__addHandler((module['loadName'], handler), url)
    return S_OK()

  def getHandlersURLs(self):
    """
      Get all handler for usage in Tornado, as a list of tornado.web.url
      If there is no handler found before, it try to find them

      :returns: a list of URL (not the string with "https://..." but the tornado object)
                see http://www.tornadoweb.org/en/stable/web.html#tornado.web.URLSpec
    """
    urls = []
    for key in self.__handlers:
      urls.append(TornadoURL(key, self.__handlers[key]))
    return urls

  def getHandlersDict(self):
    """
      Return all handler dictionary

      :returns: dictionary with absolute url as key ("/System/Service")
                and tornado.web.url object as value
    """
    return self.__handlers
