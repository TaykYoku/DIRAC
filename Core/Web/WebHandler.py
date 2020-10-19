""" Main module
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

#######
__RCSID__ = "$Id$"

from io import open

import os
import time
import threading
from datetime import datetime
from six.moves import http_client
from tornado.web import RequestHandler, HTTPError
from tornado import gen
import tornado.ioloop
from tornado.ioloop import IOLoop

import DIRAC

from DIRAC import gConfig, gLogger, S_OK, S_ERROR
from DIRAC.ConfigurationSystem.Client import PathFinder
from DIRAC.Core.DISET.AuthManager import AuthManager
from DIRAC.Core.Security.X509Chain import X509Chain  # pylint: disable=import-error
from DIRAC.Core.Utilities.JEncode import decode, encode
from DIRAC.FrameworkSystem.Client.MonitoringClient import MonitoringClient
#######

import ssl
import json
import functools
import traceback
from time import time

from concurrent.futures import ThreadPoolExecutor
from authlib.common.security import generate_token

import tornado.web
import tornado.gen
import tornado.ioloop
import tornado.websocket
import tornado.stack_context

from authlib.jose import jwt

from DIRAC import gConfig, gLogger, S_OK, S_ERROR
from DIRAC.Core.Web import Conf
from DIRAC.Core.Web.SessionData import SessionData
from DIRAC.Core.Security import Properties
from DIRAC.Core.Security.X509Chain import X509Chain  # pylint: disable=import-error
from DIRAC.Core.DISET.AuthManager import AuthManager
from DIRAC.Core.DISET.ThreadConfig import ThreadConfig
from DIRAC.Core.Utilities.JEncode import encode
from DIRAC.ConfigurationSystem.Client.Helpers import Registry
# from DIRAC.FrameworkSystem.Client.AuthManagerData import gAuthManagerData


global gThreadPool
gThreadPool = ThreadPoolExecutor(100)
sLog = gLogger.getSubLogger(__name__)


class WErr(tornado.web.HTTPError):

  def __init__(self, code, msg="", **kwargs):
    super(WErr, self).__init__(code, str(msg) or None)
    for k in kwargs:
      setattr(self, k, kwargs[k])
    self.ok = False
    self.msg = msg
    self.kwargs = kwargs

  def __str__(self):
    return super(WErr, self).__str__()

  @classmethod
  def fromSERROR(cls, result):
    """ Prevent major problem with % in the message """
    return cls(500, result['Message'].replace("%", ""))


class WOK(object):

  def __init__(self, data=False, **kwargs):
    for k in kwargs:
      setattr(self, k, kwargs[k])
    self.ok = True
    self.data = data


def asyncWithCallback(method):
  return tornado.web.asynchronous(method)


def asyncGen(method):
  return tornado.gen.coroutine(method)


class WebHandler(tornado.web.RequestHandler):
  # Because we initialize at first request, we use a flag to know if it's already done
  __init_done = False
  # Lock to make sure that two threads are not initializing at the same time
  __init_lock = threading.RLock()
  
  # MonitoringClient, we don't use gMonitor which is not thread-safe
  # We also need to add specific attributes for each service
  _monitor = None

  __disetConfig = ThreadConfig()
  __log = False

  # Auth requirements
  AUTH_PROPS = None
  # Location of the handler in the URL
  LOCATION = ""
  # URL Schema with holders to generate handler urls
  URLSCHEMA = ""
  # RE to extract group and setup
  PATH_RE = None
  # If need to use request path for declare some value/option
  OVERPATH = False
  # Prefix of methods names
  METHOD_PREFIX = "web_"

  # This is a Tornado magic method
  def initialize(self):  # pylint: disable=arguments-differ
    """
      Initialize the handler, called at every request.

      It just calls :py:meth:`.__initializeService`

      If anything goes wrong, the client will get ``Connection aborted``
      error. See details inside the method.

      ..warning::
        DO NOT REWRITE THIS FUNCTION IN YOUR HANDLER
        ==> initialize in DISET became initializeRequest in HTTPS !
    """
    # Only initialized once
    if not self.__init_done:
      # Ideally, if something goes wrong, we would like to return a Server Error 500
      # but this method cannot write back to the client as per the
      # `tornado doc <https://www.tornadoweb.org/en/stable/guide/structure.html#overriding-requesthandler-methods>`_.
      # So the client will get a ``Connection aborted```
      try:
        res = self.__initializeService()
        if not res['OK']:
          raise Exception(res['Message'])
      except Exception as e:
        sLog.error("Error in initialization", repr(e))
        raise
  
  @classmethod
  def _initMonitoring(cls, serviceName, fullUrl):
    """
      Initialize the monitoring specific to this handler
      This has to be called only by :py:meth:`.__initializeService`
      to ensure thread safety and unicity of the call.

      :param serviceName: relative URL ``/<System>/<Component>``
      :param fullUrl: full URl like ``https://<host>:<port>/<System>/<Component>``
    """

    # Init extra bits of monitoring

    cls._monitor = MonitoringClient()
    cls._monitor.setComponentType(MonitoringClient.COMPONENT_WEB)

    cls._monitor.initialize()

    if tornado.process.task_id() is None:  # Single process mode
      cls._monitor.setComponentName('Tornado/%s' % serviceName)
    else:
      cls._monitor.setComponentName('Tornado/CPU%d/%s' % (tornado.process.task_id(), serviceName))

    cls._monitor.setComponentLocation(fullUrl)

    cls._monitor.registerActivity("Queries", "Queries served", "Framework", "queries", MonitoringClient.OP_RATE)

    cls._monitor.setComponentExtraParam('DIRACVersion', DIRAC.version)
    cls._monitor.setComponentExtraParam('platform', DIRAC.getPlatform())
    cls._monitor.setComponentExtraParam('startTime', datetime.utcnow())

    cls._stats = {'requests': 0, 'monitorLastStatsUpdate': time.time()}

    return S_OK()

  @classmethod
  def __initializeService(cls):
    """
      Initialize a service.
      The work is only perform once at the first request.

      :param relativeUrl: relative URL, e.g. ``/<System>/<Component>``
      :param absoluteUrl: full URL e.g. ``https://<host>:<port>/<System>/<Component>``

      :returns: S_OK
    """
    # If the initialization was already done successfuly,
    # we can just return
    if cls.__init_done:
      return S_OK()

    # Otherwise, do the work but with a lock
    with cls.__init_lock:

      # Check again that the initialization was not done by another thread
      # while we were waiting for the lock
      if cls.__init_done:
        return S_OK()

      # Url starts with a "/", we just remove it
      serviceName = cls.__name__
      match = cls.PATH_RE.match(cls.request.path)
      groups = match.groups()
      route = groups[2]
      handlerRoute = route if route[-1] == "/" else route[:route.rfind("/")]

      cls._startTime = datetime.utcnow()
      sLog.info("First use of %s, initializing service..." % serviceName)
      cls._authManager = AuthManager(Conf.getAuthSectionForHandler(handlerRoute))

      cls._initMonitoring(serviceName, self.request.path)

      cls.__monitorLastStatsUpdate = time.time()

      cls.initializeHandler()

      cls.__init_done = True

      return S_OK()
  
  @classmethod
  def initializeHandler(cls):
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
    """
      Called at every request, may be overwritten in your handler.
    """
    pass

  def threadTask(self, method, *args, **kwargs):
    def threadJob(*targs, **tkwargs):
      args = targs[0]
      disetConf = targs[1]
      self.__disetConfig.reset()
      self.__disetConfig.load(disetConf)
      return method(*args, **tkwargs)

    targs = (args, self.__disetDump)
    return tornado.ioloop.IOLoop.current().run_in_executor(gThreadPool,
                                                           functools.partial(threadJob, *targs, **kwargs))

  def __disetBlockDecor(self, func):
    def wrapper(*args, **kwargs):
      raise RuntimeError("All DISET calls must be made from inside a Threaded Task!")

    return wrapper

  # def __init__(self, *args, **kwargs):
  #   """ Initialize the handler
  #   """
  #   super(WebHandler, self).__init__(*args, **kwargs)
  #   if not WebHandler.__log:
  #     WebHandler.__log = gLogger.getSubLogger(self.__class__.__name__)

  def prepare(self):
    """
      Prepare the request. It reads certificates and check authorizations.
      We make the assumption that there is always going to be a ``method`` argument
      regardless of the HTTP method used

    """
    self.__parseURI()
    self.__disetConfig.reset()
    self.__disetConfig.setDecorator(self.__disetBlockDecor)
    self.__disetDump = self.__disetConfig.dump()

    match = cls.PATH_RE.match(cls.request.path)
    groups = match.groups()
    route = groups[2]
    self.method = "index" if route[-1] == "/" else route[route.rfind("/") + 1:]

    self._stats['requests'] += 1
    self._monitor.setComponentExtraParam('queries', self._stats['requests'])
    self._monitor.addMark("Queries")

    try:
      self.credDict = self._gatherPeerCredentials()
    except Exception:  # pylint: disable=broad-except
      # If an error occur when reading certificates we close connection
      # It can be strange but the RFC, for HTTP, say's that when error happend
      # before authentication we return 401 UNAUTHORIZED instead of 403 FORBIDDEN
      sLog.error(
          "Error gathering credentials", "%s; path %s" %
          (self.getRemoteAddress(), self.request.path))
      raise HTTPError(status_code=http_client.UNAUTHORIZED)

    # Resolves the hard coded authorization requirements
    try:
      hardcodedAuth = getattr(self, 'auth_' + self.method)
    except AttributeError:
      hardcodedAuth = None
    
    if not hardcodedAuth and hasattr(self, 'AUTH_PROPS'):
      if not isinstance(self.AUTH_PROPS, (list, tuple)):
        self.AUTH_PROPS = [p.strip() for p in self.AUTH_PROPS.split(",") if p.strip()]
      hardcodedAuth = self.AUTH_PROPS

    self.credDict['validGroup'] = False

    # Check whether we are authorized to perform the query
    # Note that performing the authQuery modifies the credDict...
    authorized = self._authManager.authQuery(self.method, self.credDict, hardcodedAuth)
    
    if self.__credDict.get('DN') and self.isTrustedHost(self.__credDict['DN']):
      self.log.info("Request is coming from Trusted host")
      authorized = True
    
    if not authorized:
      sLog.error(
          "Unauthorized access", "Identity %s; path %s; DN %s" %
          (self.srv_getFormattedRemoteCredentials,
           self.request.path,
           self.credDict['DN'],
           ))
      raise HTTPError(status_code=http_client.UNAUTHORIZED)
    
    DN = self.getDN()
    if DN:
      self.__disetConfig.setDN(DN)
    ID = self.getID()
    if ID:
      self.__disetConfig.setID(ID)

    # pylint: disable=no-value-for-parameter
    if self.getUserGroup():  # pylint: disable=no-value-for-parameter
      self.__disetConfig.setGroup(self.getUserGroup())  # pylint: disable=no-value-for-parameter
    self.__disetConfig.setSetup(self.__setup)
    self.__disetDump = self.__disetConfig.dump()
    
    self.__sessionData = SessionData(self.__credDict, self.__setup)
    self.__forceRefreshCS()

  def on_finish(self):
    """
      Called after the end of HTTP request.
      Log the request duration
    """
    elapsedTime = 1000.0 * self.request.request_time()

    try:
      if self.result['OK']:
        argsString = "OK"
      else:
        argsString = "ERROR: %s" % self.result['Message']
    except (AttributeError, KeyError):  # In case it is not a DIRAC structure
      if self._reason == 'OK':
        argsString = 'OK'
      else:
        argsString = 'ERROR %s' % self._reason

      argsString = "ERROR: %s" % self._reason
    sLog.notice("Returning response", "%s %s (%.2f ms) %s" % (self.srv_getFormattedRemoteCredentials(),
                                                              self._serviceName,
                                                              elapsedTime, argsString))

  def __parseURI(self):
    match = self.PATH_RE.match(self.request.path)
    groups = match.groups()
    self.__setup = groups[0] or Conf.setup()
    self.__group = groups[1]
    self.__route = groups[2]
    self.__args = groups[3:]

  def __forceRefreshCS(self):
    """ Force refresh configuration from master configuration server
    """
    if self.request.headers.get('X-RefreshConfiguration') == 'True':
      self.log.debug('Initialize force refresh..')
      if not AuthManager('').authQuery("", dict(self.__credDict), "CSAdministrator"):
        raise WErr(401, 'Cannot initialize force refresh, request not authenticated')
      result = gConfig.forceRefresh()
      if not result['OK']:
        raise WErr(501, result['Message'])

  def _gatherPeerCredentials(self):
    """
      Load client certchain in DIRAC and extract informations.

      The dictionary returned is designed to work with the AuthManager,
      already written for DISET and re-used for HTTPS.

      :returns: a dict containing the return of :py:meth:`DIRAC.Core.Security.X509Chain.X509Chain.getCredentials`
                (not a DIRAC structure !)
    """
    # Parse URI
    self.__parseURI()

    # Authorization type
    self.__authGrant = self.get_cookie('authGrant', 'Certificate')
    self.__sessionID = self.get_secure_cookie('session_id')
    self.__session = self.application.getSession(self.__sessionID)
    # self.__jwtAuth = self.request.headers.get("Authorization")
    return self.__processCredentials()

  def __processCredentials(self):
    """ Extract the user credentials based on the certificate or what comes from the balancer

        :return: S_OK()/S_ERROR()
    """
    # Unsecure protocol only for visitors
    if self.request.protocol != "https":  # or self.__idp == "Visitor":
      return S_OK()

    self.__credDict = {'group': self.__group}

    if self.__authGrant == 'Session':
      result = self.__readSession()
    elif self.__authGrant == 'Visitor':
      result = S_OK()
    else:
      result = self.__readCertificate()

    if not result['OK']:
      self.log.error(result['Message'], 'Continue as Visitor.')
    return S_OK(self.__credDict)

  def _request_summary(self):
    """ Return a string returning the summary of the request

        :return: str
    """
    summ = super(WebHandler, self)._request_summary()
    cl = []
    if self.__credDict.get('validDN', False):
      cl.append(self.__credDict['username'])
      if self.__credDict.get('validGroup', False):
        cl.append("@%s" % self.__credDict['group'])
      cl.append(" (%s)" % self.__credDict['DN'])
    summ = "%s %s" % (summ, "".join(cl))
    return summ

  def __readSession(self):
    """ Fill credentionals from session

        :return: S_OK()/S_ERROR()
    """
    if not self.__session or not self.__session.token:
      return S_ERROR('Session expired.')

    if self.request.headers.get("Authorization"):
      token = self.application._resourceProtector.acquire_token(self.request, 'changeGroup')

      # Is session active?
      if self.__session.token.access_token != token.access_token:
        return S_ERROR('Session expired.')
    token = self.application._resourceProtector.validator(self.__session.token.refresh_token, 'changeGroup', None, 'OR')

    self.__credDict['ID'] = token.sub
    self.__credDict['issuer'] = token.issuer

    # Update session expired time
    self.application.updateSession(self.__session)
    return S_OK()

  def __readCertificate(self):
    """ Fill credentional from certificate and check is registred

        :return: S_OK()/S_ERROR()
    """
    if Conf.balancer() == "nginx":
      # NGINX
      headers = self.request.headers
      if not headers:
        return S_ERROR('No headers found.')
      if headers.get('X-Scheme') == "https" and headers.get('X-Ssl_client_verify') == 'SUCCESS':
        DN = headers['X-Ssl_client_s_dn']
        if not DN.startswith('/'):
          items = DN.split(',')
          items.reverse()
          DN = '/' + '/'.join(items)
        self.__credDict['DN'] = DN
        self.__credDict['issuer'] = headers['X-Ssl_client_i_dn']
      else:
        return S_ERROR('No certificate upload to browser.')

    else:
      # TORNADO
      derCert = self.request.get_ssl_certificate(binary_form=True)
      if not derCert:
        return S_ERROR('No certificate found.')
      pemCert = ssl.DER_cert_to_PEM_cert(derCert)
      chain = X509Chain()
      chain.loadChainFromString(pemCert)
      result = chain.getCredentials()
      if not result['OK']:
        return S_ERROR("Could not get client credentials %s" % result['Message'])
      self.__credDict = result['Value']
      # Hack. Data coming from OSSL directly and DISET difer in DN/subject
      try:
        self.__credDict['DN'] = self.__credDict['subject']
      except KeyError:
        pass

    return S_OK()

  @property
  def log(self):
    return sLog

  @classmethod
  def getLog(cls):
    return cls.__log

  def getDN(self):
    return self.__credDict.get('DN', '')

  def getID(self):
    return self.__credDict.get('ID', '')

  # def getIdP(self):
  #   return self.__idp

  def getCurrentSession(self):
    return self.__session

  def getUserName(self):
    return self.__credDict.get('username', '')

  def getUserGroup(self):
    return self.__credDict.get('group', '')

  def getUserSetup(self):
    return self.__setup

  def getProperties(self):
    return self.__credDict.get('properties', [])

  def isRegisteredUser(self):
    return self.__credDict.get('username', 'anonymous') != 'anonymous' and self.__credDict.get('group')

  def getSessionData(self):
    return self.__sessionData.getData()

  def getAppSettings(self, app=None):
    return Conf.getAppSettings(app or self.__class__.__name__.replace('Handler', '')).get('Value') or {}

  def actionURL(self, action=""):
    """ Given an action name for the handler, return the URL

        :param str action: action

        :return: str
    """
    if action == "index":
      action = ""
    group = self.getUserGroup()
    if group:
      group = "/g:%s" % group
    setup = self.getUserSetup()
    if setup:
      setup = "/s:%s" % setup
    location = self.LOCATION
    if location:
      location = "/%s" % location
    ats = dict(action=action, group=group, setup=setup, location=location)
    return self.URLSCHEMA % ats

  def __auth(self, handlerRoute, group, method):
    """ Authenticate request

        :param str handlerRoute: the name of the handler
        :param str group: DIRAC group
        :param str method: the name of the method

        :return: bool
    """
    if not isinstance(self.AUTH_PROPS, (list, tuple)):
      self.AUTH_PROPS = [p.strip() for p in self.AUTH_PROPS.split(",") if p.strip()]
    self.__credDict['validGroup'] = False
    # self.__credDict['group'] = group
    auth = AuthManager(Conf.getAuthSectionForHandler(handlerRoute))
    ok = auth.authQuery(method, self.__credDict, self.AUTH_PROPS)
    if ok:
      self.__credDict['validGroup'] = True
      # WARN: __credDict['properties'] already defined in AuthManager in the last version of DIRAC
      # self.__credDict['properties'] = Registry.getPropertiesForGroup(self.__credDict['group'], [])
      msg = ' - '
      if self.__credDict.get('DN'):
        msg = '%s' % self.__credDict['DN']
      elif self.__credDict.get('ID'):
        result = gAuthManagerData.getIdPForID(self.__credDict['ID'])  # pylint: disable=no-member
        if not result['OK']:
          self.log.error(result['Message'])
          return False
        msg = 'IdP: %s, ID: %s' % (result['Value'], self.__credDict['ID'])
      self.log.info("AUTH OK: %s by %s@%s (%s)" % (handlerRoute, self.__credDict['username'],
                                                   self.__credDict['group'], msg))
    else:
      self.log.info("AUTH KO: %s by %s@%s" % (handlerRoute, self.__credDict['username'], self.__credDict['group']))

    if self.__credDict.get('DN') and self.isTrustedHost(self.__credDict['DN']):
      self.log.info("Request is coming from Trusted host")
      return True
    return ok

  def isTrustedHost(self, dn):
    """ Check if the request coming from a TrustedHost

        :param str dn: certificate DN

        :return: bool if the host is Trusrted it return true otherwise false
    """
    retVal = Registry.getHostnameForDN(dn)
    if retVal['OK']:
      hostname = retVal['Value']
      if Properties.TRUSTED_HOST in Registry.getPropertiesForHost(hostname, []):
        return True
    return False

  def __checkPath(self):
    """ Check the request, auth, credentials and DISET config

        :return: WOK()/WErr()
    """
    if self.__route[-1] == "/":
      methodName = "index"
      handlerRoute = self.__route
    else:
      iP = self.__route.rfind("/")
      methodName = self.__route[iP + 1:]
      handlerRoute = self.__route[:iP]

    if not self.__auth(handlerRoute, self.__group, methodName):
      return WErr(401, "Unauthorized. %s" % methodName)

    DN = self.getDN()
    if DN:
      self.__disetConfig.setDN(DN)
    ID = self.getID()
    if ID:
      self.__disetConfig.setID(ID)

    # pylint: disable=no-value-for-parameter
    if self.getUserGroup():  # pylint: disable=no-value-for-parameter
      self.__disetConfig.setGroup(self.getUserGroup())  # pylint: disable=no-value-for-parameter
    self.__disetConfig.setSetup(self.__setup)
    self.__disetDump = self.__disetConfig.dump()

    return WOK(methodName)

  def get(self, setup, group, route, *pathArgs):
    methodName = "web_%s" % self.method
    try:
      mObj = getattr(self, methodName)
    except AttributeError as e:
      self.log.fatal("This should not happen!! %s" % e)
      raise tornado.web.HTTPError(404)
    return mObj(*pathArgs)

  def post(self, *args, **kwargs):
    return self.get(*args, **kwargs)

  def delete(self, *args, **kwargs):
    return self.get(*args, **kwargs)

  def write_error(self, status_code, **kwargs):
    self.set_status(status_code)
    cType = "text/plain"
    data = self._reason
    if 'exc_info' in kwargs:
      ex = kwargs['exc_info'][1]
      trace = traceback.format_exception(*kwargs["exc_info"])
      if not isinstance(ex, WErr):
        data += "\n".join(trace)
      else:
        if self.settings.get("debug"):
          self.log.error("Request ended in error:\n  %s" % "\n  ".join(trace))
        data = ex.msg
        if isinstance(data, dict):
          cType = "application/json"
          data = json.dumps(data)
    self.set_header('Content-Type', cType)
    self.finish(data)

  def finishJEncode(self, o):
    """ Encode data before finish
    """
    self.finish(encode(o))

  def srv_getRemoteAddress(self):
    """
    Get the address of the remote peer.

    :return: Address of remote peer.
    """

    remote_ip = self.request.remote_ip
    # Although it would be trivial to add this attribute in _HTTPRequestContext,
    # Tornado won't release anymore 5.1 series, so go the hacky way
    try:
      remote_port = self.request.connection.stream.socket.getpeername()[1]
    except Exception:  # pylint: disable=broad-except
      remote_port = 0

    return (remote_ip, remote_port)

  def getRemoteAddress(self):
    """
      Just for keeping same public interface
    """
    return self.srv_getRemoteAddress()

class WebSocketHandler(tornado.websocket.WebSocketHandler, WebHandler):

  def __init__(self, *args, **kwargs):
    WebHandler.__init__(self, *args, **kwargs)
    tornado.websocket.WebSocketHandler.__init__(self, *args, **kwargs)

  def open(self, setup, group, route):
    if not self._pathResult.ok:
      raise self._pathResult
    return self.on_open()

  def on_open(self):
    pass
