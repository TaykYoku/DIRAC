""" Main module
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import ssl
import json
import functools
import traceback

from concurrent.futures import ThreadPoolExecutor

import tornado.web
import tornado.gen
import tornado.ioloop
import tornado.websocket
import tornado.stack_context

from DIRAC import gConfig, gLogger, S_OK, S_ERROR
from DIRAC.Core.Web import Conf
# from DIRAC.Core.Web.SessionData import SessionData
from DIRAC.Core.Security import Properties
from DIRAC.Core.Security.X509Chain import X509Chain  # pylint: disable=import-error
from DIRAC.Core.DISET.AuthManager import AuthManager
from DIRAC.Core.DISET.ThreadConfig import ThreadConfig
# from DIRAC.Core.Utilities.JEncode import encode
# from DIRAC.ConfigurationSystem.Client.Helpers import Registry
# from DIRAC.FrameworkSystem.Client.AuthManagerData import gAuthManagerData


global gThreadPool
gThreadPool = ThreadPoolExecutor(100)


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
  __disetConfig = ThreadConfig()
  __log = False

  # Location of the handler in the URL
  LOCATION = ""
  # If need to use request path for declare some value/option
  METHOD_PREFIX = "web_"

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

  def __init__(self, *args, **kwargs):
    """ Initialize the handler
    """
    super(WebHandler, self).__init__(*args, **kwargs)
    if not WebHandler.__log:
      WebHandler.__log = gLogger.getSubLogger(self.__class__.__name__)

    # Fill credentials
    self.__credDict = {}
    self.__setup = gConfig.getValue("/DIRAC/Setup")

    # Setup diset
    self.__disetConfig.reset()
    self.__disetConfig.setDecorator(self.__disetBlockDecor)
    self.__disetDump = self.__disetConfig.dump()

    # Set method name
    try:
      self._methodName = self.request.path.replace(self.LOCATION, '', 1).split('/')[1]
    except IndexError:
      self._methodName = None
    

  def __processCredentials(self):
    """ Extract the user credentials based on the certificate or what comes from the balancer

        :return: S_OK()/S_ERROR()
    """
    # Unsecure protocol only for visitors
    if self.request.protocol != "https":
      return S_OK()

    auth = self.request.headers.get("Authorization")
    if auth:
      # If present "Authorization" header it means that need to use another then certificate authZ
      authParts = auth.split()
      authType = authParts[0]
      if authParts != 2 or authType.lower() != "bearer":
        return S_ERROR("Invalid authorization header type.")
      token = authParts[1]
      # Read public key of DIRAC auth service
      with open('/opt/dirac/etc/grid-security/certificates/public.key', 'rb') as f:
        key = f.read()
      # Get claims and verify signature
      claims = jwt.decode(token, key)
      # Verify token
      claims.validate()
      # If no found 'group' claim, user group need to add as https argument
      self.__credDict = {'ID': claims.sub, 'group': claims.get('group')}
      return S_OK()

    # For certificate
    return self.__readCertificate()

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
    return self.__log

  @classmethod
  def getLog(cls):
    return cls.__log

  def getDN(self):
    return self.__credDict.get('DN', '')

  def getID(self):
    return self.__credDict.get('ID', '')

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


  def prepare(self):
    # Get method object
    methodName = "%s%s" % (self.METHOD_PREFIX, self._methodName)
    try:
      self.__method = getattr(self, methodName)
    except AttributeError:
      self.log.fatal("%s method is not implemented." % methodName)
      raise tornado.web.HTTPError(404)

    # Get credentionals
    result = self.__processCredentials()
    if not result['OK']:
      raise tornado.web.HTTPError(503)

    # Authorize
    # Resolves the hard coded authorization requirements
    hardcodedAuth = getattr(self, 'auth_' + self._methodName, None)
    if not AuthManager(None).authQuery(self._methodName, self.__credDict, hardcodedAuth):
      raise tornado.web.HTTPError(401)
    
    # Set DISET
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

    # Initialize request
    self.initialize()

  def get(self, *args, **kwargs):
    return self.__method(*args, **kwargs)

  def post(self, *args, **kwargs):
    return self.__method(*args, **kwargs)
