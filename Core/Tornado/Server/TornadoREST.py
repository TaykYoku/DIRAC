"""
TornadoService is the base class for your handlers.
It directly inherits from :py:class:`tornado.web.RequestHandler`
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

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
import jwt  # TODO: need to add pyjwt to DIRACOS

import DIRAC

from DIRAC import gConfig, gLogger, S_OK, S_ERROR
from DIRAC.ConfigurationSystem.Client import PathFinder
from DIRAC.Core.DISET.AuthManager import AuthManager
from DIRAC.Core.Security.X509Chain import X509Chain  # pylint: disable=import-error
from DIRAC.Core.Utilities.JEncode import decode, encode
from DIRAC.FrameworkSystem.Client.MonitoringClient import MonitoringClient
from DIRAC.ConfigurationSystem.Client.Helpers.Resources import getProviderInfo

sLog = gLogger.getSubLogger(__name__)


class TornadoService(RequestHandler):  # pylint: disable=abstract-method
  """
    Base class for all the Handlers.
    It directly inherits from :py:class:`tornado.web.RequestHandler`

    Each HTTP request is served by a new instance of this class.

    For the sequence of method called, please refer to
    the `tornado documentation <https://www.tornadoweb.org/en/stable/guide/structure.html>`_.

    For compatibility with the existing :py:class:`DIRAC.Core.DISET.TransferClient.TransferClient`,
    the handler can define a method ``export_streamToClient``. This is the method that will be called
    whenever ``TransferClient.receiveFile`` is called. It is the equivalent of the DISET
    ``transfer_toClient``.
    Note that this is here only for compatibility, and we discourage using it for new purposes, as it is
    bound to disappear.

    The handler only define the ``post`` verb. Please refer to :py:meth:`.post` for the details.

    In order to create a handler for your service, it has to
    follow a certain skeleton::

      from DIRAC.Core.Tornado.Server.TornadoService import TornadoService
      class yourServiceHandler(TornadoService):

        # Called only once when the first
        # request for this handler arrives
        # Useful for initializing DB or so.
        # You don't need to use super or to call any parents method, it's managed by the server
        @classmethod
        def initializeHandler(cls, infosDict):
          '''Called only once when the first
             request for this handler arrives
             Useful for initializing DB or so.
             You don't need to use super or to call any parents method, it's managed by the server
          '''
          pass


        def initializeRequest(self):
          '''
             Called at the beginning of each request
          '''
          pass

        # Specify the default permission for the method
        # See :py:class:`DIRAC.Core.DISET.AuthManager.AuthManager`
        auth_someMethod = ['authenticated']


        def export_someMethod(self):
          '''The method you want to export.
           It must start with ``export_``
           and it must return an S_OK/S_ERROR structure
          '''
          return S_ERROR()


        def export_streamToClient(self, myDataToSend, token):
          ''' Automatically called when ``Transfer.receiveFile`` is called.
              Contrary to the other ``export_`` methods, it does not need
              to return a DIRAC structure.
          '''

          # Do whatever with the token

          with open(myFileToSend, 'r') as fd:
            return fd.read()


    Note that because we inherit from :py:class:`tornado.web.RequestHandler`
    and we are running using executors, the methods you export cannot write
    back directly to the client. Please see inline comments for more details.

    In order to pass information around and keep some states, we use instance attributes.
    These are initialized in the :py:meth:`.initialize` method.

  """

  # Because we initialize at first request, we use a flag to know if it's already done
  __init_done = False
  # Lock to make sure that two threads are not initializing at the same time
  __init_lock = threading.RLock()

  @classmethod
  def __initializeService(cls):
    """
      Initialize a service.
      The work is only perform once at the first request.

      For REST interface, I think we can pass this.

      :returns: S_OK
    """
    pass

  @classmethod
  def initializeHandler(cls, serviceInfoDict):
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

  def __prepare(self):
    # "method" argument of the POST call.
    # This resolves into the ``export_<method>`` method
    # on the handler side
    # If the argument is not available, the method exists
    # and an error 400 ``Bad Request`` is returned to the client
    self.method = self.get_argument("method")

  def prepare(self):
    """
      Prepare the request. It reads certificates and check authorizations.
      We make the assumption that there is always going to be a ``method`` argument
      regardless of the HTTP method used

    """
    self.__prepare()

    self._stats['requests'] += 1

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

    # Check whether we are authorized to perform the query
    # Note that performing the authQuery modifies the credDict...
    authorized = self._authManager.authQuery(self.method, self.credDict, hardcodedAuth)
    if not authorized:
      sLog.error(
          "Unauthorized access", "Identity %s; path %s; DN %s" %
          (self.srv_getFormattedRemoteCredentials,
           self.request.path,
           self.credDict['DN'],
           ))
      raise HTTPError(status_code=http_client.UNAUTHORIZED)

  def get(self):
    self.post()

  # Make post a coroutine.
  # See https://www.tornadoweb.org/en/branch5.1/guide/coroutines.html#coroutines
  # for details
  @gen.coroutine
  def post(self):  # pylint: disable=arguments-differ
    """
      Method to handle incoming ``POST`` requests.
      Note that all the arguments are already prepared in the :py:meth:`.prepare`
      method.

      The ``POST`` arguments expected are:

      * ``method``: name of the method to call
      * ``args``: JSON encoded arguments for the method
      * ``extraCredentials``: (optional) Extra informations to authenticate client
      * ``rawContent``: (optionnal, default False) If set to True, return the raw output
        of the method called.

      If ``rawContent`` was requested by the client, the ``Content-Type``
      is ``application/octet-stream``, otherwise we set it to ``application/json``
      and JEncode retVal.

      If ``retVal`` is a dictionary that contains a ``Callstack`` item,
      it is removed, not to leak internal information.


      Example of call using ``requests``::

        In [20]: url = 'https://server:8443/DataManagement/TornadoFileCatalog'
          ...: cert = '/tmp/x509up_u1000'
          ...: kwargs = {'method':'whoami'}
          ...: caPath = '/home/dirac/ClientInstallDIR/etc/grid-security/certificates/'
          ...: with requests.post(url, data=kwargs, cert=cert, verify=caPath) as r:
          ...:     print r.json()
          ...:
        {u'OK': True,
            u'Value': {u'DN': u'/C=ch/O=DIRAC/OU=DIRAC CI/CN=ciuser/emailAddress=lhcb-dirac-ci@cern.ch',
            u'group': u'dirac_user',
            u'identity': u'/C=ch/O=DIRAC/OU=DIRAC CI/CN=ciuser/emailAddress=lhcb-dirac-ci@cern.ch',
            u'isLimitedProxy': False,
            u'isProxy': True,
            u'issuer': u'/C=ch/O=DIRAC/OU=DIRAC CI/CN=ciuser/emailAddress=lhcb-dirac-ci@cern.ch',
            u'properties': [u'NormalUser'],
            u'secondsLeft': 85441,
            u'subject': u'/C=ch/O=DIRAC/OU=DIRAC CI/CN=ciuser/emailAddress=lhcb-dirac-ci@cern.ch/CN=2409820262',
            u'username': u'adminusername',
            u'validDN': False,
            u'validGroup': False}}
    """

    sLog.notice(
        "Incoming request %s /%s: %s" %
        (self.srv_getFormattedRemoteCredentials(),
         self._serviceName,
         self.method))

    # Execute the method in an executor (basically a separate thread)
    # Because of that, we cannot calls certain methods like `self.write`
    # in __executeMethod. This is because these methods are not threadsafe
    # https://www.tornadoweb.org/en/branch5.1/web.html#thread-safety-notes
    # However, we can still rely on instance attributes to store what should
    # be sent back (reminder: there is an instance
    # of this class created for each request)
    retVal = yield IOLoop.current().run_in_executor(None, self.__executeMethod)

    # retVal is :py:class:`tornado.concurrent.Future`
    self.result = retVal.result()

    # Here it is safe to write back to the client, because we are not
    # in a thread anymore

    # If set to true, do not JEncode the return of the RPC call
    # This is basically only used for file download through
    # the 'streamToClient' method.
    rawContent = self.get_argument('rawContent', default=False)

    if rawContent:
      # See 4.5.1 http://www.rfc-editor.org/rfc/rfc2046.txt
      self.set_header("Content-Type", "application/octet-stream")
      result = self.result
    else:
      self.set_header("Content-Type", "application/json")
      result = encode(self.result)

    self.write(result)
    self.finish()

  def __getMethodName(self):
    return 'export_%s' % self.get_argument("method")
  
  def __getMethodArgsKwargs(self):
    args_encoded = self.get_body_argument('args', default=encode([]))
    return (decode(args_encoded)[0], {})

  @gen.coroutine
  def __executeMethod(self):
    """
      Execute the method called, this method is ran in an executor
      We have several try except to catch the different problem which can occur

      - First, the method does not exist => Attribute error, return an error to client
      - second, anything happend during execution => General Exception, send error to client

      .. warning::
        This method is called in an executor, and so cannot use methods like self.write
        See https://www.tornadoweb.org/en/branch5.1/web.html#thread-safety-notes
    """
    try:
      method = getattr(self, self.__getMethodName())
    except AttributeError as e:
      sLog.error("Invalid method", self.__getMethodName())
      raise HTTPError(status_code=http_client.NOT_IMPLEMENTED)
    # Decode args kwargs
    args, kwargs = self.__getMethodArgsKwargs()
    # Execute
    try:
      self.initializeRequest()
      retVal = method(*args, **kwargs)
    except Exception as e:  # pylint: disable=broad-except
      sLog.exception("Exception serving request", "%s:%s" % (str(e), repr(e)))
      raise HTTPError(http_client.INTERNAL_SERVER_ERROR)

    return retVal

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

  def _gatherPeerCredentials(self):
    """
      Load client certchain in DIRAC and extract informations.

      The dictionary returned is designed to work with the AuthManager,
      already written for DISET and re-used for HTTPS.

      :returns: a dict containing the return of :py:meth:`DIRAC.Core.Security.X509Chain.X509Chain.getCredentials`
                (not a DIRAC structure !)
    """
    if self.request.headers.get("authorization"):
      # If present "authorization" header it means that need to use another then certificate authZ
      tType, token = self.request.headers["authorization"].split()
      if tType.lower() != "bearer":
        raise Exception('Unknown "%s" authorization flow, please use "Bearer" tokens.')

      # Read token claims without verification to found IdP secret key
      cred = jwt.decode(token, verify=False)
      # If "usb" claim is anonymous, don't verify it
      if cred['sub'] == 'anonymous':
        return {'ID': 'anonymous', 'group': 'visitor'}
      # Look identity provider secret key to verify token
      res = getProviderInfo(cred['idp'])  # getProviderInfo implemented in PR #4650
      if not res['OK']:
        raise Exception(res['Message'])
      key = res['Value'].get('client_secret')
      # Get claims and verify signature
      claims = jwt.decode(token, key)
      # Verify token
      claims.validate()
      # If no found 'group' claim, user group need to add as https argument
      credDict = {'ID': claims.sub,
                  'group': claim.get('group')}
    else:
      chainAsText = self.request.get_ssl_certificate().as_pem()
      peerChain = X509Chain()

      # Here we read all certificate chain
      cert_chain = self.request.get_ssl_certificate_chain()
      for cert in cert_chain:
        chainAsText += cert.as_pem()

      peerChain.loadChainFromString(chainAsText)

      # Retrieve the credentials
      res = peerChain.getCredentials(withRegistryInfo=False)
      if not res['OK']:
        raise Exception(res['Message'])

      credDict = res['Value']

    # We check if client sends extra credentials...
    if "extraCredentials" in self.request.arguments:
      extraCred = self.get_argument("extraCredentials")
      if extraCred:
        credDict['extraCredentials'] = decode(extraCred)[0]
    return credDict


####
#
#  Utilities methods, some getters.
#  From DIRAC.Core.DISET.requestHandler to get same interface in the handlers.
#  Adapted for Tornado.
#  These method are copied from DISET RequestHandler, they are not all used when i'm writing
#  these lines. I rewrite them for Tornado to get them ready when a new HTTPS service need them
#
####

  @classmethod
  def srv_getCSOption(cls, optionName, defaultValue=False):
    """
    Get an option from the CS section of the services

    :return: Value for serviceSection/optionName in the CS being defaultValue the default
    """
    if optionName[0] == "/":
      return gConfig.getValue(optionName, defaultValue)
    for csPath in cls._serviceInfoDict['csPaths']:
      result = gConfig.getOption("%s/%s" % (csPath, optionName, ), defaultValue)
      if result['OK']:
        return result['Value']
    return defaultValue

  def getCSOption(self, optionName, defaultValue=False):
    """
      Just for keeping same public interface
    """
    return self.srv_getCSOption(optionName, defaultValue)

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

  def srv_getRemoteCredentials(self):
    """
    Get the credentials of the remote peer.

    :return: Credentials dictionary of remote peer.
    """
    return self.credDict

  def getRemoteCredentials(self):
    """
    Get the credentials of the remote peer.

    :return: Credentials dictionary of remote peer.
    """
    return self.credDict

  def srv_getFormattedRemoteCredentials(self):
    """
      Return the DN of user

      Mostly copy paste from
      :py:meth:`DIRAC.Core.DISET.private.Transports.BaseTransport.BaseTransport.getFormattedCredentials`

      Note that the information will be complete only once the AuthManager was called
    """
    address = self.getRemoteAddress()
    peerId = ""
    # Depending on where this is call, it may be that credDict is not yet filled.
    # (reminder: AuthQuery fills part of it..)
    try:
      peerId = "[%s:%s]" % (self.credDict['group'], self.credDict['username'])
    except AttributeError:
      pass

    if address[0].find(":") > -1:
      return "([%s]:%s)%s" % (address[0], address[1], peerId)
    return "(%s:%s)%s" % (address[0], address[1], peerId)

  def srv_getURL(self):
    """
      Return the URL
    """
    return self.request.path
