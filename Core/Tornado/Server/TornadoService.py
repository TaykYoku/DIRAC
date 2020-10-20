"""
TornadoService is the base class for your handlers.
It directly inherits from :py:class:`tornado.web.RequestHandler`
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

__RCSID__ = "$Id$"

from tornado.web import HTTPError
from tornado import gen
import tornado.ioloop
from tornado.ioloop import IOLoop

import DIRAC

from DIRAC import S_OK, S_ERROR
from DIRAC.ConfigurationSystem.Client import PathFinder
from DIRAC.Core.Utilities.JEncode import decode, encode
from DIRAC.Core.Tornado.Server.BaseRequestHandler import BaseRequestHandler


class TornadoService(BaseRequestHandler):  # pylint: disable=abstract-method
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
  def _getServiceName(self, request):
    """ Search service name in request.

        :param object request: tornado Request

        :return: str
    """
    # Expected path: ``/<System>/<Component>``
    return request.path[1:]
  
  def _getServiceAuthSection(self, serviceName):
    """ Search service auth section.

        :param str serviceName: service name

        :return: str
    """
    return "%s/Authorization" % PathFinder.getServiceSection(serviceName)
  
  def _getServiceInfo(self, serviceName, request):
    """ Fill service information.

        :param str serviceName: service name
        :param object request: tornado Request

        :return: dict
    """
    return {'serviceName': serviceName,
            'serviceSectionPath': PathFinder.getServiceSection(serviceName),
            'csPaths': [PathFinder.getServiceSection(serviceName)],
            'URL': request.full_url()}

  def _getMethodName(self):
    """ Parse method name.

        :return: str
    """
    return self.get_argument("method")

  def _getMethodArgs(self):
    """ Decode args.

        :return: list
    """
    args_encoded = self.get_body_argument('args', default=encode([]))
    return decode(args_encoded)[0]

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

    # getting method
    method = self._getMethod()

    # Execute
    try:
      self.initializeRequest()
      retVal = method(*self._getMethodArgs())
    except Exception as e:  # pylint: disable=broad-except
      sLog.exception("Exception serving request", "%s:%s" % (str(e), repr(e)))
      raise HTTPError(http_client.INTERNAL_SERVER_ERROR)

    return retVal
