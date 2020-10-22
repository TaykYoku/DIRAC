"""
TornadoService is the base class for your handlers.
It directly inherits from :py:class:`tornado.web.RequestHandler`
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

__RCSID__ = "$Id$"

import tornado.ioloop
from tornado import gen
from tornado.web import HTTPError
from tornado.ioloop import IOLoop
from six.moves import http_client

import DIRAC

from DIRAC.Core.Web import Conf
from DIRAC.Core.Tornado.Server.TornadoService import TornadoService
from DIRAC.FrameworkSystem.private.authorization.utils.Tokens import ResourceProtector

sLog = gLogger.getSubLogger(__name__)


class TornadoREST(TornadoService):  # pylint: disable=abstract-method
  METHOD_PREFIX = 'web_'

  @classmethod
  def _getServiceName(cls, request):
    """ Search service name in request.

        :param object request: tornado Request

        :return: str
    """
    try:
      return cls.LOCATION.split('/')[-1].strip('/')
    except expression as identifier:
      return cls.__name__
  
  @classmethod
  def _getServiceAuthSection(cls, serviceName):
    """ Search service auth section.

        :param str serviceName: service name

        :return: str
    """
    return Conf.getAuthSectionForHandler(serviceName)
  
  @classmethod
  def _getServiceInfo(cls, serviceName, request):
    """ Fill service information.

        :param str serviceName: service name
        :param object request: tornado Request

        :return: dict
    """
    return {}

  def _getMethodName(self):
    """ Parse method name.

        :return: str
    """
    try:
      return self.request.path.split(self.LOCATION)[1].split('?')[0].strip('/').split('/')[0].strip('/')
    except Exception:
      return 'index'

  def _getMethodArgs(self, args):
    """ Decode args.

        :return: list
    """
    return args
  
  def _getMethodAuthProps(self):
    """ Resolves the hard coded authorization requirements for method.

        :return: object
    """
    hardcodedAuth = super(TornadoREST, self)._getMethodAuthProps()
    if not hardcodedAuth and hasattr(self, 'AUTH_PROPS'):
      if not isinstance(self.AUTH_PROPS, (list, tuple)):
        self.AUTH_PROPS = [p.strip() for p in self.AUTH_PROPS.split(",") if p.strip()]
      hardcodedAuth = self.AUTH_PROPS
    return hardcodedAuth

  def _gatherPeerCredentials(self):
    """
      Load client certchain in DIRAC and extract informations.

      The dictionary returned is designed to work with the AuthManager,
      already written for DISET and re-used for HTTPS.

      :returns: a dict containing the return of :py:meth:`DIRAC.Core.Security.X509Chain.X509Chain.getCredentials`
                (not a DIRAC structure !)
    """
    credDict = {}

    # Unsecure protocol only for visitors
    if self.request.protocol == "https":

      if self.request.headers.get("Authorization"):
        # read token
        credDict = self._readToken()

      else:
        try:
          # try read certificate
          if Conf.balancer() == "nginx":
            credDict = self.__readCertificateFromNginx()
          else:
            credDict = super(TornadoService, self)._gatherPeerCredentials()

          # MUST BE ADDED when read certificate
          # # Add a group if it present in the request path
          # if self.__group:
          # credDict['validGroup'] = False
          #   credDict['group'] = self.__group
        except Exception as e:
          sLog.warn(str(e))

    return credDict
  
  def _readToken(self, scope=None):
    """ Fill credentionals from session

        :param str scope: scope

        :return: dict
    """
    token = ResourceProtector().acquire_token(self.request, scope)
    return {'ID': token.sub, 'issuer': token.issuer, 'group': token.groups[0]}

  def __readCertificateFromNginx(self):
    """ Fill credentional from certificate and check is registred from nginx.

        :return: dict
    """
    headers = self.request.headers
    if not headers:
      raise Exception('No headers found.')
    if headers.get('X-Scheme') != "https":
      raise Exception('Unsecure protocol.')
    if headers.get('X-Ssl_client_verify') != 'SUCCESS':
      raise Exception('No certificate upload to browser.')

    DN = headers['X-Ssl_client_s_dn']
    if not DN.startswith('/'):
      items = DN.split(',')
      items.reverse()
      DN = '/' + '/'.join(items)
    return {'DN': DN, 'issuer': headers['X-Ssl_client_i_dn']}

  @gen.coroutine
  def get(self, *args, **kwargs):  # pylint: disable=arguments-differ
    """
    """
    retVal = yield IOLoop.current().run_in_executor(None, self._executeMethod, args)

    # retVal is :py:class:`tornado.concurrent.Future`
    self._finishFuture(retVal)

  def _finishFuture(self, retVal):
    """ Handler Future result

        :param object retVal: tornado.concurrent.Future
    """
    result = retVal.result()
    try:
      if not result['OK']:
        raise HTTPError(http_client.INTERNAL_SERVER_ERROR)
      result = result['Value']
    except (AttributeError, KeyError, TypeError):
      pass
    super(TornadoREST, self)._finishFuture(result)
    
