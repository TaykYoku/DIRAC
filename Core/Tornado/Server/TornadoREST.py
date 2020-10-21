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
from DIRAC.Core.Tornado.Server.TornadoService import TornadoService
from DIRAC.Core.Web import Conf


class TornadoREST(TornadoService):  # pylint: disable=abstract-method
  @classmethod
  def _getServiceName(cls, request):
    """ Search service name in request.

        :param object request: tornado Request

        :return: str
    """
    route = cls.LOCATION
    return route if route[-1] == "/" else route[:route.rfind("/")]
  
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
      return self.request.path.split(self.LOCATION)[1].split('?')[0].split('/')[0].strip('/')
    except Exception:
      return 'index'

  def _getMethodArgs(self):
    """ Decode args.

        :return: list
    """
    try:
      return [a.strip('/') for a in self.request.path.split(self.LOCATION)[1].split('?')[0].split('/')[1:]]
    except Exception:
      return []
    # return self._tornadoMethodArgs

  def _gatherPeerCredentials(self):
    """
      Load client certchain in DIRAC and extract informations.

      The dictionary returned is designed to work with the AuthManager,
      already written for DISET and re-used for HTTPS.

      :returns: a dict containing the return of :py:meth:`DIRAC.Core.Security.X509Chain.X509Chain.getCredentials`
                (not a DIRAC structure !)
    """
    credDict = {}

    # Authorization type
    self.__authGrant = self.get_cookie('authGrant', 'Certificate')

    # Unsecure protocol only for visitors
    if self.request.protocol == "https":

      # if self.__authGrant == 'Session':
      #   # read session
      #   credDict = self.__readSession(self.get_secure_cookie('session_id'))

      # elif self.request.headers.get("Authorization"):
      #   # read token
      #   credDict = self.__readToken()

      if self.__authGrant == 'Certificate':
        try:
          # try read certificate
          if Conf.balancer() == "nginx":
            credDict = self.__readCertificateFromNginx()
          else:
            credDict = super(WebHandler, self)._gatherPeerCredentials()
          # Add a group if it present in the request path
          if self.__group:
            credDict['validGroup'] = False
            credDict['group'] = self.__group
        except Exception as e:
          sLog.warn(str(e))

    return credDict

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

  def get(self, *args, **kwargs):
    self.post(*args, **kwargs)
