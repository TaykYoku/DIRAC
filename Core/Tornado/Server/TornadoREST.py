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
    return self._tornadoMethodArgs
