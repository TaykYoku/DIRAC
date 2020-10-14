from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from authlib.oauth2 import OAuth2Request as _OAuth2Request

__RCSID__ = "$Id$"


def createOAuth2Request(self, request, method_cls=OAuth2Request, use_json=False):
  if isinstance(request, method_cls):
    return request
  if isinstance(request, dict):
    return method_cls(request['method'], request['uri'],
                      request.get('body'), request.get('headers'))
  if use_json:
    body = json_decode(request.body)
  else:
    body = {}
    for k, v in request.body_arguments.items():
      body[k] = ' '.join(v)
  m = method_cls(request.method, request.uri, body, request.headers)
  return method_cls(request.method, request.uri, body, request.headers)


class OAuth2Request(_OAuth2Request):
  def toDict(self):
    return {'method': self.method,
            'uri': self.uri,
            'body': self.body,
            'headers': self.headers}