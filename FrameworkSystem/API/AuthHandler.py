""" Handler to provide REST APIs to manage user authentication.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import re
from time import time
from pprint import pprint

from tornado import web, gen, template
from tornado.template import Template
from tornado.escape import json_decode
from authlib.common.security import generate_token
from authlib.jose import jwt

from DIRAC.Core.Utilities.JEncode import encode

from DIRAC import S_OK, S_ERROR, gConfig, gLogger
from DIRAC.Core.Tornado.Server.WebHandler import WebHandler, asyncGen, WErr
from DIRAC.FrameworkSystem.Client.AuthManagerClient import gSessionManager
from DIRAC.FrameworkSystem.Client.ProxyManagerClient import gProxyManager
from DIRAC.FrameworkSystem.Client.NotificationClient import NotificationClient
from DIRAC.ConfigurationSystem.Client.Helpers.Resources import getProvidersForInstance
from DIRAC.ConfigurationSystem.Client.Helpers.CSGlobals import getSetup


__RCSID__ = "$Id$"

from authlib.oauth2.rfc8628 import (
    DeviceAuthorizationEndpoint as _DeviceAuthorizationEndpoint,
    DeviceCodeGrant as _DeviceCodeGrant,
    DeviceCredentialDict,
)
from authlib.oauth2.rfc7636 import (
    create_s256_code_challenge,
)


class AuthHandler(WebHandler):
  LOCATION = "/DIRAC/auth"
  METHOD_PREFIX = "web_"

  @classmethod
  def initializeHandler(cls):
    """ This method is called only one time, at the first request.
    """
    print('---->> initializeHandler')

  #path_oauth = ['([A-z]+)', '([0-9]*)']  # mapped to fn(a, b=None):
  #method_oauth = ['post', 'get']
  @asyncGen
  def web_register(self):
    """ Device authorization flow

        POST: /device?client_id= &scope=
    """
    if self.request.method == 'POST':
      result = yield self.threadTask(gSessionManager.addClient, self.request.arguments)
      if not result['OK']:
        raise WErr(503, result['Message'])
      self.finish(result['Value'])

  path_device = ['([A-z0-9]*)']
  @asyncGen
  def web_device(self, userCode=None):
    """ Device authorization flow

        POST: /device?client_id= &scope=
        group
        provider
    """
    userCode = self.get_argument('user_code', userCode)
    if self.request.method == 'POST':
      data = {'client_id': self.get_argument('client_id')}
      client = yield self.threadTask(gSessionManager.getClient, data['client_id'])
      if not client:
        raise WErr(401, 'Client ID is unregistred.')
      data['expires_in'] = 300
      data['expires_at'] = int(time()) + data['expires_in']
      data['device_code'] = generate_token(20)
      data['user_code'] = generate_token(10)
      data['scope'] = self.get_argument('scope', '')
      data['group'] = self.get_argument('group', None)
      data['Provider'] = self.get_argument('provider', None)
      data['interval'] = 5
      data['verification_uri'] = 'https://marosvn32.in2p3.fr/DIRAC/auth/device'
      data['verification_uri_complete'] = 'https://marosvn32.in2p3.fr/DIRAC/auth/device/%s' % data['user_code']
      # return DeviceCredentialDict(data)
      gSessionManager.addSession(data['device_code'], data)
      self.finish(data)
    elif self.request.method == 'GET':
      if userCode:
        session, data = gSessionManager.getSessionByOption('user_code', userCode)
        if not session:
          raise WErr(404, 'Session expired.')
        authURL = 'https://marosvn32.in2p3.fr/DIRAC/auth/authorization'
        if data.get('Provider'):
          authURL += '/%s' % data['Provider']
        authURL += '?response_type=device&user_code=%s&client_id=%s' % (userCode, data['client_id'])
        self.redirect(authURL)
      else:
        t = template.Template('''<!DOCTYPE html>
        <html>
          <head>
            <title>Authetication</title>
            <meta charset="utf-8" />
          </head>
          <body>
            <form id="user_code_form" onsubmit="verification_uri_complete()">
              <input type="text" id="user_code" name="user_code">
              <button type="submit" id="submit">Submit</button>
            </form>
            <script>
              function verification_uri_complete(){
                var form = document.getElementById('user_code_form');
                form.action = "{{url}}/" + document.getElementById('user_code').value + "{{query}}";
              }
            </script>
          </body>
        </html>''')
        self.finish(t.generate(url=self.request.protocol + "://" + self.request.host + self.request.path,
                               query='?' + self.request.query))

  path_authorization = ['([A-z0-9]*)']
  @asyncGen
  def web_authorization(self, idP=None):
    """ Authorization endpoint

        GET: /authorization/< DIRACs IdP >?client_id=.. &response_type=(code|device)

        Device flow:
          &user_code=..                         (required)

        Authentication code flow:
          &state=..                             (main session id, optional)
          &code_challenge=..                    (PKCE, optional)
          &code_challenge_method=(pain|S256)    ('pain' by default, optional)


    """
    # Only GET method supported
    if self.request.method != 'GET':
      raise WErr(404, '%s request method not supported.' % self.request.method)
    self.log.info('web_authorization: %s' % self.request)
    
    # Check client
    client = yield self.threadTask(gSessionManager.getClient, self.get_argument('client_id'))
    if not client:
      raise WErr(404, 'Client ID is unregistred.')
    
    # Research supported IdPs
    result = getProvidersForInstance('Id')
    if not result['OK']:
      raise WErr(503, result['Message'])
    idPs = result['Value']
    if not idP:

      # Choose IdP
      t = template.Template('''<!DOCTYPE html>
      <html>
        <head>
          <title>Authetication</title>
          <meta charset="utf-8" />
        </head>
        <body>
          <ul>
            {% for idP in idPs %}
              <li> <a href="{{url}}/{{idP}}{{query}}">{{idP}}</a> </li>
            {% end %}
          <ul>
        </body>
      </html>''')
      self.finish(t.generate(url=self.request.protocol + "://" + self.request.host + self.request.path,
                             query='?' + self.request.query, idPs=idPs))
    else:

      # Check IdP
      if idP not in idPs:
        raise WErr(503, 'Provider not exist.')

      flow = self.get_argument('response_type')

      # Authorization code flow
      if flow == 'code':
        session = self.get_argument('state', generate_token(10))
        sessionDict = {}
        codeChallenge = self.get_argument('code_challenge', None)
        if codeChallenge:
          sessionDict['code_challenge'] = codeChallenge
          sessionDict['code_challenge_method'] = self.get_argument('code_challenge_method', 'pain')
        gSessionManager.addSession(session, sessionDict)
      
      # Device flow
      elif flow == 'device':
        session, _ = gSessionManager.getSessionByOption('user_code', self.get_argument('user_code'))
        if not session:
          raise WErr(404, 'Session expired.')

      # Submit second auth flow through IdP
      result = gSessionManager.submitAuthorizeFlow(idP, session)
      if not result['OK']:
        raise WErr(503, result['Message'])
      self.log.notice('Redirect to', result['Value'])
      self.redirect(result['Value'])

  @asyncGen
  def web_redirect(self):
    # Redirect endpoint for response
    self.log.info('REDIRECT RESPONSE:\n', self.request)

    # Try to catch errors
    error = self.get_argument('error', None)
    if error:
      description = self.get_argument('error_description', '')
      raise WErr(500, '%s session crashed with error:\n%s\n%s' % (session, error,
                                                                  description))

    # Try to parse session id
    session = self.get_argument('state', None)

    # Parse result of the second authentication flow
    self.log.info(session, 'session, parsing authorization response %s' % self.get_arguments)
    result = gSessionManager.parseAuthResponse(self.request, session)
    if not result['OK']:
      raise WErr(503, result['Message'])
    username, userID, groupStatuses, mainSession = result['Value']

    # researche Group
    sessionDict = gSessionManager.getSession(mainSession)
    reqGroup = self.get_argument('group', sessionDict.get('group'))
    if not reqGroup:
      return self.finish('You need to choose group')
      
      # self.__chooseGroup(session, groupStatuses)
    pprint(groupStatuses)
    thisGroup = groupStatuses.get(reqGroup)
    if not thisGroup:
      return self.finish('Wrone group')
    
    elif thisGroup['Status'] == 'needToAuth':
      
      # Submit second auth flow through IdP
      result = gSessionManager.submitAuthorizeFlow(thisGroup['Action'][1][0], mainSession)
      if not result['OK']:
        raise WErr(503, result['Message'])
      self.log.notice('Redirect to', result['Value'])
      return self.redirect(result['Value'])
    
    elif thisGroup['Status'] not in ['ready', 'unknown']:
      return self.finish('Bad group status')

    # Create DIRAC access token for username/group
    reuslt = self.__getAccessToken(userID, reqGroup, mainSession)
    print(result)
    if not result['OK']:
      raise WErr(503, result['Message'])
    gSessionManager.updateSession(mainSession, Status='authed', Token=result['Value'])
    print('---- Token ---')
    print(result['Value'])

    # Device flow
    if 'device_code' in sessionDict:
      t = template.Template('''<!DOCTYPE html>
      <html>
        <head>
          <title>Authetication</title>
          <meta charset="utf-8" />
        </head>
        <body>
          <script type="text/javascript"> window.close() </script>
        </body>
      </html>''')
      return self.finish(t.generate())

    # Authorization code flow
    elif sessionDict['grant'] == 'code':
      if 'code_challenge' in sessionDict:
        # code = Create JWS
        pass
      else:
        code = generate_token(10)
        requests.get(sessionDict['redirect_uri'], {'code': code, 'state': session})
      gSessionManager.updateSession(session, code=code)
      return self.finish({'code': code, 'state': session})

  @asyncGen
  def web_token(self):
    # Support only POST method
    if self.request.method != 'POST':
      raise

    # Check client
    client = yield self.threadTask(gSessionManager.getClient, self.get_argument('client_id'))
    if not client:
      raise

    grantType = self.get_argument('grant_type')

    # Device flow
    if grantType == 'device_code':
      session, data = gSessionManager.getSessionByOption('device_code', self.get_argument('device_code'))
      if not session:
        print('=====>> %s' % gSessionManager.getSession())
        raise 

      # Waiting IdP auth result
      if data['Status'] not in ['authed', 'failed']:
        self.finish('Status: %s Wait..' % data['Status'])
        return
    
    # Authentication code flow
    elif grantType == 'authorization_code':
      session, data = gSessionManager.getSessionByOption('code', self.get_argument('code'))
      if not session:
        raise

      # Check client params
      if self.get_argument('redirect_uri') != client['redirect_uri']:
        raise
      if data['code_challenge_method']:
        codeVerifier = self.get_argument('code_verifier')
        if data['code_challenge_method'] == 'S256':
          codeVerifier = create_s256_code_challenge(codeVerifier)
        if codeVerifier != data['code_challenge']:
          raise WErr(404, 'code_verifier is not correct.')

    # Remove session and return DIRAC access token
    print('remove session')
    gSessionManager.removeSession(session)
    pprint(data)
    if data['Status'] != 'authed':
      raise WErr(401, data['Comment'])
    self.finish(encode(data['Token']))

  def __getAccessToken(self, uid, group, session):
    print('GENERATE ACCESS TOKEN')
    header = {'alg': 'RS256'}
    payload = {'sub': uid,
               'grp': group,
               'iss': getSetup(),
               'exp': 12 * 3600}
    # Read private key of DIRAC auth service
    with open('/opt/dirac/etc/grid-security/jwtRS256.key', 'r') as f:
      key = f.read()
    # Need to use enum==0.3.1 for python 2.7
    return S_OK({'access_token': jwt.encode(header, payload, key),
                 'token_type': 'Baerer',
                 'expires_at': 12 * 3600,
                 'state': session})
