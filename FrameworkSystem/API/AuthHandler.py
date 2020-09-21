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

from authlib.oauth2.base import OAuth2Error
from authlib.common.security import generate_token
from authlib.jose import jwt
from authlib.oauth2 import OAuth2Request

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
    """ Client registry

        POST: /registry?client_id=.. &scope=.. &redirect_uri=..
    """
    self.server = self.application.authorizationServer
    if self.request.method == 'POST':
      result = yield self.threadTask(self.server.addClient, self.request.arguments)
      # result = yield self.threadTask(gSessionManager.addClient, self.request.arguments)
      if not result['OK']:
        raise WErr(503, result['Message'])
      self.finish(result['Value'])

  path_device = ['([A-z0-9]*)']
  @asyncGen
  def web_device(self, userCode=None):
    """ Device authorization flow

        POST: /device?client_id=.. &scope=..
          group - optional
          provider - optional
        
        GET: /device/<user code>
    """
    self.server = self.application.authorizationServer
    userCode = self.get_argument('user_code', userCode)
    if self.request.method == 'POST':
      data = {}
      data['flow'] = 'device'
      data['client_id'] = self.get_argument('client_id')
      client = yield self.threadTask(gSessionManager.getClient, data['client_id'])
      if not client:
        raise WErr(401, 'Client ID is unregistred.')
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

        GET: /authorization/< DIRACs IdP >?client_id=.. &response_type=(code|device)&group=..

        Device flow:
          &user_code=..                         (required)

        Authentication code flow:
          &scope=..                             (optional)
          &redirect_uri=..                      (optional)
          &state=..                             (main session id, optional)
          &code_challenge=..                    (PKCE, optional)
          &code_challenge_method=(pain|S256)    ('pain' by default, optional)


    """
    self.server = self.application.authorizationServer
    if self.request.method == 'GET':
      try:
        # HERE WE CHECK CLIENTS
        grant = self.server.validate_consent_request(self.request, end_user=None)
            ##### 1
            # def validate_consent_request(self, request, end_user=None):
            #   """Validate current HTTP request for authorization page. This page is designed for resource owner to grant or deny the authorization::
            #       class AuthorizationHandler(RequestHandler)
            #         def get():
            #           try:
            #             grant = server.validate_consent_request(self.request, end_user=current_user)
            #             self.render('authorize.html', grant=grant, user=current_user)
            #           except OAuth2Error as error:
            #             self.render('error.html', error=error)
            #   """
            #   req = self.create_oauth2_request(request)
            #   req.user = end_user
            #   grant = self.get_authorization_grant(req)
            #   grant.validate_consent_request()
            #   if not hasattr(grant, 'prompt'):
            #       grant.prompt = None
            #   return grant
            ###########################################################
                ##### 1.1
                # def get_authorization_grant(self, request):
                #   """Find the authorization grant for current request.
                #   :param request: OAuth2Request instance.
                #   :return: grant instance
                #   """
                #   for (grant_cls, extensions) in self._authorization_grants:
                #       if grant_cls.check_authorization_endpoint(request):
                #           return _create_grant(grant_cls, extensions, request, self)
                #   raise InvalidGrantError(
                #       'Response type {!r} is not supported'.format(request.response_type))
                #####################
                  ##### 1.1.1
                  # def check_authorization_endpoint(cls, request):
                  #   return request.response_type in cls.RESPONSE_TYPES
                  ##### 1.1.2
                  # def _create_grant(grant_cls, extensions, request, server):
                  #   grant = grant_cls(request, server)
                  #   if extensions:
                  #       for ext in extensions:
                  #           ext(grant)
                  #   return grant
                ##### 1.2
                # def validate_code_authorization_request(grant):
                #   client_id = grant.request.client_id
                #   log.debug('Validate authorization request of %r', client_id)

                #   if client_id is None:
                #       raise InvalidClientError(state=grant.request.state)

                #   client = grant.server.query_client(client_id)
                #   if not client:
                #       raise InvalidClientError(state=grant.request.state)

                #   redirect_uri = grant.validate_authorization_redirect_uri(grant.request, client)
                #   response_type = grant.request.response_type
                #   if not client.check_response_type(response_type):
                #       raise UnauthorizedClientError(
                #           'The client is not authorized to use '
                #           '"response_type={}"'.format(response_type),
                #           state=grant.request.state,
                #           redirect_uri=redirect_uri,
                #       )

                #   try:
                #       grant.request.client = client
                #       grant.validate_requested_scope()
                #       grant.execute_hook('after_validate_authorization_request')
                #   except OAuth2Error as error:
                #       error.redirect_uri = redirect_uri
                #       raise error
                #   return redirect_uri
      except OAuth2Error as error:
        print(error.error)
        print(error.description)
        self.finish(error.error)
        return
      # HERE WE CHOSSE IDP (POST) AND AUTH
    #   return render_template('authorize.html', user=user, grant=grant)


    # if not user and 'username' in request.form:
    #     username = request.form.get('username')
    #     user = User.query.filter_by(username=username).first()
    # if request.form['confirm']:
    #     grant_user = user
    # else:
    #     grant_user = None
    

    # ORIGINAL
    #################
    # # Only GET method supported
    # if self.request.method != 'GET':
    #   raise WErr(404, '%s request method not supported.' % self.request.method)
    # self.log.info('web_authorization: %s' % self.request)
    
    # # Check client
    # client = yield self.threadTask(gSessionManager.getClient, self.get_argument('client_id'),
    #                                {'redirect_uri': self.get_argument('redirect_uri', None)})
    # if not client:
    #   raise WErr(404, 'Client ID is unregistred.')
    #################


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
        sessionDict['flow'] = flow
        sessionDict['redirect_uri'] = client['redirect_uri']
        sessionDict['group'] = self.get_argument('group', None)
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
    self.server = self.application.authorizationServer
    # Redirect endpoint for response
    self.log.info('REDIRECT RESPONSE:\n', self.request)

    # Try to catch errors
    error = self.get_argument('error', None)
    if error:
      description = self.get_argument('error_description', '')
      raise WErr(500, '%s session crashed with error:\n%s\n%s' % (session, error,
                                                                  description))

    # Try to parse IdP session id
    session = self.get_argument('session', self.get_argument('state', None))

    choosedGroup = self.get_argument('chooseGroup', None)
    if choosedGroup:
      gSessionManager.updateSession(session, group=choosedGroup)
    else:
      # Parse result of the second authentication flow
      self.log.info(session, 'session, parsing authorization response %s' % self.get_arguments)
      result = yield self.threadTask(gSessionManager.parseAuthResponse, self.request, session)
      if not result['OK']:
        raise WErr(503, result['Message'])
      # Return main session flow
      session = result['Value']

    sessionDict = gSessionManager.getSession(session)
    username = sessionDict['username']
    profile = sessionDict['profile']
    userID = sessionDict['userID']

    # Researche Group
    result = gProxyManager.getGroupsStatusByUsername(username)
    if not result['OK']:
      gSessionManager.updateSession(session, Status='failed', Comment=result['Message'])
      self.finish(result['Message'])
      return
    groupStatuses = result['Value']

    reqGroup = self.get_argument('group', sessionDict.get('group'))
    if not reqGroup:
      t = template.Template('''<!DOCTYPE html>
      <html>
        <head>
          <title>Authetication</title>
          <meta charset="utf-8" />
        </head>
        <body>
          Please choose group:
          <ul>
            {% for group, data in groups.items() %}
              <li> <a href="{{url}}?{{query}}&chooseGroup={{group}}">{{group}}</a>
                : {{data['Status']}} </br>
                {{data['Comment']}} </br>
                {% if data.get('Action', '') %}
                  {{data['Action'][0]}} : {{data['Action'][1][0]}}
                {% end %}
              </li>
            {% end %}
          <ul>
        </body>
      </html>''')
      url = self.request.protocol + "://" + self.request.host + self.request.path
      query = '%s&session=%s' % (self.request.query, session)
      self.finish(t.generate(url=url, query=query, groups=groupStatuses))
      return

    pprint(groupStatuses)
    thisGroup = groupStatuses.get(reqGroup)
    if not thisGroup:
      self.finish('%s - wrone group for %s user.' % (reqGroup, username))
      return
    
    elif thisGroup['Status'] == 'needToAuth':
      
      # Submit second auth flow through IdP
      result = gSessionManager.submitAuthorizeFlow(thisGroup['Action'][1][0], session)
      if not result['OK']:
        raise WErr(503, result['Message'])
      self.log.notice('Redirect to', result['Value'])
      self.redirect(result['Value'])
      return
    
    elif thisGroup['Status'] not in ['ready', 'unknown']:
      self.finish('%s - bad group status' % thisGroup['Status'])
      return

    # Create DIRAC access token for username/group
    result = self.__getAccessToken(userID, reqGroup, session)
    print(result)
    if not result['OK']:
      raise WErr(503, result['Message'])
    gSessionManager.updateSession(session, Status='authed', Token=result['Value'])
    print('---- Token ---')
    print(result['Value'])

    ###### RESPONSE
    # return authorization.create_authorization_response(grant_user=grant_user)
    ###### RESPONSE

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
      self.finish(t.generate())
      return

    # Authorization code flow
    elif sessionDict['flow'] == 'code':
      if 'code_challenge' in sessionDict:
        # code = Create JWS ?
        code = generate_token(10)
      else:
        code = generate_token(10)
        self.redirect('%s?code=%s&state=%s' % (sessionDict['redirect_uri'], code, state))
        return
      gSessionManager.updateSession(session, code=code)
      self.finish({'code': code, 'state': session})

  @asyncGen
  def web_token(self):
    self.server = self.application.authorizationServer
    # Support only POST method
    if self.request.method != 'POST':
      raise

    grant = self.get_argument('grant_type')

    # Check client
    kwargs = {}
    if grant == 'authorization_code':
      kwargs['redirect_uri'] = self.get_argument('redirect_uri')
    client = yield self.threadTask(gSessionManager.getClient, self.get_argument('client_id'), kwargs)
    if not client:
      raise

    # Device flow
    if grant == 'device_code':
      #### it can be jws
      session, data = gSessionManager.getSessionByOption('device_code', self.get_argument('device_code'))
      if not session:
        raise 

      # Waiting IdP auth result
      if data['Status'] not in ['authed', 'failed']:
        self.finish('Status: %s Wait..' % data['Status'])
        return
    
    # Authentication code flow
    elif grant == 'authorization_code':
      #### it can be jws
      session, data = gSessionManager.getSessionByOption('code', self.get_argument('code'))
      if not session:
        self.finish('%s session expired.' % session)
        return

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
  
  # def __createOAuth2Request(self):
  #   return OAuth2Request(self.request.method, self.request.uri,
  #                        json_decode(self.request.body), self.request.headers)
