""" Handler to provide REST APIs to manage user authentication.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import re
import json
from pprint import pprint

from tornado import web, gen, template
from tornado.escape import json_decode
from tornado.template import Template

from authlib.jose import jwk, jwt
# from authlib.jose import JsonWebKey
from authlib.oauth2.base import OAuth2Error
from authlib.common.security import generate_token

from DIRAC import S_OK, S_ERROR, gConfig, gLogger
# from DIRAC.Core.Tornado.Server.WebHandler import WebHandler, asyncGen, WErr
from DIRAC.Core.Web.WebHandler import WebHandler, asyncGen, WErr
from DIRAC.FrameworkSystem.private.authorization.utils import ClientRegistrationEndpoint
from DIRAC.FrameworkSystem.private.authorization.grants import DeviceAuthorizationEndpoint
from DIRAC.FrameworkSystem.Client.ProxyManagerClient import gProxyManager
from DIRAC.ConfigurationSystem.Client.Helpers import Registry
from DIRAC.ConfigurationSystem.Client.Helpers.Resources import getProvidersForInstance


__RCSID__ = "$Id$"


class AuthHandler(WebHandler):
  AUTH_PROPS = 'all'
  LOCATION = "/auth" #"/DIRAC/auth"
  METHOD_PREFIX = "web_"

  # def initializeRequest(self):
  #   self.server = self.application.authorizationServer
  
  def initialize(self):
    super(AuthHandler, self).initialize()
    pprint(self.application.settings)
    
    self.server = self.application._authServer #self.application.settings['authorizationServer']

  path_index = ['.well-known/(oauth-authorization-server|openid-configuration)']
  def web_index(self, instance):
    """ Well known endpoint

        GET: /.well-known/openid-configuration
        GET: /.well-known/oauth-authorization-server
    """
    if self.request.method == "GET":
      self.finish(dict(self.server.metadata))

  def web_jwk(self):
    """ JWKs
    """
    if self.request.method == "GET":
      with open('/opt/dirac/etc/grid-security/jwtRS256.key.pub', 'rb') as f:
        key = f.read()
      # key = JsonWebKey.import_key(key, {'kty': 'RSA'})
      self.finish({'keys': [jwk.dumps(key, kty='RSA', alg='RS256')]})
      # self.finish(key.as_dict())
  
  def web_userinfo(self):
    self.finish(self.__validateToken())

  @asyncGen
  def web_register(self):
    """ Client registry

        POST: /registry?client_id=.. &scope=.. &redirect_uri=..
    """
    name = ClientRegistrationEndpoint.ENDPOINT_NAME
    r = yield self.threadTask(self.server.create_endpoint_response, name, self.request)
    self.__finish(*r)

  path_device = ['([A-z0-9-_]*)']
  @asyncGen
  def web_device(self, userCode=None):
    """ Device authorization flow

        POST: /device?client_id=.. &scope=..
          # group - optional
          provider - optional
        
        GET: /device/<user code>
    """
    if self.request.method == 'POST':
      name = DeviceAuthorizationEndpoint.ENDPOINT_NAME
      r = yield self.threadTask(self.server.create_endpoint_response, name, self.request)
      self.__finish(*r)

    elif self.request.method == 'GET':
      userCode = self.get_argument('user_code', userCode)
      if userCode:
        session, data = self.server.getSessionByOption('user_code', userCode)
        if not session:
          self.finish('%s authorization session expired.' % session)
          return
        authURL = self.server.metadata['authorization_endpoint']
        authURL += '?%s&client_id=%s&user_code=%s' % (data['request'].query,
                                                      data['client_id'], userCode)
        self.redirect(authURL)
        return
      
      t = template.Template('''<!DOCTYPE html>
      <html>
        <head>
          <title>Authentication</title>
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
  def web_authorization(self, provider=None):
    """ Authorization endpoint

        GET: /authorization/< DIRACs IdP >?client_id=.. &response_type=(code|device)&scope=..      #group=..

        Device flow:
          &user_code=..                         (required)

        Authentication code flow:
          &scope=..                             (optional)
          &redirect_uri=..                      (optional)
          &state=..                             (main session id, optional)
          &code_challenge=..                    (PKCE, optional)
          &code_challenge_method=(pain|S256)    ('pain' by default, optional)
    """
    print('=== Sessions ===')
    pprint(self.server.getSessions())
    print('----------------')
    if self.request.method == 'GET':
      try:
        # grant = yield self.threadTask(self.server.validate_consent_request, self.request, None)
        grant = self.server.validate_consent_request(self.request, None)
        # grant.validate_authorization_request()
        # validate_code_authorization_request(grant)
        # validate_authorization_redirect_uri(request, client)
        # 
      except OAuth2Error as error:
        self.finish("%s</br>%s" % (error.error, error.description))
        return

    # Research supported IdPs
    result = getProvidersForInstance('Id')
    if not result['OK']:
      raise WErr(503, result['Message'])
    idPs = result['Value']

    idP = self.get_argument('provider', provider)
    if not idP:
      # Choose IdP
      t = template.Template('''<!DOCTYPE html>
      <html>
        <head>
          <title>Authentication</title>
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
      return
    print('=== Sessions ===')
    pprint(self.server.getSessions())
    print('----------------')
    # Check IdP
    if idP not in idPs:
      self.finish('%s is not registered in DIRAC.' % idP)
      return

    # Use here grant
    # flow = self.get_argument('response_type')
    # session = self.get_argument('state'), generate_token(10))

    # Submit second auth flow through IdP
    result = self.server.getIdPAuthorization(idP, self.get_argument('state')) # session)
    if not result['OK']:
      raise WErr(503, result['Message'])
    self.log.notice('Redirect to', result['Value'])
    print('=== Sessions ===')
    pprint(self.server.getSessions())
    print('----------------')
    self.redirect(result['Value'])

  @asyncGen
  def web_redirect(self):
    # Redirect endpoint for response
    self.log.info('REDIRECT RESPONSE:\n', self.request)
    print('=== Sessions ===')
    pprint(self.server.getSessions())
    print('----------------')
    # Try to catch errors
    error = self.get_argument('error', None)
    if error:
      description = self.get_argument('error_description', '')
      self.finish('%s session crashed with error:\n%s\n%s' % (session, error, description))
      return

    # Try to parse IdP session id
    # session = self.get_argument('session', self.get_argument('state', None))
    session = self.get_argument('state')

    # Added group
    choosedScope = self.get_arguments('chooseScope', None)
    if not choosedScope:
      # Parse result of the second authentication flow
      self.log.info(session, 'session, parsing authorization response %s' % self.get_arguments)
      result = yield self.threadTask(self.server.parseIdPAuthorizationResponse, self.request, session)
      if not result['OK']:
        raise WErr(503, result['Message'])
      # Return main session flow
      session = result['Value']

    # Main session metadata
    print('MAIN SESSION: %s' % session)
    print('=== Sessions ===')
    pprint(self.server.getSessions())
    print('----------------')
    sessionDict = self.server.getSession(session)
    pprint(sessionDict)
    username = sessionDict['username']
    request = sessionDict['request']    
    userID = sessionDict['userID']

    if choosedScope:
      # Modify scope in main session
      scopes = request.data['scope'].split()
      scopes.extend(choosedScope)
      request.data['scope'] = ' '.join(list(set(scopes)))
      self.server.updateSession(session, request=request)

    #group = sessionDict.get('group')

    # Search groups in scope
    # scopes = list(set(request.args['scope']) + set(choosedScope))
    groups = [(s.split(':')[1]) for s in request.data['scope'] if s.startswith('g:')]

    # Researche Group
    result = gProxyManager.getGroupsStatusByUsername(username, groups)
    if not result['OK']:
      self.server.updateSession(session, Status='failed', Comment=result['Message'])
      self.finish(result['Message'])
      return
    groupStatuses = result['Value']
    print('======= Group STATUSES:')
    pprint(groupStatuses)

    # reqGroup = self.get_argument('group', group)
    # if not reqGroup:
    if not groups:
      t = template.Template('''<!DOCTYPE html>
      <html>
        <head>
          <title>Authentication</title>
          <meta charset="utf-8" />
        </head>
        <body>
          Please choose group:
          <ul>
            {% for group, data in groups.items() %}
              <li> <a href="{{url}}?state={{session}}&chooseScope=g:{{group}}">{{group}}</a>
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
      # query = '%s&session=%s' % (self.request.query, session)
      self.finish(t.generate(url=url, session=session, groups=groupStatuses))
      return

    pprint(groupStatuses)
    for group in groups:
      status = groupStatuses[group]['Status']
      action = groupStatuses[group].get('Action')

      # thisGroup = groupStatuses.get(reqGroup)
      # if not thisGroup:
      #   self.finish('%s - wrone group for %s user.' % (reqGroup, username))
      #   return
    
      if status == 'needToAuth':
        # Submit second auth flow through IdP
        idP = action[1][0]
        result = self.server.getIdPAuthorization(idP, session)
        if not result['OK']:
          raise WErr(503, result['Message'])
        self.log.notice('Redirect to', result['Value'])
        self.redirect(result['Value'])
        return
      if status not in ['ready', 'unknown']:
        self.finish('%s - bad group status' % status)
        return

    # self.server.updateSession(session, Status='authed')

    ###### RESPONSE
    self.__finish(*self.server.create_authorization_response(request, username))

  @asyncGen
  def web_token(self):
    self.__finish(*self.server.create_token_response(self.request))
  
  def __finish(self, data, code, headers):
    self.set_status(code)
    for header in headers:
      self.set_header(*header)
    self.finish(data)

  def __validateToken(self):
    """ Load client certchain in DIRAC and extract informations.

        The dictionary returned is designed to work with the AuthManager,
        already written for DISET and re-used for HTTPS.

        :returns: a dict containing the return of :py:meth:`DIRAC.Core.Security.X509Chain.X509Chain.getCredentials`
                  (not a DIRAC structure !)
    """
    auth = self.request.headers.get("Authorization")
    credDict = {}
    if not auth:
      raise WErr(401, 'Unauthorize')
    # If present "Authorization" header it means that need to use another then certificate authZ
    authParts = auth.split()
    authType = authParts[0]
    if len(authParts) != 2 or authType.lower() != "bearer":
      raise Exception("Invalid header authorization")
    token = authParts[1]
    # Read public key of DIRAC auth service
    with open('/opt/dirac/etc/grid-security/jwtRS256.key.pub', 'rb') as f:
      key = f.read()
    # Get claims and verify signature
    claims = jwt.decode(token, key)
    # Verify token
    claims.validate()
    result = Registry.getUsernameForID(claims.sub)
    if not result['OK']:
      raise Exception("User is not valid.")
    claims['username'] = result['Value']
    return claims