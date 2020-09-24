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

from authlib.oauth2.base import OAuth2Error
from authlib.common.security import generate_token
from authlib.oauth2.rfc8414 import get_well_known_url

from DIRAC import S_OK, S_ERROR, gConfig, gLogger
from DIRAC.Core.Tornado.Server.WebHandler import WebHandler, asyncGen, WErr
from DIRAC.FrameworkSystem.API.AuthServer import DeviceAuthorizationEndpoint, ClientRegistrationEndpoint
from DIRAC.FrameworkSystem.Client.ProxyManagerClient import gProxyManager
from DIRAC.ConfigurationSystem.Client.Helpers.Resources import getProvidersForInstance


__RCSID__ = "$Id$"


class AuthHandler(WebHandler):
  LOCATION = "/DIRAC/auth"
  METHOD_PREFIX = "web_"

  path_index = ['/.well-known/oauth-authorization-server']
  def web_index(self):
    """ Well known endpoint

        GET: /.well-known/oauth-authorization-server
    """
    if self.request.method == "GET":
      self.finish(json.dumps(self.application.authorizationServer.metadata))

  @asyncGen
  def web_register(self):
    """ Client registry

        POST: /registry?client_id=.. &scope=.. &redirect_uri=..
    """
    self.server = self.application.authorizationServer

    name = ClientRegistrationEndpoint.ENDPOINT_NAME
    data, code, headers = yield self.threadTask(self.server.create_endpoint_response, name, self.request)
    self.set_status(code)
    for header in headers:
      self.set_header(*header)
    self.finish(data)

  path_device = ['([A-z0-9-_]*)']
  @asyncGen
  def web_device(self, userCode=None):
    """ Device authorization flow

        POST: /device?client_id=.. &scope=..
          group - optional
          provider - optional
        
        GET: /device/<user code>
    """
    self.server = self.application.authorizationServer

    if self.request.method == 'POST':
      name = DeviceAuthorizationEndpoint.ENDPOINT_NAME
      data, code, headers = yield self.threadTask(self.server.create_endpoint_response, name, self.request)
      self.set_status(code)
      for header in headers:
        self.set_header(*header)
      self.finish(data)

    elif self.request.method == 'GET':
      userCode = self.get_argument('user_code', userCode)
      if userCode:
        session, data = self.server.getSessionByOption('user_code', userCode)
        if not session:
          self.finish('Session expired.')
          return
        authURL = self.server.metadata['authorization_endpoint']
        authURL += '?%s&client_id=%s&user_code=%s' % (data['request'].query,
                                                      data['client_id'], userCode)
        self.redirect(authURL)
        return
      
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
  def web_authorization(self, provider=None):
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
        grant = yield self.threadTask(self.server.validate_consent_request, self.request, None)
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
      return

    # Check IdP
    if idP not in idPs:
      self.finish('%s is not registered in DIRAC.' % idP)
      return

    # Use here grant
    flow = self.get_argument('response_type')
    session = self.get_argument('state', generate_token(10))
    # Authorization code flow
    if flow == 'code':
      sessionDict = {}
      sessionDict['request'] = self.request
      # sessionDict['flow'] = flow
      sessionDict['client_id'] = self.get_argument('client_id')
      sessionDict['group'] = self.get_argument('group', None)
      codeChallenge = self.get_argument('code_challenge', None)
      if codeChallenge:
        sessionDict['code_challenge'] = codeChallenge
        sessionDict['code_challenge_method'] = self.get_argument('code_challenge_method', 'pain')
      self.server.addSession(session, **sessionDict)

    # Submit second auth flow through IdP
    result = self.server.getIdPAuthorization(idP, session)
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
      self.finish('%s session crashed with error:\n%s\n%s' % (session, error, description))
      return

    # Try to parse IdP session id
    session = self.get_argument('session', self.get_argument('state', None))

    # Added group
    choosedGroup = self.get_argument('chooseGroup', None)
    if choosedGroup:
      self.server.updateSession(session, group=choosedGroup)
    else:
      # Parse result of the second authentication flow
      self.log.info(session, 'session, parsing authorization response %s' % self.get_arguments)
      result = yield self.threadTask(self.server.parseIdPAuthorizationResponse, self.request, session)
      if not result['OK']:
        raise WErr(503, result['Message'])
      # Return main session flow
      session = result['Value']

    # Main session metadata
    sessionDict = self.server.getSession(session)
    username = sessionDict['username']
    request = sessionDict['request']    
    userID = sessionDict['userID']
    group = sessionDict.get('group')

    # Researche Group
    result = gProxyManager.getGroupsStatusByUsername(username)
    if not result['OK']:
      self.server.updateSession(session, Status='failed', Comment=result['Message'])
      self.finish(result['Message'])
      return
    groupStatuses = result['Value']

    reqGroup = self.get_argument('group', group)
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
      idP = thisGroup['Action'][1][0]
      result = self.server.getIdPAuthorization(idP, session)
      if not result['OK']:
        raise WErr(503, result['Message'])
      self.log.notice('Redirect to', result['Value'])
      self.redirect(result['Value'])
      return
    
    elif thisGroup['Status'] not in ['ready', 'unknown']:
      self.finish('%s - bad group status' % thisGroup['Status'])
      return

    # self.server.updateSession(session, Status='authed')

    ###### RESPONSE
    data, code, headers = self.server.create_authorization_response(request, username)
    self.set_status(code)
    for header in headers:
      self.set_header(*header)
    self.finish(data)

  @asyncGen
  def web_token(self):
    self.server = self.application.authorizationServer
    data, code, headers = self.server.create_token_response(self.request)
    self.set_status(code)
    for header in headers:
      self.set_header(*header)
    self.finish(data)
