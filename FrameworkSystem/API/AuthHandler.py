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

from DIRAC import S_OK, S_ERROR, gConfig, gLogger
from DIRAC.Core.Utilities import ThreadSafe
from DIRAC.Core.Utilities.DictCache import DictCache
from DIRAC.Resources.IdProvider.IdProviderFactory import IdProviderFactory
from DIRAC.Core.Tornado.Server.WebHandler import WebHandler, asyncGen, WErr
from DIRAC.FrameworkSystem.Client.AuthManagerClient import gSessionManager
from DIRAC.FrameworkSystem.Client.ProxyManagerClient import gProxyManager
from DIRAC.FrameworkSystem.Client.NotificationClient import NotificationClient
from DIRAC.ConfigurationSystem.Client.Helpers.Resources import getProvidersForInstance
from DIRAC.ConfigurationSystem.Client.Helpers.CSGlobals import getSetup


__RCSID__ = "$Id$"

cacheSession = DictCache()
cacheClient = DictCache()
gCacheClient = ThreadSafe.Synchronizer()
gCacheSession = ThreadSafe.Synchronizer()

from authlib.oauth2.rfc8628 import (
    DeviceAuthorizationEndpoint as _DeviceAuthorizationEndpoint,
    DeviceCodeGrant as _DeviceCodeGrant,
    DeviceCredentialDict,
)
from authlib.oauth2.rfc7636 import (
    create_s256_code_challenge,
)
# class DeviceAuthorizationEndpoint(_DeviceAuthorizationEndpoint):
#     def get_verification_uri(self):
#         return 'https://example.com/activate'

#     def save_device_credential(self, client_id, scope, data):
#         pass

# class DeviceCodeGrant(_DeviceCodeGrant):
#     def query_device_credential(self, device_code):
#         data = device_credentials.get(device_code)
#         if not data:
#             return None

#         now = int(time.time())
#         data['expires_at'] = now + data['expires_in']
#         data['device_code'] = device_code
#         data['scope'] = 'profile'
#         data['interval'] = 5
#         data['verification_uri'] = 'https://example.com/activate'
#         return DeviceCredentialDict(data)

#     def query_user_grant(self, user_code):
#         if user_code == 'code':
#             return User.query.get(1), True
#         if user_code == 'denied':
#             return User.query.get(1), False
#         return None

#     def should_slow_down(self, credential, now):
#         return False


class AuthHandler(WebHandler):
  LOCATION = "/DIRAC/auth"
  METHOD_PREFIX = "web_"

  @classmethod
  def initializeHandler(cls):
    """ This method is called only one time, at the first request.
    """
    print('---->> initializeHandler')
    global cacheSession
    # {<main session id>: {<param 1>: <value>,
    #                      <param 2>: <value>,
    #                      <another session flow id>: {<param 1>: <value>,
    #                                                  <param 2>: <value>}}
    global cacheClient

  #path_oauth = ['([A-z]+)', '([0-9]*)']  # mapped to fn(a, b=None):
  #method_oauth = ['post', 'get']

  @gCacheClient
  def addClient(self, data):
    result = gSessionManager.createClient(data)
    if result['OK']:
      data = result['Value']
      cacheClient.add(data['client_id'], 24 * 3600, data)
    return result

  @gCacheClient
  def getClient(self, clientID):
    data = cacheClient.get(clientID)
    if not data:
      result = gSessionManager.getClientByID(clientID)
      if result['OK']:
        data = result['Value']
        cacheClient.add(data['client_id'], 24 * 3600, data)
    return data
  
  @gCacheSession
  def addSession(self, session, data, exp=300):
    cacheSession.add(session, exp, data)
  
  @gCacheSession
  def getSession(self, session=None):
    return cacheSession.get(session) if session else cacheSession.getDict()
  
  def updateSession(self, session, exp=300, **data):
    origData = self.getSession(session) or {}
    for k, v in data.items():
      origData[k] = v
    self.addSession(session, origData, exp)
  
  def getSessionByOption(self, key, value=None):
    value = value or self.get_argument(key)
    sessions = self.getSession()
    for session, data in sessions.items():
      if data[key] == value:
        return session, data
    return None, {}

  @asyncGen
  def web_register(self):
    """ Device authorization flow

        POST: /device?client_id= &scope=
    """
    if self.request.method == 'POST':
      result = yield self.threadTask(self.addClient, self.request.arguments)
      if not result['OK']:
        raise WErr(503, result['Message'])
      self.finish(result['Value'])
    
    # TODO_remove this block:
    else:
      self.finish(cacheClient.getDict())

  path_device = ['([A-z0-9]*)']
  @asyncGen
  def web_device(self, userCode=None):
    """ Device authorization flow

        POST: /device?client_id= &scope=
    """
    userCode = self.get_argument('user_code', userCode)
    if self.request.method == 'POST':
      data = {'client_id': self.get_argument('client_id')}
      client = yield self.threadTask(self.getClient, data['client_id'])
      if not client:
        raise WErr(401, 'Client ID is unregistred.')
      data['expires_in'] = 300
      data['expires_at'] = int(time()) + data['expires_in']
      data['device_code'] = generate_token(20)
      data['user_code'] = generate_token(10)
      data['scope'] = self.get_argument('scope', '')
      data['group'] = self.get_argument('group', None)
      data['interval'] = 5
      data['verification_uri'] = 'https://marosvn32.in2p3.fr/DIRAC/auth/device'
      data['verification_uri_complete'] = 'https://marosvn32.in2p3.fr/DIRAC/auth/device/%s' % data['user_code']
      # return DeviceCredentialDict(data)
      self.addSession(data['device_code'], data)
      self.finish(data)
    elif self.request.method == 'GET':
      if userCode:
        session, data = self.getSessionByOption('user_code', userCode)
        if not session:
          raise WErr(404, 'Session expired.')
        authURL = 'https://marosvn32.in2p3.fr/DIRAC/auth/authorization'
        self.redirect('%s?user_code=%s&client_id=%s' % (authURL, userCode, data['client_id']))
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
    # Only GET method supported
    if self.request.method != 'GET':
      raise WErr(404, '%s request method not supported.' % self.request.method)
    self.log.info('web_authorization: %s' % self.request)
    
    # Check client
    client = yield self.threadTask(self.getClient, self.get_argument('client_id'))
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
      result = getProvidersForInstance('Id')
      if not result['OK']:
        raise WErr(503, result['Message'])
      self.finish(t.generate(url=self.request.protocol + "://" + self.request.host + self.request.path,
                             query='?' + self.request.query, idPs=idPs))
    else:

      # Check IdP
      if idP not in idPs:
        raise WErr(503, 'Provider not exist.')
      
      userCode = self.get_argument('user_code', None)
      flow = self.get_argument('response_type', 'device' if userCode else None)

      # Authorization code flow
      if flow == 'code':
        session = self.get_argument('state', generate_token(10))
        sessionDict = {}
        codeChallenge = self.get_argument('code_challenge', None)
        if codeChallenge:
          sessionDict['code_challenge'] = codeChallenge
          sessionDict['code_challenge_method'] = self.get_argument('code_challenge_method', 'pain')
        self.addSession(session, sessionDict)
      
      # Device flow
      elif flow == 'device':
        session, _ = self.getSessionByOption('user_code', userCode)
        if not session:
          raise WErr(404, 'Session expired.')
        # session = self.get_argument('session', generate_token(10))
      
      # Add IdP name to session
      self.updateSession(session, Provider=idP)

      # Submit second auth flow through IdP

      # ##########AuthManager:submitAuthFlow########################################################################
      # result = IdProviderFactory().getIdProvider(idP)
      # if not result['OK']:
      #   raise WErr(503, result['Message'])
      # provObj = result['Value']
      # result = provObj.submitNewSession(session)
      # if not result['OK']:
      #   raise WErr(503, result['Message'])
      # self.log.notice('Redirect to', result['Value'])
      # authURL, idPSessionParams = result['Value']
      # ##################################################################################
      result = AuthManagerClient().submitAuthorizeFlow(idP, session)
      if not result['OK']:
        raise WErr(503, result['Message'])
      self.log.notice('Redirect to', result['Value'])
      authURL, idPSessionParams = result['Value']
      self.updateSession(session, **{idP:idPSessionParams})
      self.redirect(authURL)

  @asyncGen
  def web_redirect(self):
    # Redirect endpoint for response
    self.log.info('REDIRECT RESPONSE:\n', self.request)
    session = self.get_argument('state', None)
    if not session:
      raise WErr(500, "In some case session was not keep in flow.")
    sessionDict = self.getSession(session)
    if not sessionDict:
      raise WErr(500, "Session expired.")
    error = self.get_argument('error', None)
    if error:
      description = self.get_argument('error_description', '')
      raise WErr(500, '%s session crashed with error:\n%s\n%s' % (session, error,
                                                                  description))
    
    # Parse result of the second authentication flow
    self.log.info(session, 'session, parsing authorization response %s' % self.get_arguments)
    
    # ##########AuthManager:readResponse########################################################################
    # result = IdProviderFactory().getIdProvider(sessionDict['Provider'])
    # if not result['OK']:
    #   return result
    #   # raise WErr(503, result['Message'])
    # provObj = result['Value']
    # result = provObj.parseAuthResponse(self.request)
    # if not result['OK']:
    #   return result
    #   # # --
    #   # self.updateSession(session, Status='failed', Comment=result['Message'])
    #   # # --
    #   # raise WErr(503, result['Message'])
    
    # # FINISHING with IdP auth result
    # userProfile = result['Value']['UsrOptns']
    # username = result['Value']['username']

    # # Is ID registred?
    # userID = userProfile['ID']
    # result = getUsernameForID(userID)
    # if not result['OK']:
    #   comment = '%s ID is not registred in the DIRAC.' % userID
    #   result = self.__registerNewUser(provider, parseDict)
    #   if result['OK']:
    #     comment += ' Administrators have been notified about you.'
    #   else:
    #     comment += ' Please, contact the DIRAC administrators.'
    #   return S_ERROR(comment)
    # return S_OK((result['Value'], userProfile))
    # ##################################################################################
    result = AuthManagerClient().parseAuthResponse(idP, self.request, sessionDict[idP])
    if not result['OK']:
      self.updateSession(session, Status='failed', Comment=result['Message'])
      raise WErr(503, result['Message'])
    username, userProfile = result['Value']

    # researche Group
    reqGroup = self.get_argument('group', sessionDict.get('group'))
    if not reqGroup:
      self.finish('You need to choose group')
      raise
      # self.__chooseGroup(session)

    # Check group
    result = gProxyManager.getGroupsStatusByUsername(username, [reqGroup])
    if not result['OK']:
      raise WErr(503, result['Message'])
    userProfile['Group'] = reqGroup

    # Create DIRAC access token for username/group
    reuslt = self.__getAccessToken(userProfile)
    if not result['OK']:
      raise WErr(503, result['Message'])
    self.updateSession(session, Status='authed', Token=result['Value'])

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

    # Authorization code flow
    elif sessionDict['grant'] == 'code':
      if 'code_challenge' in sessionDict:
        # code = Create JWS
        pass
      else:
        code = generate_token(10)
        requests.get(sessionDict['redirect_uri'], {'code': code, 'state': session})
      self.updateSession(session, code=code)
      self.finish({'code': code, 'state': session})

  @asyncGen
  def web_token(self):
    # Support only POST method
    if self.request.method != 'POST':
      raise
    
    # Check client
    client = yield self.threadTask(self.getClient, self.get_argument('client_id'))
    if not client:
      raise
    
    grantType = self.get_argument('grant_type')

    # Device flow
    if grantType == 'device_code':
      session, data = self.getSessionByOption('device_code')
      if not session:
        raise
      
      # Waiting IdP auth result
      if data['Status'] not in ['authed', 'failed']:
        self.finish('Status: %s Wait..' % data['Status'])
      else:
        
        # Remove session and return DIRAC access token
        cacheSession.delete(session)
        if data['Status'] != 'authed':
          raise WErr(401, data['Comment'])
        self.finish(data['Token'])
    
    # Authentication code flow
    elif grantType == 'authorization_code':
      session, data = self.getSessionByOption('code')
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
      cacheSession.delete(session)
      if data['Status'] != 'authed':
        raise WErr(401, data['Comment'])
      self.finish(data['Token'])

  def __getAccessToken(self, profile):
    #### GENERATE TOKEN
    header = {'alg': 'RS256'}
    payload = {'sub': profile['ID'],
               'grp': profile['Group'],
               'iss': getSetup(),
               'exp': 12 * 3600}
    # Read private key of DIRAC auth service
    with open('/opt/dirac/etc/grid-security/jwtRS256.key', 'r') as f:
      key = f.read()
    return S_OK({'access_token': jwt.encode(header, payload, key),
                 'token_type': 'Baerer',
                 'expires_at': 12 * 3600,
                 'state': session})

  # def __chooseIdP(self, session):
  #   t = template.Template('''<!DOCTYPE html>
  #   <html>
  #     <head>
  #       <title>Authetication</title>
  #       <meta charset="utf-8" />
  #     </head>
  #     <body>
  #       <ul>
  #         {% for idP in idPs %}
  #           <li> <a href="{{authEndpoint}}/{{idP}}?session={{session}}">{{idP}}</a> </li>
  #         {% end %}
  #       <ul>
  #     </body>
  #   </html>''')
  #   result = getProvidersForInstance('Id')
  #   if not result['OK']:
  #     raise WErr(503, result['Message'])
  #   self.write(t.generate(authEndpoint='https://marosvn32.in2p3.fr/DIRAC/auth/authorization',
  #                         idPs=result['Value'], session=session))

  # def __chooseGroup(self, session):
  #   sessionDict = self.getSession(session)
  #   if not sessionDict:
  #     raise WErr(500, "Session expired.")
    
  #   reqGroup = self.get_argument('group', sessionDict.get('group'))
  #   result = gProxyManager.getGroupsStatusByUsername(username, [reqGroup])
  #   if not result['OK']:
  #     raise WErr(503, result['Message'])
  #   pprint(result['Value'])
  #   groupsStates = result['Value']
  #   if not reqGroup:
  #     t = template.Template('''<!DOCTYPE html>
  #     <html>
  #       <head>
  #         <title>Authetication</title>
  #         <meta charset="utf-8" />
  #       </head>
  #       <body>
  #         Please choose group:
  #         <ul>
  #           {% for group, status, comment in groups %}
  #             <li> <a href="{{url}}/{{idP}}?session={{session}}">{{idP}}</a> </li>
  #           {% end %}
  #         <ul>
  #       </body>
  #     </html>''')
  #     self.write(t.generate(url=self.request.full_url(),
  #                           groups=result['Value'], session=session))
  #   elif not self.get_argument('ignoreGroupCheck', sessionDict.get('ignoreGroupCheck'))
  #     if groupsStates[reqGroup]['Status'] not in ['unknown', 'ready']:
  #       if groupsStates[reqGroup].get('Action'):
  #         t = template.Template('''<!DOCTYPE html>
  #         <html>
  #           <head>
  #             <title>Authetication</title>
  #             <meta charset="utf-8" />
  #           </head>
  #           <body>
  #             Authentication process stuck
  #             Status of {{group}} group: {{status}}
  #             <a href={{url}}>{{comment}}</a>

  #           </body>
  #         </html>''')
  #         self.write(t.generate(group=reqGroup, status=groupsStates[reqGroup]['Status'],
  #                               url=groupsStates[reqGroup]['Action'][1],
  #                               comment=groupsStates[reqGroup]['Comment']))
  #   else:
      

  # def __generateToken(self, header, payload):


  
  # auth_auth = ['all']
  # methods_auth = ['POST', 'GET']
  # def web_auth(self, instance, state=None, **kwargs):
  #   """ REST endpoint for users authentication.

  #       **GET** /auth/<IdP>?<options> -- this request for initialization authentication flow  
  #         * *IdP* -- is a registred in DIRAC Identity provider name that need to use for authentication
          
  #         Options:
  #           * *email* -- send the authentication URL to the email(optional)
          
  #         Response in the json format with the next keys:
  #           * *Status* -- session status, required values: "needToAuth", "ready", "fail".
  #           * *URL* -- link for authentication, generated by choosed identity provider. Returned if status is "needToAuth".
  #           * *Session* -- current session ID, returned if status is "needToAuth".
  #           * *UserName* -- user name, returned if status is "ready".

  #       **GET** /auth/<session> -- redirect to identity provider authentication endpoint to enable the user to authenticate  
  #         * *session* -- session ID

  #         Response depended from redirected endpoint

  #       **GET** /auth/<session>/status -- retrieve session with status and describe  
  #         * *session* -- session ID

  #         Response in the json format with the next keys:
  #           * *Comment* -- comment
  #           * *Status* -- session status, requeried statuses: "prepared", "in progress", "failed"
  #           * *Session* -- session ID
  #           * *ID* -- identity provider user identity number
  #           * *Provider* -- identity provider name

  #       **GET** /auth/redirect -- redirect endpoint to catch responce from authentication flow of identity provider
          
  #         Response in the html format
  #   """
  #   optns = self.overpath.strip('/').split('/')
  #   if not optns or len(optns) > 2:
  #     raise WErr(404, "Wrone way")
  #   result = getProvidersForInstance('Id')
  #   if not result['OK']:
  #     raise WErr(500, result['Message'])
  #   idPs = result['Value']
  #   idP = optns[0] if optns[0] in idPs else None
  #   session = re.match("([A-z0-9]+)?", optns[0]).group()

  #   if idP:
  #     # Create new authenticate session
  #     session = self.get_cookie(idP)
  #     self.log.info('Initialize "%s" authorization flow' % idP, 'with %s session' % session if session else '')
  #     result = yield self.threadTask(gSessionManager.submitAuthorizeFlow, idP, session) # group
  #     if not result['OK']:
  #       self.clear_cookie(idP)
  #       raise WErr(500, result['Message'])
  #     if result['Value']['Status'] == 'ready':
  #       self.set_cookie("TypeAuth", idP)
  #     elif result['Value']['Status'] == 'needToAuth':
  #       if self.args.get('email'):
  #         notify = yield self.threadTask(NotificationClient().sendMail, self.args['email'],
  #                                        'Authentication throught %s' % idP,
  #                                        'Please, go throught the link %s to authorize.' % result['Value']['URL'])
  #         if not notify['OK']:
  #           result['Value']['Comment'] = '%s\n%s' % (result['Value'].get('Comment') or '', notify['Message'])
  #       self.log.notice('%s authorization session "%s" provider was created' % (result['Value']['Session'], idP))
  #     else:
  #       raise WErr(500, 'Not correct status "%s" of %s' % (result['Value']['Status'], idP))
  #     self.finishJEncode(result['Value'])

  #   elif optns[0] == 'redirect':
  #     # Redirect endpoint for response
  #     self.log.info('REDIRECT RESPONSE:\n', self.request)
  #     if self.args.get('error'):
  #       raise WErr(500, '%s session crashed with error:\n%s\n%s' % (self.args.get('state') or '',
  #                                                                   self.args['error'],
  #                                                                   self.args.get('error_description') or ''))
  #     if 'state' not in self.args:
  #       raise WErr(404, '"state" argument not set.')
  #     if not self.args.get('state'):
  #       raise WErr(404, '"state" argument is empty.')
  #     self.log.info(self.args['state'], 'session, parsing authorization response %s' % self.args)
  #     result = yield self.threadTask(gSessionManager.parseAuthResponse, self.args, self.args['state'])
  #     if not result['OK']:
  #       raise WErr(500, result['Message'])
  #     comment = result['Value']['Comment']
  #     status = result['Value']['Status']
  #     t = Template('''<!DOCTYPE html>
  #       <html><head><title>Authetication</title>
  #         <meta charset="utf-8" /></head><body>
  #           %s <br>
  #           <script type="text/javascript">
  #             if ("%s" == "redirect") { window.open("%s","_self") }
  #             else { window.close() }
  #           </script>
  #         </body>
  #       </html>''' % (comment, status, comment))
  #     self.log.info('>>>REDIRECT:\n', comment)
  #     self.finish(t.generate())

  #   elif session:
  #     if optns[-1] == session:
  #       # Redirect to authentication endpoint
  #       self.log.info(session, 'authorization session flow.')
  #       result = yield self.threadTask(gSessionManager.getSessionAuthLink, session)
  #       if not result['OK']:
  #         raise WErr(500, '%s session not exist or expired!\n%s' % (session, result['Message']))
  #       self.log.notice('Redirect to', result['Value'])
  #       self.redirect(result['Value'])

  #     elif optns[-1] == 'status':
  #       # Get session authentication status
  #       self.log.info(session, 'session, get status of authorization.')
  #       result = yield self.threadTask(gSessionManager.getSessionStatus, session)
  #       if not result['OK']:
  #         raise WErr(500, result['Message'])
  #       self.set_cookie("TypeAuth", result['Value']['Provider'])
  #       self.set_cookie(result['Value']['Provider'], session)
  #       self.finishJEncode(result['Value'])

  #     else:
  #       raise WErr(404, "Wrone way")
    
  #   elif token:
  #     idP = self.get_cookie("TypeAuth")
  #     session = self.get_cookie(idP)
  #     if not session:
  #       raise WErr(500, 'Session is absent in cookies.')
      
  #     group = self.args.get('group')
  #     time = self.args.get('livetime')
  #     # Create token by session
  #     result = yield self.threadTask(gSessionManager.getTokenBySession, session, group, time)
  #     if not result['OK']:
  #       raise WErr(500, result['Message'])
  #     self.clear_cookie("TypeAuth")
  #     self.clear_cookie(idP)
  #     self.finishJEncode(result['Value'])

  #   else:
  #     raise WErr(404, "Wrone way")
