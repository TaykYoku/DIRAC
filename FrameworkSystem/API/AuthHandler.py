""" Handler to provide REST APIs to manage user authentication.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import re
from datetime import datetime

from tornado import web, gen
from tornado.template import Template
from authlib.common.security import generate_token

from DIRAC import S_OK, S_ERROR, gConfig, gLogger
from DIRAC.Core.Utilities import ThreadSafe
from DIRAC.Core.Utilities.DictCache import DictCache
from DIRAC.Core.Tornado.Server.WebHandler import WebHandler, asyncGen, WErr
from DIRAC.FrameworkSystem.Client.AuthManagerClient import gSessionManager
from DIRAC.FrameworkSystem.Client.NotificationClient import NotificationClient
from DIRAC.ConfigurationSystem.Client.Helpers.Resources import getProvidersForInstance

__RCSID__ = "$Id$"

cacheSession = DictCache()
cacheClient = DictCache()
gCacheClient = ThreadSafe.Synchronizer()
gCacheSession = ThreadSafe.Synchronizer()


class AuthHandler(WebHandler):
  LOCATION = "/DIRAC/oauth"
  METHOD_PREFIX = "web_"

  @classmethod
  def initializeHandler(cls):
    """ This method is called only one time, at the first request.
    """
    print('---->> initializeHandler')
    global cacheSession
    global cacheClient

  #path_oauth = ['([A-z]+)', '([0-9]*)']  # mapped to fn(a, b=None):
  #method_oauth = ['post', 'get']

  @gCacheClient
  def addClient(self, data):
    result = gSessionManager.createClient(data)
    if result['OK']:
      data = result['Value']
      cacheClient.add(data['client_id'], (data['ExpiresIn'] - datetime.now()).seconds, data)
    return result

  @gCacheClient
  def getClient(self, clientID):
    data = cacheClient.get(clientID)
    if not data:
      result = gSessionManager.getClient(clientID)
      if result['OK']:
        data = result['Value']
        cid = data['client_id']
        exp = (data['ExpiresIn'] - datetime.now()).seconds
        cacheClient.add(cid, exp, data)
    return data
  
  @gCacheSession
  def addSession(self, session, data, expTime=300):
    cacheSession.add(session, expTime, data)
  
  @gCacheSession
  def getSession(self, session=None):
    return cacheSession.get(session) if session else cacheSession.getDict()
  
  def updateSession(self, session, expTime=60, **data):
    origData = self.getSession(session)
    for k, v in data.items():
      origData[k] = v
    self.addSession(session, origData, expTime)
  
  def getSessionByOption(self, key):
    value = self.get_argument(key)
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
        raise WErr(result['Message'])
      self.finish(result['Value'])
    else:
      self.finish(cacheClient.getDict())

  @asyncGen
  def web_device(self):
    """ Device authorization flow

        POST: /device?client_id= &scope=
    """
    if self.request.method == 'POST':
      scope = self.grt_argument('scope', None)
      client = yield self.threadTask(self.getClient, self.get_argument('client_id'))
      if not client:
        raise
      session = generate_token(10)  # user_code
      userCode = generate_token(10)
      deviceCode = generate_token(10)
      sessionDict = {'grant': 'device',
                     'user_code': userCode,
                     'device_code': deviceCode}
      self.addSession(session, sessionDict)
      self.write({'expires_in': 300, 'device_code': deviceCode, 'user_code': userCode,
                  'verification_uri': 'https://dirac.egi.eu/DIRAC/device',
                  'verification_uri_complete': 'https://dirac.egi.eu/DIRAC/device?user_code=%s' % userCode})
    elif self.request.method == 'GET':
      userCode = self.get_argument('user_code', None)
      if userCode:
        t = """
        <!DOCTYPE html>
          <html>
            <head>
              <title>Authetication</title>
              <meta charset="utf-8" />
            </head>
            <body>
              <ul>
                {% for idP in idPs %}
                  <li> <a href="{{authEndpoint}}/{{idP}}">{{idP}}</a> </li>
                {% end %}
              <ul>
            </body>
          </html>
        """
        session = self.getSessionByOption('user_code')
        if not session:
          raise
        self.set_cookie('session', session, 60)
        self.write(t.generate(authEndpoint='https://dirac.egi.eu/DIRAC/authorization',
                              idPs=getProvidersForInstance('id')))
      else:
        t = """
        <!DOCTYPE html>
          <html>
            <head>
              <title>Authetication</title>
              <meta charset="utf-8" />
            </head>
            <body>
              <form action="{{deviceEndpoint}}" method="GET">
                <input type="text" id="user_code" name="user_code">
                <button type="submit" id="submit">Submit</button>
              </form>
            </body>
          </html>
        """
        self.write(t.generate(deviceEndpoint='https://dirac.egi.eu/DIRAC/device'))
    else:
      raise
    self.finish()

  path_oauth = ['([A-z_-.,0-9]*)']
  @asyncGen
  def web_authorization(self, idP=None):
    if self.request.method != 'GET':
      raise
    self.log.info('web_authorization: %s' % self.request)
    if self.get_argument('response_type', None) == 'code':
      client = yield self.threadTask(self.getClient, self.get_argument('client_id'))
      if not client:
        raise
      session = self.get_argument('state', generate_token(10))
      codeChallenge = self.get_argument('code_challenge', None)
      if codeChallenge:
        sessionDict['code_challenge'] = codeChallenge
        sessionDict['code_challenge_method'] = self.get_argument('code_challenge_method', 'pain')
      self.addSession(session, sessionDict)
      t = """
      <!DOCTYPE html>
        <html>
          <head>
            <title>Authetication</title>
            <meta charset="utf-8" />
          </head>
          <body>
            <ul>
              {% for idP in idPs %}
                <li> <a href="{{authEndpoint}}/{{idP}}">{{idP}}</a> </li>
              {% end %}
            <ul>
          </body>
        </html>
      """
      self.set_cookie('session', session, 60)
      self.finish(t.generate(authEndpoint='https://dirac.egi.eu/DIRAC/authorization',
                             idPs=getProvidersForInstance('id')))
    elif idP:
      if idP not in getProvidersForInstance('id'):
        raise
      session = self.get_cookie('session')
      self.clean_cookie('session')
      if not session:
        raise
      self.updateSession(session, Provider=idP)
      result = IdProviderFactory().getIdProvider(idP)
      if not result['OK']:
        raise
      provObj = result['Value']
      result = provObj.getAuthURL(self.getSession(session))
      if not result['OK']:
        raise
      self.log.notice('Redirect to', result['Value'])
      self.redirect(result['Value'])

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

    self.log.info(session, 'session, parsing authorization response %s' % self.get_arguments)
    result = IdProviderFactory().getIdProvider(sessionDict['Provider'])
    if not result['OK']:
      raise
    provObj = result['Value']
    result = provObj.parseAuthResponse(**self.get_arguments)
    if not result['OK']:
      raise
    #### GENERATE TOKEN
    header = {}
    payload = {'sub': result['Value']['ID'],
               'grp': result['Value']['Group'],
               'iss': getSetup(),
               'exp': 12 * 3600}
    #### key = READ Key
    sessionDict['Token'] = {'access_token': jwt.encode(header, payload, key),
                            'token_type': 'Baerer',
                            'expires_at': 12 * 3600,
                            'state': session}
    sessionDict['Status'] = result['Value']['Status']
    sessionDict['Comment'] = result['Value']['Comment']
    if sessionDict['grant'] == 'device':
      t = """
      <!DOCTYPE html>
        <html>
          <head>
            <title>Authetication</title>
            <meta charset="utf-8" />
          </head>
          <body>
            <script type="text/javascript"> window.close() </script>
          </body>
        </html>
      """
      self.finish(t.generate())
    elif sessionDict['grant'] == 'code':
      if 'code_challenge' in sessionDict:
        # code = Create JWS
        self.finish({'code': code, 'state': session})
      else:
        code = generate_token(10)
        requests.get(sessionDict['redirect_uri'], {'code': code, 'state': session})
      sessionDict['code'] = code

    self.updateSession(session, sessionDict, 300)

  
  def web_token(self):
    if self.request.method != 'POST':
      raise
    client = yield self.threadTask(self.getClient, self.get_argument('client_id'))
    if not client:
      raise
    grantType = self.get_argument('grant_type')
    if grantType == 'device_code':
      session, data = self.getSessionByOption('device_code')
      if not session:
        raise
      if data['Status'] not in ['authed', 'failed']:
        self.write('Status: %s Wait..' % data['Status'])
      else:
        cacheSession.delete(session)
        if data['Status'] != 'authed':
          raise
        if not data['Token']:
          raise
        self.write(data['Token'])
      self.finish()
    elif grantType == 'authorization_code':
      session, data = self.getSessionByOption('code')
      if not session:
        raise
      cacheSession.delete(session)
      if self.get_argument('redirect_uri') != client['redirect_uri']:
        raise
      codeVerifier = self.get_argument('code_verifier', None)
      if codeVerifier:
        if data['code_challenge_method'] == 'S256':
          from authlib.oauth2.rfc7636 import create_s256_code_challenge
          codeVerifier = create_s256_code_challenge(codeVerifier)
        if data['code_challenge'] != codeVerifier:
          raise
      if not data['Token']:
        raise
      self.finish(data['Token'])
    else:
      raise



  
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
