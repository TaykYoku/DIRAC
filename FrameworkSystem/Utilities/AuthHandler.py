""" Handler to provide REST APIs to manage user authentication.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import re

from tornado import web, gen
from tornado.template import Template

from DIRAC import S_OK, S_ERROR, gConfig, gLogger
from DIRAC.Core.Web.WebHandler import WebHandler, asyncGen, WErr
from DIRAC.FrameworkSystem.Client.AuthManagerClient import gSessionManager
from DIRAC.FrameworkSystem.Client.NotificationClient import NotificationClient
from DIRAC.ConfigurationSystem.Client.Helpers.Resources import getProvidersForInstance

__RCSID__ = "$Id$"

template = """
<!DOCTYPE html>
<html>
  <head>
    <title>Authetication</title>
    <meta charset="utf-8" />
  </head>
  <body>
    <ul>
      {% for idP, url in idPs.items() %}
        <li> <p id="{{idP}}" onclick="auth()">{{idP}}</p> </li>
      {% end %}
    <ul>
    <script type="text/javascript">
      function auth() {
        var me = this;

        authorizationURL = result.Value.URL;
        session = result.Value.Session;

        // Open popup
        var oAuthReqWin = open(authorizationURL, "popupWindow", "hidden=yes,height=570,width=520,scrollbars=yes,status=yes");
        oAuthReqWin.focus();

        // Send request to redirect URL about success authorization
        console.log("debug", "Watch when popup window will be close");
        var res = (function waitPopupClosed(i, r) {
          if (r === "closed") {
            return Ext.Ajax.request({
              url: {{GLOBAL_BASE_URL}} + "Authentication/waitOAuthStatus",
              params: {
                typeauth: authProvider,
                inthread: inthread ?? null,
                session: session
              },
              async: false,
              success: function(response) {
                var result = Ext.decode(response.responseText);
                var msg = result.Comment ? result.Comment.replace(/\n/g, "<br>") : "";
                if (result.Status == "authed") {
                  return (location.protocol = "https:");  
                } else if (result.Status != "failed") {
                  msg = "Authentication thread discontinued.\n" + msg;
                }
                
                // Hide load icon
                Ext.get("app-dirac-loading").hide();
                Ext.get("app-dirac-loading-msg").setHtml("Loading module. Please wait ...");
                return Ext.Msg.show({
                  closeAction: "destroy",
                  title: "Authentication error.",
                  message: msg,
                  icon: Ext.Msg.ERROR
                });
              },
              failure: function(form, action) {
                // Hide load icon
                Ext.get("app-dirac-loading").hide();
                Ext.get("app-dirac-loading-msg").setHtml("Loading module. Please wait ...");
                return me.alert("Request was ended with error: " + form + action, "error");
              }
            });
          } else {
            setTimeout(function() {
              if (--i) {
                if (oAuthReqWin === undefined) {
                  me.log("debug", "Popup window was closed.");
                  return waitPopupClosed(0, "closed");
                }
                if (oAuthReqWin) {
                  if (oAuthReqWin.closed) {
                    me.log("debug", "Popup window was closed.");
                    return waitPopupClosed(0, "closed");
                  } else {
                    oAuthReqWin.focus();
                    return waitPopupClosed(i);
                  }
                } else {
                  return waitPopupClosed(i);
                }
              } else {
                return waitPopupClosed(120);
              }
            }, 1000);
          }
        })(120, "opened");
      }
      if ("%s" == "redirect") { window.open("%s","_self") }
      else { window.close() }
    </script>
  </body>
</html>
"""

class AuthHandler(WebHandler):
  OVERPATH = True
  AUTH_PROPS = "all"
  LOCATION = "/"

  def initialize(self):
    super(AuthHandler, self).initialize()
    self.args = {}
    for arg in self.request.arguments:
      if len(self.request.arguments[arg]) > 1:
        self.args[arg] = self.request.arguments[arg]
      else:
        self.args[arg] = self.request.arguments[arg][0] or ''
    return S_OK()

  @asyncGen
  def web_oauth(self):
    if optns[0] == 'authorization':
      if self.request.method == 'GET':

      t = Template('''<!DOCTYPE html>
        <html><head><title>Authetication</title>
          <meta charset="utf-8" /></head><body>
            %s <br>
            <script type="text/javascript">
              if ("%s" == "redirect") { window.open("%s","_self") }
              else { window.close() }
            </script>
          </body>
        </html>''' % (comment, status, comment))
      self.log.info('>>>REDIRECT:\n', comment)
      self.finish(t.generate())
    elif optns[0] == 'token':
      pass
  
  @asyncGen
  def web_auth(self):
    """ REST endpoint for users authentication.

        **GET** /auth/<IdP>?<options> -- this request for initialization authentication flow  
          * *IdP* -- is a registred in DIRAC Identity provider name that need to use for authentication
          
          Options:
            * *email* -- send the authentication URL to the email(optional)
          
          Response in the json format with the next keys:
            * *Status* -- session status, required values: "needToAuth", "ready", "fail".
            * *URL* -- link for authentication, generated by choosed identity provider. Returned if status is "needToAuth".
            * *Session* -- current session ID, returned if status is "needToAuth".
            * *UserName* -- user name, returned if status is "ready".

        **GET** /auth/<session> -- redirect to identity provider authentication endpoint to enable the user to authenticate  
          * *session* -- session ID

          Response depended from redirected endpoint

        **GET** /auth/<session>/status -- retrieve session with status and describe  
          * *session* -- session ID

          Response in the json format with the next keys:
            * *Comment* -- comment
            * *Status* -- session status, requeried statuses: "prepared", "in progress", "failed"
            * *Session* -- session ID
            * *ID* -- identity provider user identity number
            * *Provider* -- identity provider name

        **GET** /auth/redirect -- redirect endpoint to catch responce from authentication flow of identity provider
          
          Response in the html format
    """
    optns = self.overpath.strip('/').split('/')
    if not optns or len(optns) > 2:
      raise WErr(404, "Wrone way")
    result = getProvidersForInstance('Id')
    if not result['OK']:
      raise WErr(500, result['Message'])
    idPs = result['Value']
    idP = optns[0] if optns[0] in idPs else None
    session = re.match("([A-z0-9]+)?", optns[0]).group()

    if idP:
      # Create new authenticate session
      session = self.get_cookie(idP)
      self.log.info('Initialize "%s" authorization flow' % idP, 'with %s session' % session if session else '')
      result = yield self.threadTask(gSessionManager.submitAuthorizeFlow, idP, session) # group
      if not result['OK']:
        self.clear_cookie(idP)
        raise WErr(500, result['Message'])
      if result['Value']['Status'] == 'ready':
        self.set_cookie("TypeAuth", idP)
      elif result['Value']['Status'] == 'needToAuth':
        if self.args.get('email'):
          notify = yield self.threadTask(NotificationClient().sendMail, self.args['email'],
                                         'Authentication throught %s' % idP,
                                         'Please, go throught the link %s to authorize.' % result['Value']['URL'])
          if not notify['OK']:
            result['Value']['Comment'] = '%s\n%s' % (result['Value'].get('Comment') or '', notify['Message'])
        self.log.notice('%s authorization session "%s" provider was created' % (result['Value']['Session'], idP))
      else:
        raise WErr(500, 'Not correct status "%s" of %s' % (result['Value']['Status'], idP))
      self.finishJEncode(result['Value'])

    elif optns[0] == 'redirect':
      # Redirect endpoint for response
      self.log.info('REDIRECT RESPONSE:\n', self.request)
      if self.args.get('error'):
        raise WErr(500, '%s session crashed with error:\n%s\n%s' % (self.args.get('state') or '',
                                                                    self.args['error'],
                                                                    self.args.get('error_description') or ''))
      if 'state' not in self.args:
        raise WErr(404, '"state" argument not set.')
      if not self.args.get('state'):
        raise WErr(404, '"state" argument is empty.')
      self.log.info(self.args['state'], 'session, parsing authorization response %s' % self.args)
      result = yield self.threadTask(gSessionManager.parseAuthResponse, self.args, self.args['state'])
      if not result['OK']:
        raise WErr(500, result['Message'])
      comment = result['Value']['Comment']
      status = result['Value']['Status']
      t = Template('''<!DOCTYPE html>
        <html><head><title>Authetication</title>
          <meta charset="utf-8" /></head><body>
            %s <br>
            <script type="text/javascript">
              if ("%s" == "redirect") { window.open("%s","_self") }
              else { window.close() }
            </script>
          </body>
        </html>''' % (comment, status, comment))
      self.log.info('>>>REDIRECT:\n', comment)
      self.finish(t.generate())

    elif session:
      if optns[-1] == session:
        # Redirect to authentication endpoint
        self.log.info(session, 'authorization session flow.')
        result = yield self.threadTask(gSessionManager.getSessionAuthLink, session)
        if not result['OK']:
          raise WErr(500, '%s session not exist or expired!\n%s' % (session, result['Message']))
        self.log.notice('Redirect to', result['Value'])
        self.redirect(result['Value'])

      elif optns[-1] == 'status':
        # Get session authentication status
        self.log.info(session, 'session, get status of authorization.')
        result = yield self.threadTask(gSessionManager.getSessionStatus, session)
        if not result['OK']:
          raise WErr(500, result['Message'])
        self.set_cookie("TypeAuth", result['Value']['Provider'])
        self.set_cookie(result['Value']['Provider'], session)
        self.finishJEncode(result['Value'])

      else:
        raise WErr(404, "Wrone way")
    
    elif token:
      idP = self.get_cookie("TypeAuth")
      session = self.get_cookie(idP)
      if not session:
        raise WErr(500, 'Session is absent in cookies.')
      
      group = self.args.get('group')
      time = self.args.get('livetime')
      # Create token by session
      result = yield self.threadTask(gSessionManager.getTokenBySession, session, group, time)
      if not result['OK']:
        raise WErr(500, result['Message'])
      self.clear_cookie("TypeAuth")
      self.clear_cookie(idP)
      self.finishJEncode(result['Value'])

    else:
      raise WErr(404, "Wrone way")
