import os
import stat
import requests
import urllib3

from DIRAC import gConfig, gLogger, S_OK, S_ERROR
from DIRAC.Core.Utilities.JEncode import decode, encode


class notebookAuth(object):
  def __init__(self):
    self.log = gLogger()
    # Load meta
    result = gConfig.getOptionsDictRecursively("/LocalInstallation/AuthorizationClient")
    if not result['OK']:
      raise("Can't load web portal settings.")
    self.metadata = result['Value']
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


  def getToken(self, accessToken):
    if accessToken.startswith('/'):
      with open(accessToken, 'rb') as f:
        accessToken = f.read()
    
    url = 'https://marosvn32.in2p3.fr/DIRAC/auth/authorization?client_id=%s' % self.metadata['client_id']
    url += '&redirect_uri=%s' % self.metadata['redirect_uri']
    if group:
      url += '&scope=g:%s' % group
    url += '&provider=CheckIn&response_type=token&access_token=%s' % accessToken
    try:
      r = requests.post(url, verify=False)
      r.raise_for_status()
      return S_OK(r.json())
    except requests.exceptions.Timeout:
      return S_ERROR('Authentication server is not answer.')
    except requests.exceptions.RequestException as ex:
      return S_ERROR(r.content or ex)
    except Exception as ex:
      return S_ERROR('Cannot read response: %s' % ex)

    def getProxyWithToken(self, token, group, lifetime=3600 * 12, voms=False):
      confUrl = gConfig.getValue("/LocalInstallation/ConfigurationServerAPI")
      if not confUrl:
        return S_ERROR('Could not get configuration server API URL.')
      setup = gConfig.getValue("/LocalInstallation/Setup")
      if not setup:
        return S_ERROR('Could not get setup name.')

      # Get REST endpoints from ConfigurationService
      try:
        r = requests.get('%s/option?path=/Systems/Framework/Production/URLs/ProxyAPI' % confUrl, verify=False)
        r.raise_for_status()
        proxyAPI = decode(r.text)[0]
      except requests.exceptions.Timeout:
        return S_ERROR('Time out')
      except requests.exceptions.RequestException as e:
        return S_ERROR(str(e))
      except Exception as e:
        return S_ERROR('Cannot read response: %s' % e)
      
      # Get proxy
      url = '%ss:%s/g:%s/proxy?lifetime=%s' % (proxyAPI, setup, group, lifetime)
      voms = voms or Registry.getGroupOption(group, "AutoAddVOMS", False)
      if voms:
        url += '&voms=%s' % voms
      with OAuth2Session(clientID, token=token) as sess:
        r = sess.get(url, verify=False)
        r.raise_for_status()
      proxy = decode(r.text)[0]
      if not proxy:
        return S_ERROR("Result is empty.")
      
      proxyLoc = '/tmp/x509up_u%s' % os.getuid()

      self.log.notice('Saving proxy.. to %s..' % proxyLoc)
      try:
        with open(proxyLoc, 'w+') as fd:
          fd.write(proxy.encode("UTF-8"))
        os.chmod(proxyLoc, stat.S_IRUSR | stat.S_IWUSR)
      except Exception as e:
        return S_ERROR("%s :%s" % (proxyLoc, repr(e).replace(',)', ')')))

      self.log.notice('Proxy is saved to %s.' % proxyLoc)
      return S_OK()