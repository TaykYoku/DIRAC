import os
import stat
import requests
import urllib3

from DIRAC import gConfig, gLogger, S_OK, S_ERROR
from DIRAC.Core.Utilities.JEncode import decode, encode
from DIRAC.ConfigurationSystem.Client.Helpers import Registry



class notebookAuth(object):
  def __init__(self, group, lifetime=3600 * 12, voms=False, aToken=None):
    self.log = gLogger.getSubLogger(__name__)
    self.group = group
    self.lifetime = lifetime
    self.voms = voms
    self.accessToken = aToken or '/var/run/secrets/egi.eu/access_token'
    # Load meta
    result = gConfig.getOptionsDictRecursively("/LocalInstallation/AuthorizationClient")
    if not result['OK']:
      raise Exception("Can't load web portal settings.")
    self.metadata = result['Value']
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


  def getToken(self):
    if self.accessToken.startswith('/'):
      with open(self.accessToken, 'rb') as f:
        self.accessToken = f.read()
    
    url = 'https://marosvn32.in2p3.fr/DIRAC/auth/authorization?client_id=%s' % self.metadata['client_id']
    url += '&redirect_uri=%s' % self.metadata['redirect_uri']
    url += '&response_type=%s' % self.metadata['response_type']
    if self.group:
      url += '&scope=g:%s' % self.group
    url += '&provider=CheckIn&access_token=%s' % self.accessToken
    try:
      r = requests.get(url, verify=False)
      r.raise_for_status()
      print(r.text)
      return S_OK(r.json())
    except requests.exceptions.Timeout:
      return S_ERROR('Authentication server is not answer.')
    except requests.exceptions.RequestException as ex:
      return S_ERROR(r.content or ex)
    except Exception as ex:
      return S_ERROR('Cannot read response: %s' % ex)

  def getProxyWithToken(self, token):
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
    url = '%ss:%s/g:%s/proxy?lifetime=%s' % (proxyAPI, setup, self.group, self.lifetime)
    voms = self.voms or Registry.getGroupOption(self.group, "AutoAddVOMS", False)
    if voms:
      url += '&voms=%s' % voms

    # Get REST endpoints from ConfigurationService
    try:
      r = requests.get(url, headers={'Authorization': 'Bearer ' + token}, verify=False)
      r.raise_for_status()
      print(r.text)
      proxy = decode(r.text)[0]
    except requests.exceptions.Timeout:
      return S_ERROR('Time out')
    except requests.exceptions.RequestException as e:
      return S_ERROR(str(e))
    except Exception as e:
      return S_ERROR('Cannot read response: %s' % e)

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