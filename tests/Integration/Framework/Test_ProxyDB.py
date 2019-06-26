#!/bin/env python
""" This is a test of the ProxyDB
    It supposes that the DB is present and installed in DIRAC
"""

# pylint: disable=invalid-name,wrong-import-position,protected-access
import os
import re
import sys
import stat
import shutil
import tempfile
import commands
import unittest

from DIRAC.Core.Base.Script import parseCommandLine
parseCommandLine()

from DIRAC import gLogger, gConfig, S_OK, S_ERROR
from DIRAC.Core.Utilities.CFG import CFG
from DIRAC.Core.Security.X509Chain import X509Chain
from DIRAC.FrameworkSystem.DB.ProxyDB import ProxyDB

certsPath = os.path.join(os.environ['DIRAC'], 'DIRAC/tests/Integration/certs')

diracTestCACFG = """
Resources
{
  ProxyProviders
  {
    DIRAC_CA
    {
      ProxyProviderType = DIRACCA
      CAConfigFile = %s
      C = DN
      O = DIRACCA
    }
  }
}
""" % os.path.join(certsPath, 'ca/openssl_config_ca.cnf')

userCFG = """
Registry
{
  Users
  {
    # In dirac_user group
    user_ca
    {
      DN = /C=DN/O=DIRACCA/OU=None/CN=user_ca/emailAddress=user_ca@diracgrid.org
      DNProperties
      {
        -C_DN-O_DIRACCA-OU_None-CN_user_ca-emailAddress_user_ca@diracgrid.org
        {
          ProxyProviders = DIRAC_CA
          Groups = dirac_user
        }
      }
    }
    user_1
    {
      DN = /C=DN/O=DIRAC/CN=user_1
      DNProperties
      {
        -C_DN-O_DIRAC-OU_user_1
        {
          ProxyProviders =
          Groups = dirac_user
        }
      }
    }
    user_2
    {
      DN = /C=DN/O=DIRAC/CN=user_2
      DNProperties
      {
        -C_DN-O_DIRAC-OU_user_2
        {
        }
      }
    }
    user_3
    {
      DN = /C=DN/O=DIRAC/CN=user_3
    }
    # Not in dirac_user group
    user_4
    {
      DN = /C=DN/O=DIRAC/CN=user_4
    }
  }
  Groups
  {
    group_1
    {
      Users = user_ca, user_1, user_2, user_3
      VO = vo_1
    }
    group_2
    {
      Users = user_4
    }
  }
  VO
  {
    vo_1
    {
      VOMSName = vo_1
      VOMSServers
      {
      }
    }
  }
}
"""


class ProxyDBTestCase(unittest.TestCase):

  @classmethod
  def createProxy(self, userName, group, time, rfc=True, limit=False, vo=False, role=None, path=None):
    """ Create user proxy
    """
    userCertFile = os.path.join(self.userDir, userName + '.cert.pem')
    userKeyFile = os.path.join(self.userDir, userName + '.key.pem')
    self.proxyPath = path or os.path.join(self.userDir, userName + '.pem')
    if not vo:
      chain = X509Chain()
      # Load user cert and key
      retVal = chain.loadChainFromFile(userCertFile)
      if not retVal['OK']:
        gLogger.warn(retVal['Message'])
        return S_ERROR("Can't load %s" % userCertFile)
      retVal = chain.loadKeyFromFile(userKeyFile)
      if not retVal['OK']:
        gLogger.warn(retVal['Message'])
        if 'bad decrypt' in retVal['Message']:
          return S_ERROR("Bad passphrase")
        return S_ERROR("Can't load %s" % userKeyFile)
      result = chain.generateProxyToFile(self.proxyPath, time * 3600,
                                         limited=limit, diracGroup=group,
                                         rfc=rfc)
      if not result['OK']:
        return result
    else:
      cmd = 'voms-proxy-fake --cert %s --key %s -q' % (userCertFile, userKeyFile)
      cmd += ' -hostcert %s -hostkey %s' % (self.hostCert, self.hostKey)
      cmd += ' -uri fakeserver.cern.ch:15000'
      cmd += ' -voms "%s%s"' % (vo, role and ':%s' % role or '')
      cmd += ' -fqan "/%s/Role=%s/Capability=NULL"' % (vo, role)
      cmd += ' -hours %s -out %s' % (time, self.proxyPath)
      if limit:
        cmd += ' -limited'
      if rfc:
        cmd += ' -rfc'
      status, output = commands.getstatusoutput(cmd)
      if status:
        return S_ERROR(output)
    chain = X509Chain()
    result = chain.loadProxyFromFile(self.proxyPath)
    if not result['OK']:
      return result
    result = chain.generateProxyToString(12 * 3600, diracGroup=group)
    if not result['OK']:
      return result
    return S_OK((chain, result['Value']))

  @classmethod
  def setUpClass(cls):
    cls.failed = False
    cls.db = ProxyDB()

    # Add configuration
    cfg = CFG()
    cfg.loadFromBuffer(diracTestCACFG)
    gConfig.loadCFG(cfg)
    cfg.loadFromBuffer(userCFG)
    gConfig.loadCFG(cfg)

    # Prepare CA
    lines = []
    cfgDict = {}
    cls.caPath = os.path.join(certsPath, 'ca')
    cls.caConfigFile = os.path.join(cls.caPath, 'openssl_config_ca.cnf')
    # Save original configuration file
    shutil.copyfile(cls.caConfigFile, cls.caConfigFile + 'bak')
    # Parse
    fields = ['dir', 'database', 'serial', 'new_certs_dir', 'private_key', 'certificate']
    with open(cls.caConfigFile, "rw+") as caCFG:
      for line in caCFG:
        if re.findall('=', re.sub(r'#.*', '', line)):
          field = re.sub(r'#.*', '', line).replace(' ', '').rstrip().split('=')[0]
          line = 'dir = %s #PUT THE RIGHT DIR HERE!\n' % (cls.caPath) if field == 'dir' else line
          val = re.sub(r'#.*', '', line).replace(' ', '').rstrip().split('=')[1]
          if field in fields:
            for i in fields:
              if cfgDict.get(i):
                val = val.replace('$%s' % i, cfgDict[i])
            cfgDict[field] = val
            if not cfgDict[field]:
              cls.failed = '%s have empty value in %s' % (field, cls.caConfigFile)
        lines.append(line)
      caCFG.seek(0)
      caCFG.writelines(lines)
    for field in fields:
      if field not in cfgDict.keys():
        cls.failed = '%s value is absent in %s' % (field, cls.caConfigFile)
    cls.hostCert = os.path.join(certsPath, 'host/hostcert.pem')
    cls.hostKey = os.path.join(certsPath, 'host/hostkey.pem')
    cls.caCert = cfgDict['certificate']
    cls.caKey = cfgDict['private_key']
    os.chmod(cls.caKey, stat.S_IREAD)
    # Check directory for new certificates
    cls.newCertDir = cfgDict['new_certs_dir']
    if not os.path.exists(cls.newCertDir):
      os.makedirs(cls.newCertDir)
    for f in os.listdir(cls.newCertDir):
      os.remove(os.path.join(cls.newCertDir, f))
    # Empty the certificate database
    cls.index = cfgDict['database']
    with open(cls.index, 'w') as indx:
      indx.write('')
    # Write down serial
    cls.serial = cfgDict['serial']
    with open(cls.serial, 'w') as serialFile:
      serialFile.write('1000')

    # Create temporaly directory for users certificates
    cls.userDir = tempfile.mkdtemp(dir=certsPath)

    # Create user certificates
    for userName in ['no_user', 'user_1', 'user_2', 'user_3']:
      userConf = """[ req ]
        default_bits           = 2048
        encrypt_key            = yes
        distinguished_name     = req_dn
        prompt                 = no
        req_extensions         = v3_req
        [ req_dn ]
        C                      = DN
        O                      = DIRAC
        CN                     = %s
        [ v3_req ]
        # Extensions for client certificates (`man x509v3_config`).
        nsComment = "OpenSSL Generated Client Certificate"
        keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
        extendedKeyUsage = clientAuth
        """ % (userName)
      userConfFile = os.path.join(cls.userDir, userName + '.cnf')
      userReqFile = os.path.join(cls.userDir, userName + '.req')
      userKeyFile = os.path.join(cls.userDir, userName + '.key.pem')
      userCertFile = os.path.join(cls.userDir, userName + '.cert.pem')
      with open(userConfFile, "w") as f:
        f.write(userConf)
      status, output = commands.getstatusoutput('openssl genrsa -out %s 2048' % userKeyFile)
      if status:
        gLogger.error(output)
        exit()
      gLogger.debug(output)
      os.chmod(userKeyFile, stat.S_IREAD)
      status, output = commands.getstatusoutput('openssl req -config %s -key %s -new -out %s' %
                                                (userConfFile, userKeyFile, userReqFile))
      if status:
        gLogger.error(output)
        exit()
      gLogger.debug(output)
      cmd = 'openssl ca -config %s -extensions usr_cert -batch -days 375 -in %s -out %s'
      cmd = cmd % (cls.caConfigFile, userReqFile, userCertFile)
      status, output = commands.getstatusoutput(cmd)
      if status:
        gLogger.error(output)
        exit()
      gLogger.debug(output)

  def setUp(self):
    if self.failed:
       self.fail(self.failed)
    self.db._update('DELETE FROM ProxyDB_Proxies WHERE UserName IN ("user_ca", "user_1", "user_2", "user_3")')
    self.db._update('DELETE FROM ProxyDB_CleanProxies WHERE UserName IN ("user_ca", "user_1", "user_2", "user_3")')

  def tearDown(self):
    self.db._update('DELETE FROM ProxyDB_Proxies WHERE UserName IN ("user_ca", "user_1", "user_2", "user_3")')
    self.db._update('DELETE FROM ProxyDB_CleanProxies WHERE UserName IN ("user_ca", "user_1", "user_2", "user_3")')

  @classmethod
  def tearDownClass(cls):
    shutil.move(cls.caConfigFile + 'bak', cls.caConfigFile)
    if os.path.exists(cls.newCertDir):
      for f in os.listdir(cls.newCertDir):
        os.remove(os.path.join(cls.newCertDir, f))
    for f in os.listdir(cls.caPath):
      if re.match("%s..*" % cls.index, f) or f.endswith('.old'):
        os.remove(os.path.join(cls.caPath, f))
    if os.path.exists(cls.userDir):
      shutil.rmtree(cls.userDir)
    # Empty the certificate database
    with open(cls.index, 'w') as index:
      index.write('')
    # Write down serial
    with open(cls.serial, 'w') as serialFile:
      serialFile.write('1000')


class testDB(ProxyDBTestCase):

  def test_connectDB(self):
    """ Try to connect to the ProxyDB
    """
    res = self.db._connect()
    self.assertTrue(res['OK'])

  def test_getUsers(self):
    """ Try to get users from DB
    """
    field = '("%%s", "/C=DN/O=DIRAC/CN=%%s", %%s "PEM", TIMESTAMPADD(SECOND, %%s, UTC_TIMESTAMP()))%s' % ''
    # Fill table for test
    for table, values, fields in [('ProxyDB_Proxies',
                                  [field % ('user_1', 'user_1', '"group_1",', '800'),
                                   field % ('user_2', 'user_2', '"group_1",', '-1')],
                                  '(UserName, UserDN, UserGroup, Pem, ExpirationTime)'),
                                  ('ProxyDB_CleanProxies',
                                  [field % ('user_3', 'user_3', '', '43200')],
                                  '(UserName, UserDN, Pem, ExpirationTime)')]:
      result = self.db._update('INSERT INTO %s%s VALUES %s ;' % (table, fields, ', '.join(values)))
      self.assertTrue(result['OK'], '\n%s' % result.get('Message') or 'Error message is absent.')
    for user, exp, expect, log in [(False, 0, ['user_1', 'user_2', 'user_3'], '\n* Without arguments'),
                                   (False, 1200, ['user_3'], '* Request proxy live time'),
                                   ('user_2', 0, ['user_2'], '* Request user name'),
                                   ('no_user', 0, [], '* Request not exist user name')]:
      gLogger.info('%s..' % log)
      result = self.db.getUsers(validSecondsLeft=exp, userName=user)
      self.assertTrue(result['OK'], '\n%s' % result.get('Message') or 'Error message is absent.')
      usersList = []
      for line in result['Value']:
        if line['Name'] in ['user_1', 'user_2', 'user_3']:
          usersList.append(line['Name'])
      self.assertEqual(set(expect), set(usersList), '%s, when expected %s' % (usersList, expect))

  def test_purgeExpiredProxies(self):
    """ Try to purge expired proxies
    """
    cmd = 'INSERT INTO ProxyDB_Proxies(UserName, UserDN, UserGroup, Pem, ExpirationTime) VALUES '
    cmd += '("user_1", "/C=DN/O=DIRAC/CN=user_1", "group_1", "PEM", '
    cmd += 'TIMESTAMPADD(SECOND, -1, UTC_TIMESTAMP()));'
    result = self.db._query(cmd)
    self.assertTrue(result['OK'], '\n%s' % result.get('Message') or 'Error message is absent.')
    cmd = 'SELECT COUNT( * ) FROM ProxyDB_Proxies WHERE ExpirationTime < UTC_TIMESTAMP()'
    self.assertTrue(bool(self.db._query(cmd)['Value'][0][0] > 0))
    result = self.db.purgeExpiredProxies()
    self.assertTrue(result['OK'], '\n%s' % result.get('Message') or 'Error message is absent.')
    self.assertTrue(result['Value'] > 0, 'Must be more then null')
    self.assertFalse(bool(self.db._query(cmd)['Value'][0][0] > 0), "Must be null")

  def test_getRemoveProxy(self):
    """ Testing get, store proxy
    """
    gLogger.info('\n* Check that DB is clean..')
    result = self.db.getProxiesContent({'UserName': ['user_ca', 'user_1', 'user_2', 'user_3']}, {})
    self.assertTrue(result['OK'], '\n%s' % result.get('Message') or 'Error message is absent.')
    self.assertTrue(bool(int(result['Value']['TotalRecords']) == 0), 'In DB present proxies.')

    gLogger.info('* Check posible crashes when get proxy..')
    # Make record with not valid proxy, valid group, user and short expired time
    cmd = 'INSERT INTO ProxyDB_Proxies(UserName, UserDN, UserGroup, Pem, ExpirationTime) VALUES '
    cmd += '("user_1", "/C=DN/O=DIRAC/CN=user_1", "group_1", "PEM", '
    cmd += 'TIMESTAMPADD(SECOND, 1800, UTC_TIMESTAMP()));'
    result = self.db._update(cmd)
    self.assertTrue(result['OK'], '\n%s' % result.get('Message') or 'Error message is absent.')
    # Try to no correct getProxy requests
    for dn, group, reqtime, log in [('/C=DN/O=DIRAC/CN=user_1', 'group_1', 9999,
                                     'No proxy provider, set request time, not valid proxy in ProxyDB_Proxies'),
                                    ('/C=DN/O=DIRAC/CN=user_1', 'group_1', 0,
                                     'Not valid proxy in ProxyDB_Proxies'),
                                    ('/C=DN/O=DIRAC/CN=no_user', 'group', 0,
                                     'User no exist, proxy not in DB tables'),
                                    ('/C=DN/O=DIRAC/CN=user_1', 'group', 0,
                                     'Group not valid, proxy not in DB tables'),
                                    ('/C=DN/O=DIRAC/CN=user_1', 'group_1', 0,
                                     'No proxy provider for user, proxy not in DB tables')]:
      result = self.db.getProxy(dn, group, reqtime)
      self.assertFalse(result['OK'], 'Must be fail.')
      gLogger.info('== > %s:\nMsg: %s' % (log, result['Message']))
    # In the last case method found proxy and must to delete it as not valid
    cmd = 'SELECT COUNT( * ) FROM ProxyDB_Proxies WHERE UserName="user_1"'
    self.assertTrue(bool(self.db._query(cmd)['Value'][0][0] == 0), 'GetProxy method was not delete proxy.')

    gLogger.info('* Check that DB is clean..')
    result = self.db.getProxiesContent({'UserName': ['user_ca', 'user_1', 'user_2', 'user_3']}, {})
    self.assertTrue(result['OK'], '\n%s' % result.get('Message') or 'Error message is absent.')
    self.assertTrue(bool(int(result['Value']['TotalRecords']) == 0), 'In DB present proxies.')

    gLogger.info('* Generate proxy on the fly..')
    result = self.db.getProxy('/C=DN/O=DIRACCA/OU=None/CN=user_ca/emailAddress=user_ca@diracgrid.org',
                              'group_1', 1800)
    self.assertTrue(result['OK'], '\n%s' % result.get('Message') or 'Error message is absent.')

    gLogger.info('* Check that ProxyDB_CleanProxy contain generated proxy..')
    result = self.db.getProxiesContent({'UserName': 'user_ca'}, {})
    self.assertTrue(result['OK'], '\n%s' % result.get('Message') or 'Error message is absent.')
    self.assertTrue(bool(int(result['Value']['TotalRecords']) == 1), 'Generated proxy must be one.')
    for table, count in [('ProxyDB_Proxies', 0), ('ProxyDB_CleanProxies', 1)]:
      cmd = 'SELECT COUNT( * ) FROM %s WHERE UserName="user_ca"' % table
      self.assertTrue(bool(self.db._query(cmd)['Value'][0][0] == count))

    gLogger.info('* Check that DB is clean..')
    result = self.db.deleteProxy('/C=DN/O=DIRACCA/OU=None/CN=user_ca/emailAddress=user_ca@diracgrid.org',
                                 proxyProvider='DIRAC_CA')
    self.assertTrue(result['OK'], '\n%s' % result.get('Message') or 'Error message is absent.')
    result = self.db.getProxiesContent({'UserName': ['user_ca', 'user_1', 'user_2', 'user_3']}, {})
    self.assertTrue(result['OK'], '\n%s' % result.get('Message') or 'Error message is absent.')
    self.assertTrue(bool(int(result['Value']['TotalRecords']) == 0), 'In DB present proxies.')

    gLogger.info('* Upload proxy..')
    for user, dn, group, vo, time, res, log in [("user_1", '/C=DN/O=DIRAC/CN=user_1', "group_1", False, 12,
                                                 False, 'With group extansion'),
                                                ("user_1", '/C=DN/O=DIRAC/CN=user_1', False, "vo_1", 12,
                                                 False, 'With voms extansion'),
                                                ("user_1", '/C=DN/O=DIRAC/CN=user_1', False, False, 0,
                                                 False, 'Expired proxy'),
                                                ("no_user", '/C=DN/O=DIRAC/CN=no_user', False, False, 12,
                                                 False, 'Not exist user'),
                                                ("user_1", '/C=DN/O=DIRAC/CN=user_1', False, False, 12,
                                                 True, 'Valid proxy')]:
      gLogger.info('== > %s:' % log)
      result = self.createProxy(user, group, time, vo=vo)
      self.assertTrue(result['OK'], '\n%s' % result.get('Message') or 'Error message is absent.')
      chain = result['Value'][0]
      self.assertTrue(result['OK'], '\n%s' % result.get('Message') or 'Error message is absent.')
      result = self.db.generateDelegationRequest(chain, dn)
      self.assertTrue(result['OK'], '\n%s' % result.get('Message') or 'Error message is absent.')
      resDict = result['Value']
      result = chain.generateChainFromRequestString(resDict['request'], time * 3500)
      self.assertTrue(result['OK'], '\n%s' % result.get('Message') or 'Error message is absent.')
      result = self.db.completeDelegation(resDict['id'], dn, result['Value'])
      self.assertEqual(result['OK'], res, 'Must be ended %s%s' %
                                          (res and 'successful' or 'with error',
                                           ': %s' % result.get('Message') or 'Error message is absent.'))
      if not res:
        gLogger.info('Msg: %s' % (result['Message']))
      cmd = 'SELECT COUNT( * ) FROM ProxyDB_Proxies WHERE UserName="%s"' % user
      self.assertTrue(bool(self.db._query(cmd)['Value'][0][0] == 0))
      cmd = 'SELECT COUNT( * ) FROM ProxyDB_CleanProxies WHERE UserName="%s"' % user
      self.assertTrue(bool(self.db._query(cmd)['Value'][0][0] == res and 1 or 0))

    gLogger.info('* Get proxy when it store only in ProxyDB_CleanProxies..')
    # Try to get proxy that was stored in previous step
    for res, group, reqtime, log in [(False, 'group_1', 24 * 3600, 'Request time more that in stored proxy'),
                                     (False, 'group_2', 0, 'Request group not contain user'),
                                     (True, 'group_1', 0, 'Request time less that in stored proxy')]:
      gLogger.info('== > %s:' % log)
      result = self.db.getProxy('/C=DN/O=DIRAC/CN=user_1', group, reqtime)
      self.assertEqual(result['OK'], res, 'Must be ended %s%s' %
                                          (res and 'successful' or 'with error',
                                           ': %s' % result.get('Message') or 'Error message is absent.'))
      if res:
        chain = result['Value'][0]
        self.assertTrue(chain.isValidProxy()['OK'], '\n%s' % result.get('Message') or 'Error message is absent.')
        result = chain.getDIRACGroup()
        self.assertTrue(result['OK'], '\n%s' % result.get('Message') or 'Error message is absent.')
        self.assertEqual('group_1', result['Value'], 'Group must be group_1, not %s' % result['Value'])
      else:
        gLogger.info('Msg: %s' % (result['Message']))

    gLogger.info('* Check that DB is clean..')
    result = self.db.deleteProxy('/C=DN/O=DIRAC/CN=user_1', proxyProvider='Certificate')
    self.assertTrue(result['OK'], '\n%s' % result.get('Message') or 'Error message is absent.')
    result = self.db.getProxiesContent({'UserName': ['user_ca', 'user_1', 'user_2', 'user_3']}, {})
    self.assertTrue(result['OK'], '\n%s' % result.get('Message') or 'Error message is absent.')
    self.assertTrue(bool(int(result['Value']['TotalRecords']) == 0), 'In DB present proxies.')

    gLogger.info('* Get proxy when it store only in ProxyDB_Proxies..')
    # Make record with proxy that contain group
    result = self.createProxy('user_1', group, 12)
    self.assertTrue(result['OK'], '\n%s' % result.get('Message') or 'Error message is absent.')
    proxyStr = result['Value'][1]
    cmd = 'INSERT INTO ProxyDB_Proxies(UserName, UserDN, UserGroup, Pem, ExpirationTime) VALUES '
    cmd += '("user_1", "%s", "%s", "%s", TIMESTAMPADD(SECOND, 43200, UTC_TIMESTAMP()))' % (dn, group,
                                                                                           proxyStr)
    result = self.db._update(cmd)
    self.assertTrue(result['OK'], '\n%s' % result.get('Message') or 'Error message is absent.')
    # Try to get it
    result = self.db.getProxy(dn, group, 1800)
    self.assertTrue(result['OK'], '\n%s' % result.get('Message') or 'Error message is absent.')
    # Check that proxy contain group
    chain = result['Value'][0]
    self.assertTrue(chain.isValidProxy()['OK'], '\n%s' % result.get('Message') or 'Error message is absent.')
    result = chain.getDIRACGroup()
    self.assertTrue(result['OK'], '\n%s' % result.get('Message') or 'Error message is absent.')
    self.assertEqual('group_1', result['Value'], 'Group must be group_1, not %s' % result['Value'])

    gLogger.info('* Check that DB is clean..')
    result = self.db.deleteProxy('/C=DN/O=DIRAC/CN=user_1')
    self.assertTrue(result['OK'], '\n%s' % result.get('Message') or 'Error message is absent.')
    result = self.db.getProxiesContent({'UserName': ['user_ca', 'user_1', 'user_2', 'user_3']}, {})
    self.assertTrue(result['OK'], '\n%s' % result.get('Message') or 'Error message is absent.')
    self.assertTrue(bool(int(result['Value']['TotalRecords']) == 0), 'In DB present proxies.')

    gLogger.info('* Get VOMS proxy..')
    # Create proxy with VOMS extansion
    result = self.createProxy('user_1', 'group_1', 12, vo='vo_1', role='role_2')
    self.assertTrue(result['OK'], '\n%s' % result.get('Message') or 'Error message is absent.')

    proxyStr = result['Value'][1]
    cmd = 'INSERT INTO ProxyDB_Proxies(UserName, UserDN, UserGroup, Pem, ExpirationTime) VALUES '
    cmd += '("user_1", "/C=DN/O=DIRAC/CN=user_1", "group_1", "%s", ' % proxyStr
    cmd += 'TIMESTAMPADD(SECOND, 43200, UTC_TIMESTAMP()))'
    result = self.db._update(cmd)
    self.assertTrue(result['OK'], '\n%s' % result.get('Message') or 'Error message is absent.')
    # Try to get proxy with VOMS extansion
    for dn, group, role, time, log in [('/C=DN/O=DIRAC/CN=user_4', 'group_2', False, 9999,
                                        'Not exist VO for current group'),
                                       ('/C=DN/O=DIRAC/CN=user_1', 'group_1', 'role_1', 9999,
                                        'Stored proxy already have different VOMS extansion'),
                                       ('/C=DN/O=DIRACCA/OU=None/CN=user_ca/emailAddress=user_ca@diracgrid.org',
                                        'group_1', 'role_1', 9999, 'Not correct VO configuration')]:
      result = self.db.getVOMSProxy(dn, group, time, role)
      self.assertFalse(result['OK'], 'Must be fail.')
      gLogger.info('== > %s:\nMsg: %s' % (log, result['Message']))
    # Check stored proxies
    for table, user, count in [('ProxyDB_Proxies', 'user_1', 1), ('ProxyDB_CleanProxies', 'user_ca', 1)]:
      cmd = 'SELECT COUNT( * ) FROM %s WHERE UserName="%s"' % (table, user)
      self.assertTrue(bool(self.db._query(cmd)['Value'][0][0] == count))

    gLogger.info('* Delete proxies..')
    for dn, table in [('/C=DN/O=DIRAC/CN=user_1', 'ProxyDB_Proxies'),
                      ('/C=DN/O=DIRACCA/OU=None/CN=user_ca/emailAddress=user_ca@diracgrid.org',
                       'ProxyDB_CleanProxies')]:
      result = self.db.deleteProxy(dn)
      self.assertTrue(result['OK'], '\n%s' % result.get('Message') or 'Error message is absent.')
      cmd = 'SELECT COUNT( * ) FROM %s WHERE UserName="user_ca"' % table
      self.assertTrue(bool(self.db._query(cmd)['Value'][0][0] == 0))


if __name__ == '__main__':
  suite = unittest.defaultTestLoader.loadTestsFromTestCase(ProxyDBTestCase)
  suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(testDB))
  testResult = unittest.TextTestRunner(verbosity=2).run(suite)
  sys.exit(not testResult.wasSuccessful())
