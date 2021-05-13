import os

from M2Crypto import RSA, BIO
from authlib.jose import jwk

from DIRAC import S_OK, S_ERROR
from DIRAC.Core.Utilities import DErrno
from DIRAC.Core.Security.Locations import getJWKKeyPairLocation


def generate_RSA(bits=4096):
  """ Generate an RSA keypair with an exponent of 65537 in PEM format
  
      :param int bits: The key length in bits
      
      :return: private key and public key
  """
  new_key = RSA.gen_key(bits, 65537)
  memory = BIO.MemoryBuffer()
  new_key.save_key_bio(memory, cipher=None)
  private_key = memory.getvalue()
  new_key.save_pub_key_bio(memory)
  return private_key, memory.getvalue()


def getJWKs():
  """ Get JWKs
  """
  keys = []
  fileDict = getJWKKeyPairLocation()
  for k in ['key.pub', 'key.pub.old']:
    if fileDict.get(k):
      with open(fileDict[k], 'rb') as f:
        key_pub = f.read()
      keys.append(jwk.dumps(key_pub, kty='RSA', alg='RS256'))
  return {'keys': keys}


def updateJWKs():
  """ Update RSA key pair
  
      :return: S_OK/S_ERROR
  """
  path = None
  retVal = gConfig.getOption('%s/Grid-Security' % g_SecurityConfPath)
  if retVal['OK']:
    path = retVal['Value']
  path = (path or "%s/etc/grid-security/" % DIRAC.rootPath) + 'jwtRS256'

  privat, public = generate_RSA()
  fileDict = getJWKKeyPairLocation()
  old_public = fileDict.get('key.pub')
  if old_public and os.path.isfile(old_public):
    os.rename(old_public, '%s.key.pub.old' % path)

  try:
    with open('%s.key' % path, 'wb') as fd:
      fd.write(privat.encode("UTF-8"))
    with open('%s.key.pub' % path, 'wb') as fd:
      fd.write(public.encode("UTF-8"))
  except Exception as e:
    return S_ERROR(DErrno.EWF, " %s: %s" % (fileName, repr(e).replace(',)', ')')))
  return S_OK()


def createJWKsIfNeeded():
  fileDict = getJWKKeyPairLocation()
  if not fileDict.get('key') or not fileDict.get('key.pub'):
    return updateJWKs()
  return S_OK()
