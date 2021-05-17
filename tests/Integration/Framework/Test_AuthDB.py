""" This is a test of the AuthDB
    It supposes that the DB is present and installed in DIRAC
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import time
from authlib.jose import JsonWebKey, JsonWebSignature, jwt
from authlib.common.encoding import json_b64encode, urlsafe_b64decode, json_loads

from DIRAC.FrameworkSystem.DB.AuthDB import AuthDB


db = AuthDB()


def test_Token():
  """ Try to revoke/save/get tokens
  """
  # Get key
  result = db.getPrivateKey()
  assert result['OK'], result['Message']
  privat_key = result['Value']['key']

  # Sign token
  payload = {'sub': 'user',
             'iss': 'issuer',
             'exp': time.time() + 3600,
             'scope': 'scope',
             'setup': 'setup',
             'group': 'my_group'}
  token = jwt.encode({'alg': 'RS256'}, payload, privat_key)
  # Expired token
  payload['exp'] = 0
  exp_token = jwt.encode({'alg': 'RS256'}, payload, privat_key)

  # Remove if exists in DB
  db.unrevokeToken(token)

  # Check if token revoked
  result = db.isTokenRevoked(token)
  assert result['OK'], result['Message']
  assert result['Value'] == False

  # Revoke token
  result = db.revokeToken(token)
  assert result['OK'], result['Message']

  # Revoke expired token
  result = db.revokeToken(exp_token)
  assert result['OK'], result['Message']

  # Check if token revoked
  result = db.isTokenRevoked(token)
  assert result['OK'], result['Message']
  assert result['Value'] == True

  # Check if expired token there
  result = db.isTokenRevoked(exp_token)
  assert result['OK'], result['Message']
  assert result['Value'] == False


def test_keys():
  """ Try to store/get/remove keys
  """
  # JWS
  jws = JsonWebSignature(algorithms=['RS256'])
  code_payload = {'user_id': 'user',
                 'scope': 'scope',
                 'redirect_uri': 'redirect_uri',
                 'client_id': 'client',
                 'code_challenge': 'code_challenge'}

  # Token metadata
  header = {'alg': 'RS256'}
  payload = {'sub': 'user',
             'iss': 'issuer',
             'scope': 'scope',
             'setup': 'setup',
             'group': 'my_group'}

  # Remove all keys
  db.removeKeys()

  # Check active keys
  result = db.getActiveKeys()
  assert result['OK'], result['Message']
  assert result['Value'] == []

  # Create new one
  result = db.getPrivateKey()
  assert result['OK'], result['Message']

  # Sign token
  header['kid'] = result['Value']['kid']
  private_key = result['Value']['key']
  token = jwt.encode(header, payload, private_key)
  # Sign auth code
  code = jws.serialize_compact(header, json_b64encode(code_payload), private_key)

  # Get public key set
  result = db.getKeySet()
  assert result['OK'], result['Message']
  _payload = jwt.decode(token, JsonWebKey.import_key_set(result['Value'].as_dict()))
  assert _payload == payload
  data = jws.deserialize_compact(code, result['Value'].keys[0])
  _code_payload = json_loads(urlsafe_b64decode(data['payload']))
  assert _code_payload == code_payload

  # Get JWK
  result = db.getJWKs()
  assert result['OK'], result['Message']
  _payload = jwt.decode(token, JsonWebKey.import_key_set(result['Value']))
  assert _payload == payload, result['Value']


def test_Sessions():
  """ Try to store/get/remove Sessions
  """
  # Example of the new session metadata
  sData1 = {'client_id': 'DIRAC_CLI',
            'device_code': 'SsoGTDglu6LThpx0CigM9i9J72B5atZ24ULr6R1awm',
            'expires_in': 1800,
            'id': 'SsoGTDglu6LThpx0CigM9i9J72B5atZ24ULr6R1awm',
            'interval': 5,
            'scope': 'g:my_group',
            'uri': 'https://domain.com/DIRAC/auth/device?&response_type=device&client_id=DIRAC_CLI&scope=g:my_group',
            'user_code': 'MDKP-MXMF',
            'verification_uri': 'https://domain.com/DIRAC/auth/device',
            'verification_uri_complete': u'https://domain.com/DIRAC/auth/device?user_code=MDKP-MXMF'}
  
  # Example of the updated session
  sData2 = {'client_id': 'DIRAC_CLI',
            'device_code': 'SsoGTDglu6LThpx0CigM9i9J72B5atZ24ULr6R1awm',
            'expires_in': 1800,
            'id': 'SsoGTDglu6LThpx0CigM9i9J72B5atZ24ULr6R1awm',
            'interval': 5,
            'scope': 'g:my_group',
            'uri': 'https://domain.com/DIRAC/auth/device?&response_type=device&client_id=DIRAC_CLI&scope=g:my_group',
            'user_code': 'MDKP-MXMF',
            'verification_uri': 'https://domain.com/DIRAC/auth/device',
            'verification_uri_complete': u'https://domain.com/DIRAC/auth/device?user_code=MDKP-MXMF',
            'user_id': 'username'}

  # Remove old session
  db.removeSession(sData1['id'])

  # Add session
  result = db.addSession(sData1)
  assert result['OK'], result['Message']

  # Get session
  result = db.getSessionByUserCode(sData1['user_code'])
  assert result['OK'], result['Message']
  assert result['Value']['device_code'] == sData1['device_code']
  assert result['Value'].get('user_id') != sData2['user_id']

  # Update session
  result = db.updateSession(sData2, sData1['id'])
  assert result['OK'], result['Message']

  # Get session
  result = db.getSession(sData2['id'])
  assert result['OK'], result['Message']
  assert result['Value']['device_code'] == sData2['device_code']
  assert result['Value']['user_id'] == sData2['user_id']

  # Remove session
  result = db.removeSession(sData2['id'])
  assert result['OK'], result['Message']

  # Make sure that the session is absent
  result = db.getSession(sData2['id'])
  assert result['OK'], result['Message']
  assert not result['Value']
