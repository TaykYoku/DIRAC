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
  {'access_token': 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjZldm5HWnN2aDBCWFM3c3FoTWVTSGE4LW5oc3g0Rk9KRTNPSlZ0azNLcEEifQ.eyJncm91cCI6ImNoZWNraW4taW50ZWdyYXRpb25fdXNlciIsInN1YiI6Ijk3ZmFkZjYzZTU1ZWEzNThhNGYwODRlNGMxMzY0NzVlMzc3MzU3YzY3MjMyNjlmMjNlYjlhYmE0MzdmZDZkOWRAZWdpLmV1IiwiaXNzIjoiaHR0cHM6Ly9tYXJvc3ZuMzIuaW4ycDMuZnIvRElSQUMvYXV0aCIsInNldHVwIjoiRUdJLVByb2R1Y3Rpb24iLCJleHAiOjE2MjEzMTcxODQsInNjb3BlIjoiZzpjaGVja2luLWludGVncmF0aW9uX3VzZXIiLCJpYXQiOjE2MjEyNzM5ODR9.a95Xwxtsy1QVKhA8rl7soWw0YLC40M0VRRts4hQme6rC1_a__SuhD3ps1PtQnJRYK1NdbqHh7_uPaLIdCkMGvDmovwVyUzBd9usi1wHeATu06k0226REPrsfl_g2yaoqeHspel_BCEVJLRCeGVMpAXWVhUb3gLaOx4XilV3jQBevqXxYiBPeiu5gyRxFe5mhSFK7B6atPiBOUNAUDxUPj9Zz5rq954sQvjz-SWVdmFMOxXKuXNCH0HnWUccID54BLp-OanhN0TcyKjrU7RdFb2UnMFbWOjitF4RXT8qXKKL1NkDUXCX4t-c1poncC9d_tgtIxViy7OlYhoXJyGFVqQ',
   'expires_in': 864000,
   'expires_at': 1621360384,
   'token_type': 'Bearer',
   'client_id': '1hlUgttap3P9oTSXUwpIT50TVHxCflN3O98uHP217Y',
   'scope': u'g:checkin-integration_user',
   'refresh_token': 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjZldm5HWnN2aDBCWFM3c3FoTWVTSGE4LW5oc3g0Rk9KRTNPSlZ0azNLcEEifQ.eyJzdWIiOiI5N2ZhZGY2M2U1NWVhMzU4YTRmMDg0ZTRjMTM2NDc1ZTM3NzM1N2M2NzIzMjY5ZjIzZWI5YWJhNDM3ZmQ2ZDlkQGVnaS5ldSIsImlzcyI6Imh0dHBzOi8vbWFyb3N2bjMyLmluMnAzLmZyL0RJUkFDL2F1dGgiLCJzZXR1cCI6IkVHSS1Qcm9kdWN0aW9uIiwiY2xpZW50X2lkIjoiMWhsVWd0dGFwM1A5b1RTWFV3cElUNTBUVkh4Q2ZsTjNPOTh1SFAyMTdZIiwiZXhwIjoxNjIxMzYwMzg0LCJzY29wZSI6Imc6Y2hlY2tpbi1pbnRlZ3JhdGlvbl91c2VyIiwiaWF0IjoxNjIxMjczOTg0fQ.ixOeAnauORbDTmUVZ48d6UjS7Ks3HuhKlpumrhJwK_sQSye8ZeahQfV_2PfF9sozS79FbHaS1y7w8bcCMg7iaM6_pDtueK2rSC90q4deuWPOAVv6iGA2hX-94hBCDAYepPWFPPwPZ3iGzTiYmBIbbLjQ9NC3xrg0OQeWmbTVFk6p8himIRGS1BvlOTvYEIxQrwxV8wseIT-NrmplpBWV6mWl1NC2dCRo-BtW1QzWYwGugcf2wRQYposcwP6x-jW-AmaqsHpNr57kkSGfsbd0DlBvuHZO0zW6QYsvX6k4VJVQubjPs9028ot0x9eOaVXClPbeJMwtS0H8AP1BThvdQA'}
  payload = {'sub': 'user',
             'iss': 'issuer',
             'iat': int(time.time()),
             'exp': int(time.time()) + (12 * 3600)),
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
