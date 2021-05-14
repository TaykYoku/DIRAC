""" Auth class is a front-end to the Auth Database
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import json
from time import time
from pprint import pprint
from M2Crypto import RSA, BIO
from authlib.jose import jwk
from sqlalchemy import Column, Integer, Text, String
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm.exc import MultipleResultsFound, NoResultFound
from authlib.jose import KeySet, RSAKey
from authlib.common.security import generate_token
from sqlalchemy.ext.declarative import declarative_base

from DIRAC import S_OK, S_ERROR, gLogger, gConfig
from DIRAC.Core.Base.SQLAlchemyDB import SQLAlchemyDB

__RCSID__ = "$Id$"


Model = declarative_base()


class JWK(Model):
  __tablename__ = 'JWK'
  __table_args__ = {'mysql_engine': 'InnoDB',
                    'mysql_charset': 'utf8'}
  kid = Column(String(255), unique=True, primary_key=True, nullable=False)
  key = Column(Text, nullable=False)
  expires_at = Column(Integer, nullable=False, default=0)


class AuthSession(Model):
  __tablename__ = 'Sessions'
  __table_args__ = {'mysql_engine': 'InnoDB',
                    'mysql_charset': 'utf8'}
  id = Column(String(255), unique=True, primary_key=True, nullable=False)
  state = Column(String(255))
  uri = Column(String(255))
  client_id = Column(String(255))
  user_id = Column(String(255))
  username = Column(String(255))
  expires_at = Column(Integer, nullable=False, default=0)
  expires_in = Column(Integer, nullable=False, default=0)
  interval = Column(Integer, nullable=False, default=5)
  verification_uri = Column(String(255))
  verification_uri_complete = Column(String(255))
  user_code = Column(String(255))
  device_code = Column(String(255))
  scope = Column(String(255))


class AuthDB(SQLAlchemyDB):
  """ AuthDB class is a front-end to the OAuth Database
  """
  def __init__(self):
    """ Constructor
    """
    super(AuthDB, self).__init__()
    self._initializeConnection('Framework/AuthDB')
    result = self.__initializeDB()
    if not result['OK']:
      raise Exception("Can't create tables: %s" % result['Message'])
    self.session = scoped_session(self.sessionMaker_o)

  def __initializeDB(self):
    """ Create the tables
    """
    tablesInDB = self.inspector.get_table_names()

    # JWK
    if 'JWK' not in tablesInDB:
      try:
        JWK.__table__.create(self.engine)  # pylint: disable=no-member
      except Exception as e:
        return S_ERROR(e)

    # Sessions
    if 'Sessions' not in tablesInDB:
      try:
        AuthSession.__table__.create(self.engine)  # pylint: disable=no-member
      except Exception as e:
        return S_ERROR(e)

    return S_OK()

  def generateRSAKeys(self):
    """ Generate an RSA keypair with an exponent of 65537 in PEM format
    
        :return: S_OK/S_ERROR
    """
    key = RSAKey.generate_key(is_private=True)
    dictKey = dict(key=json.dumps(key.as_dict()),
                   expires_at=time() + (30 * 24 *3600),
                   kid=KeySet([key]).as_dict()['keys'][0]['kid'])
    
    session = self.session()
    try:
      session.add(JWK(**dictKey))
      session.query(JWK).filter(JWK.expires_at < time()).delete()
    except Exception as e:
      return self.__result(session, S_ERROR('Could not generate keys: %s' % e))
    return self.__result(session, S_OK(dictKey))

  def getKeySet(self):
    """ Get key set
    
        :return: S_OK(obj)/S_ERROR()
    """
    keys = []
    result = self.getActiveKeys()
    if result['OK'] and not result['Value']:
      result = self.generateRSAKeys()
      if result['OK']:
        result = self.getActiveKeys()
    if not result['OK']:
      return result
    for keyDict in result['Value']:
      key = RSAKey.import_key(json.loads(keyDict['key']))
      keys.append(key)
    return S_OK(KeySet(keys))
  
  def getJWKs(self):
    """ Get JWKs list
    
        :return: S_OK(dict)/S_ERROR()
    """
    keys = []
    result = self.getKeySet()
    if not result['OK']:
      return result
    for k in result['Value'].as_dict()['keys']:
      keys.append({'n': k['n'], "kty": k['kty'], "e": k['e'], "kid": k['kid']})
    return S_OK({'keys': keys})
  
  def getPrivateKey(self):
    """ Get private key
    
        :return: S_OK(obj)/S_ERROR()
    """
    result = self.getActiveKeys()
    if not result['OK']:
      return result
    newer = {}
    for d in result['Value']:
      if d['expires_at'] > newer.get('expires_at', time() + (24 * 3600)):
        newer = d
    if not newer.get('key'):
      result = self.generateRSAKeys()
      if not result['OK']:
        return result
      newer = result['Value']
    return S_OK(RSAKey.import_key(json.loads(newer['key'])))

  def getActiveKeys(self):
    """ Get active keys
    
        :return: S_OK(list)/S_ERROR()
    """
    session = self.session()
    try:
      jwks = session.query(JWK).filter(JWK.expires_at > time()).all()
    except NoResultFound:
      return self.__result(session, S_OK([]))
    except Exception as e:
      return self.__result(session, S_ERROR(str(e)))
    return self.__result(session, S_OK([self.__rowToDict(jwk) for jwk in jwks]))
  
  def removeKeys(self):
    """ Get active keys
    
        :return: S_OK(list)/S_ERROR()
    """
    session = self.session()
    try:
      session.query(JWK).delete()
    except Exception as e:
      return self.__result(session, S_ERROR(str(e)))
    return self.__result(session, S_OK())

  def removeExpiredSessions(self):
    """ Remove expired sessions """
    session = self.session()
    try:
      session.query(AuthSession).filter(AuthSession.expires_at < time()).delete()
    except Exception as e:
      return self.__result(session, S_ERROR(str(e)))
    return self.__result(session, S_OK())

  def addSession(self, data):
    """ Add new session

        :param dict data: session metadata

        :return: S_OK(dict)/S_ERROR()
    """
    attrts = {}
    if not data.get('expires_at'):
      data['expires_at'] = data['expires_in'] + time()
    gLogger.debug('Add authorization session:', data)
    for k, v in data.items():
      if k not in AuthSession.__dict__.keys():
        self.log.warn('%s is not expected as authentication session attribute.' % k)
      else:
        attrts[k] = v
    session = self.session()
    try:
      session.add(AuthSession(**attrts))
    except Exception as e:
      return self.__result(session, S_ERROR('Could not add Token: %s' % e))
    return self.__result(session, S_OK('Token successfully added'))

  def updateSession(self, data, sessionID):
    """ Update session data

        :param dict data: data info
        :param str sessionID: sessionID

        :return: S_OK(object)/S_ERROR()
    """
    self.removeSession(sessionID=sessionID)
    return self.addSession(data)

  def removeSession(self, sessionID):
    """ Remove session

        :param str sessionID: session id

        :return: S_OK()/S_ERROR()
    """
    session = self.session()
    try:
      session.query(AuthSession).filter(AuthSession.id == sessionID).delete()
    except Exception as e:
      return self.__result(session, S_ERROR(str(e)))
    return self.__result(session, S_OK())

  def getSession(self, sessionID):
    """ Get client

        :param str sessionID: session id

        :return: S_OK(dict)/S_ERROR()
    """
    session = self.session()
    try:
      resData = session.query(AuthSession).filter(AuthSession.id == sessionID).first()
    except MultipleResultsFound:
      return self.__result(session, S_ERROR("%s is not unique ID." % sessionID))
    except NoResultFound:
      return self.__result(session, S_ERROR("%s session is expired." % sessionID))
    except Exception as e:
      return self.__result(session, S_ERROR(str(e)))
    return self.__result(session, S_OK(self.__rowToDict(resData)))
  
  def getSessionByUserCode(self, userCode):
    """ Get client

        :param str userCode: user code

        :return: S_OK(dict)/S_ERROR()
    """
    session = self.session()
    try:
      resData = session.query(AuthSession).filter(AuthSession.user_code == userCode).first()
    except MultipleResultsFound:
      return self.__result(session, S_ERROR("%s is not unique ID." % sessionID))
    except NoResultFound:
      return self.__result(session, S_ERROR("%s session is expired." % sessionID))
    except Exception as e:
      return self.__result(session, S_ERROR(str(e)))
    return self.__result(session, S_OK(self.__rowToDict(resData)))

  def __result(self, session, result=None):
    try:
      if not result['OK']:
        session.rollback()
      else:
        session.commit()
    except Exception as e:
      session.rollback()
      result = S_ERROR('Could not commit: %s' % (e))
    session.close()
    return result

  def __rowToDict(self, row):
    """ Convert sqlalchemy row to dictionary

        :param object row: sqlalchemy row

        :return: dict
    """
    return {c.name: str(getattr(row, c.name)) for c in row.__table__.columns} if row else {}
