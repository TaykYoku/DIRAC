""" Auth class is a front-end to the Auth Database
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import json
from time import time
from pprint import pprint
from authlib.oauth2.rfc6749.wrappers import OAuth2Token
from authlib.integrations.sqla_oauth2 import OAuth2ClientMixin, OAuth2TokenMixin
from sqlalchemy import Column, Integer, Text, BigInteger, String
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm.exc import MultipleResultsFound, NoResultFound
from sqlalchemy.types import TypeDecorator, VARCHAR
from sqlalchemy.ext.mutable import Mutable
from sqlalchemy.ext.declarative import declarative_base

from DIRAC import S_OK, S_ERROR, gLogger, gConfig
from DIRAC.Core.Base.SQLAlchemyDB import SQLAlchemyDB
from DIRAC.ConfigurationSystem.Client.Utilities import getAuthClientsFromCS

__RCSID__ = "$Id$"


# Next two classes to help sqlalchemy work with dicts
# https://docs.sqlalchemy.org/en/14/orm/extensions/mutable.html#establishing-mutability-on-scalar-column-values
class MutableDict(Mutable, dict):
    @classmethod
    def coerce(cls, key, value):
        "Convert plain dictionaries to MutableDict."

        if not isinstance(value, MutableDict):
            if isinstance(value, dict):
                return MutableDict(value)

            # this call will raise ValueError
            return Mutable.coerce(key, value)
        else:
            return value

    def __setitem__(self, key, value):
        "Detect dictionary set events and emit change events."

        dict.__setitem__(self, key, value)
        self.changed()

    def __delitem__(self, key):
        "Detect dictionary del events and emit change events."

        dict.__delitem__(self, key)
        self.changed()

class JSONEncodedDict(TypeDecorator):
    "Represents an immutable structure as a json-encoded string."

    impl = VARCHAR(255)

    def process_bind_param(self, value, dialect):
        if value is not None:
            value = json.dumps(value)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            value = json.loads(value)
        return value

Model = declarative_base()

class Client(Model, OAuth2ClientMixin):
  __tablename__ = 'Clients'
  __table_args__ = {'mysql_engine': 'InnoDB',
                    'mysql_charset': 'utf8'}
  id = Column(Integer, primary_key=True, nullable=False)
  # Parameter names must match field names to avoid AttributeError exception
  client_metadata = Column('client_metadata', MutableDict.as_mutable(JSONEncodedDict))
  _client_metadata = None


class Token(Model, OAuth2TokenMixin):
  __tablename__ = 'Tokens'
  __table_args__ = {'mysql_engine': 'InnoDB',
                    'mysql_charset': 'utf8'}
  id = Column(BigInteger, unique=True, primary_key=True, nullable=False)
  # access_token too large for varchar(255)
  # 767 bytes is the stated prefix limitation for InnoDB tables in MySQL version 5.6
  # https://stackoverflow.com/questions/1827063/mysql-error-key-specification-without-a-key-length
  access_token = Column(Text, nullable=False)
  # client_id too large
  client_id = Column(String(255))
  provider = Column(Text)
  user_id = Column(String(255), nullable=False)

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

    # Clients
    if 'Clients' not in tablesInDB:
      try:
        Client.__table__.create(self.engine)  # pylint: disable=no-member
      except Exception as e:
        return S_ERROR(e)

    # Tokens
    if 'Tokens' not in tablesInDB:
      try:
        Token.__table__.create(self.engine)  # pylint: disable=no-member
      except Exception as e:
        return S_ERROR(e)

    return S_OK()

  def addClient(self, data):
    """ Add new client

        :param dict data: client metadata

        :return: S_OK(dict)/S_ERROR()
    """
    #TODO: remove debug
    print('============ addClient ============')
    pprint(data)
    session = self.session()
    client = Client(**data)
    print('------ client')
    pprint(client.client_metadata)
    client.set_client_metadata(data['client_metadata'])
    pprint(client.client_metadata)
    print('-------------')

    try:
      res = client.client_info
      res['client_metadata'] = client.client_metadata
      pprint(res)
      session.add(client)
      print('======== session.add(client)')
      pprint(res)
    except Exception as e:
      return self.__result(session, S_ERROR('Could not add Client: %s' % e))
    return self.__result(session, S_OK(res))
  
  def removeClient(self, clientID):
    """ Remove client

        :param str clientID: client id

        :return: S_OK()/S_ERROR()
    """
    session = self.session()
    try:
      session.query(Client).filter(Client.client_id==clientID).delete()
    except Exception as e:
      return self.__result(session, S_ERROR(str(e)))
    return self.__result(session, S_OK())

  def getClient(self, clientID):
    """ Get client

        :param str clientID: client id

        :return: S_OK(dict)/S_ERROR()
    """
    # To begin with, let's see if this client is described in the configuration
    result = getAuthClientsFromCS()
    if not result['OK']:
      return result
    clientsDict = result['Value']
    for cliDict in list(clientsDict.values()):
      if clientID == cliDict['client_id']:
        cliDict.get('client_id_issued_at', int(time()))
        cliDict.get('client_secret_expires_at', 0)
        return S_OK(cliDict)
    
    # If not let's search it in the database
    session = self.session()
    try:
      client = session.query(Client).filter(Client.client_id==clientID).first()
      session.commit()
      data = client.client_info
      data['client_metadata'] = client.client_metadata
    except MultipleResultsFound:
      return self.__result(session, S_ERROR("%s is not unique ID." % clientID))
    except NoResultFound:
      return self.__result(session, S_ERROR("%s client not registred." % clientID))
    except Exception as e:
      return self.__result(session, S_ERROR(str(e)))
    return self.__result(session, S_OK(data))  # client.client_info.update({'redirect_uri': redirect_uri})))

  # def getClientByID(self, clientID, redirect_uri=None, **kwargs):
  #   session = self.session()
  #   try:
  #     client = session.query(Client).filter(Client.client_id==clientID).one()
  #     if not redirect_uri:
  #       redirect_uri = client.get_default_redirect_uri()
  #     elif not client.check_redirect_uri(redirect_uri):
  #       self.__result(session, S_ERROR("redirect_uri: '%s' is wrong for %s client." % (redirect_uri, clientID)))
  #     resDict = client.client_info
  #     resDict['redirect_uri'] = redirect_uri
  #   except MultipleResultsFound:
  #     return self.__result(session, S_ERROR("%s is not unique ID." % clientID))
  #   except NoResultFound:
  #     return self.__result(session, S_ERROR("%s client not registred." % clientID))
  #   except Exception as e:
  #     return self.__result(session, S_ERROR(str(e)))
  #   return self.__result(session, S_OK(resDict))#client.client_info.update({'redirect_uri': redirect_uri})))

  def storeToken(self, metadata):
    """ Save token

        :param dict metadata: token info

        :return: S_OK(str)/S_ERROR()
    """
    attrts = {}
    print('========= STORE TOKEN')
    pprint(metadata)
    print('---------------------')
    for k, v in metadata.items():
      if k not in Token.__dict__.keys():
        self.log.warn('%s is not expected as token attribute.' % k)
      else:
        attrts[k] = v
    attrts['id'] = hash(attrts['access_token'])

    session = self.session()
    try:
      session.add(Token(**attrts))
    except Exception as e:
      return self.__result(session, S_ERROR('Could not add Token: %s' % e))
    return self.__result(session, S_OK('Token successfully added'))
  
  def updateToken(self, token, refreshToken):
    """ Update token

        :param dict token: token info
        :param str refreshToken: refresh token

        :return: S_OK(object)/S_ERROR()
    """
    session = self.session()
    try:
      session.update(Token(**token)).where(Token.refresh_token==refreshToken)
    except MultipleResultsFound:
      return self.__result(session, S_ERROR("%s is not unique." % refreshToken))
    except NoResultFound:
      return self.__result(session, S_ERROR("%s token not found." % refreshToken))
    except Exception as e:
      return self.__result(session, S_ERROR(str(e)))
    return self.__result(session, S_OK(OAuth2Token(token)))

  def removeToken(self, access_token=None, refresh_token=None):
    """ Remove token

        :param str access_token: access token
        :param str refresh_token: refresh token

        :return: S_OK(object)/S_ERROR()
    """
    session = self.session()
    try:
      if access_token:
        session.query(Token).filter(Token.access_token==access_token).delete()
      if refresh_token:
        session.query(Token).filter(Token.refresh_token==refresh_token).delete()
    except Exception as e:
      return self.__result(session, S_ERROR(str(e)))
    return self.__result(session, S_OK('Token successfully removed'))
  
  def getTokenByUserIDAndProvider(self, userID, provider):
    session = self.session()
    try:
      token = session.query(Token).filter(Token.user_id==userID, Token.provider==provider).first()
    except NoResultFound:
      return self.__result(session, S_ERROR("Token not found."))
    except Exception as e:
      return self.__result(session, S_ERROR(str(e)))
    return self.__result(session, S_OK(self.__rowToDict(token)))
  
  def getIdPTokens(self, IdP, userIDs=None):
    session = self.session()
    try:
      if userIDs:
        tokens = session.query(Token).filter(Token.provider==IdP).filter(Token.user_id.in_(set(userIDs))).all()
      else:
        tokens = session.query(Token).filter(Token.provider==IdP).all()
    except NoResultFound:
      return self.__result(session, S_ERROR("Tokens not found."))
    except Exception as e:
      return self.__result(session, S_ERROR(str(e)))
    return self.__result(session, S_OK([OAuth2Token(self.__rowToDict(t)) for t in tokens]))

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