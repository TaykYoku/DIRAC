""" Auth class is a front-end to the Auth Database
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import re
import json
import pprint
import random
import string
from authlib.common.security import generate_token

from ast import literal_eval
from datetime import datetime, timedelta

from DIRAC import gConfig, S_OK, S_ERROR, gLogger
from DIRAC.Core.Base.SQLAlchemyDB import SQLAlchemyDB

__RCSID__ = "$Id$"

from authlib.oauth2.rfc6749.wrappers import OAuth2Token
from authlib.integrations.sqla_oauth2 import OAuth2ClientMixin, OAuth2TokenMixin
from sqlalchemy.orm import relationship, scoped_session
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, Text, BigInteger, String
from sqlalchemy.orm.exc import MultipleResultsFound, NoResultFound

Model = declarative_base()

class Client(Model, OAuth2ClientMixin):
  __tablename__ = 'Clients'
  __table_args__ = {'mysql_engine': 'InnoDB',
                    'mysql_charset': 'utf8'}
  id = Column(Integer, primary_key=True, nullable=False)

class Token(Model, OAuth2TokenMixin):
  __tablename__ = 'Tokens'
  __table_args__ = {'mysql_engine': 'InnoDB',
                    'mysql_charset': 'utf8'}
  id = Column(BigInteger, unique=True, primary_key=True, nullable=False)
  # access_token too large for varchar(255)
  # 767 bytes is the stated prefix limitation for InnoDB tables in MySQL version 5.6
  # https://stackoverflow.com/questions/1827063/mysql-error-key-specification-without-a-key-length
  access_token = Column(Text, nullable=False)
  provider = Column(Text)
  user_id = Column(String(255), nullable=False)
  
  # def toDict(self):
  #   return {'access_token': self.access_token,
  #           '': self.system,
  #                 'Module': self.module,
  #                 'Type': self.cType}

  # @property
  # def tokenToDict(self):

  #     return dict(
  #         Provider=self.client_id,
  #         UserID=self.sub,
  #         access_token=self.access_token,
  #         refresh_token=self.client_secret_expires_at,
  #     )

# Relationships
# token = relationship("Token")

class AuthDB2(SQLAlchemyDB):
  """ AuthDB class is a front-end to the OAuth Database
  """
  def __init__(self):
    """ Constructor
    """
    super(AuthDB2, self).__init__()
    self._initializeConnection('Framework/AuthDB2')
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

  def addClient(self, client_id=None, client_secret=None, **metadata):

    client = Client(client_id=client_id or generate_token(30),
                    client_secret=client_secret or generate_token(30),
                    _client_metadata=str(metadata))
    
    session = self.session()
    try:
      session.add(client)
      result = S_OK(client.client_info)
      session.commit()
    except Exception as e:
      session.rollback()
      result = S_ERROR('Could not add Client: %s' % (e))

    session.close()
    return result
  
  def removeClient(self, clientID):
    session = self.session()

    result = self.__filterFields(session, Client, {'client_id': clientID})
    if not result['OK']:
      session.rollback()
      session.close()
      return result

    for client in result['Value']:
      session.delete(client)
    
    try:
      session.commit()
    except Exception as e:
      session.rollback()
      session.close()
      return S_ERROR('Could not commit changes: %s' % (e))

    session.close()
    return S_OK('Components successfully removed')

  def getClientByID(self, clientID):
    session = self.session()
    try:
      client = session.query(Client).filter(Client.client_id==clientID).one()
    except MultipleResultsFound:
      return self.__result(session, S_ERROR("%s is not unique ID." % clientID))
    except NoResultFound:
      return self.__result(session, S_ERROR("%s client not registred." % clientID))
    except Exception as e:
      return self.__result(session, S_ERROR(str(e)))

    return self.__result(session, S_OK(client.client_info))

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

  def storeToken(self, client_id=None, token_type=None, **metadata):
    attrts = {}
    for k, v in metadata.items():
      if k not in Token.__dict__.keys():
        self.log.warn('%s is not expected as token attribute.' % k)
      else:
        attrts[k] = v
    attrts['id'] = hash(attrts['access_token'])
    attrts['client_id'] = client_id
    attrts['token_type'] = token_type or "Baerer"

    session = self.session()
    try:
      session.add(Token(**attrts))
      session.commit()
    except Exception as e:
      session.rollback()
      session.close()
      return S_ERROR('Could not add Token: %s' % (e))

    session.close()
    return S_OK('Component successfully added')
  
  def updateToken(self, token, refreshToken):
    session = self.session()
    try:
      # tokenDict = dict(session.query(Token).filter(Token.refresh_token==refreshToken).one())
      # for k, v in dict(token).items():
      #   tokenDict[k] = v
      # session.add(Token.from_dict(tokenDict))
      session.update(Token(**token)).where(Token.refresh_token==refreshToken)
    except MultipleResultsFound:
      return self.__result(session, S_ERROR("%s is not unique." % refreshToken))
    except NoResultFound:
      return self.__result(session, S_ERROR("%s token not found." % refreshToken))
    except Exception as e:
      return self.__result(session, S_ERROR(str(e)))

    return self.__result(session, S_OK(OAuth2Token(token)))

  def removeToken(self, access_token=None, refresh_token=None):
    session = self.session()
    d = {}
    if access_token:
      d['access_token'] = access_token
    if refresh_token:
      d['refresh_token'] = refresh_token
    result = self.__filterFields(session, Token, d)
    
    if not result['OK']:
      session.rollback()
      session.close()
      return result

    for client in result['Value']:
      session.delete(client)
    
    try:
      session.commit()
    except Exception as e:
      session.rollback()
      session.close()
      return S_ERROR('Could not commit changes: %s' % (e))

    session.close()
    return S_OK('Components successfully removed')
  
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

  def __rowToDict(self, row):
    """ Convert sqlalchemy row to dictionary

        :param object row: sqlalchemy row
    
        :return: dict
    """
    return {c.name: str(getattr(row, c.name)) for c in row.__table__.columns} if row else {}

  def getToken(self, params):
    session = self.session()
    try:
      client = session.query(Token).filter(**params).one()
      session.commit()
    except MultipleResultsFound as e:
      return S_ERROR(str(e))
    except NoResultFound, e:
      return S_ERROR(str(e))
    except Exception as e:
      session.rollback()
      session.close()
      return S_ERROR('Could not commit changes: %s' % (e))

    session.close()
    return S_OK(client)
  
  def __filterFields(self, session, table, matchFields=None):
    """
    Filters instances of a selection by finding matches on the given fields
    session argument is a Session instance used to retrieve the items
    table argument must be one the following three: Component, Host,
    InstalledComponent
    matchFields argument should be a dictionary with the fields to match.
    matchFields accepts fields of the form <Field.bigger> and <Field.smaller>
    to filter using > and < relationships.
    If matchFields is empty, no filtering will be done
    """

    if matchFields is None:
      matchFields = {}

    filtered = session.query(table)

    for key in matchFields:
      actualKey = key

      comparison = '='
      if '.bigger' in key:
        comparison = '>'
        actualKey = key.replace('.bigger', '')
      elif '.smaller' in key:
        comparison = '<'
        actualKey = key.replace('.smaller', '')

      if matchFields[key] is None:
        sql = '`%s` IS NULL' % (actualKey)
      elif isinstance(matchFields[key], list):
        if len(matchFields[key]) > 0 and None not in matchFields[key]:
          sql = '`%s` IN ( ' % (actualKey)
          for i, element in enumerate(matchFields[key]):
            toAppend = element
            if isinstance(toAppend, datetime):
              toAppend = toAppend.strftime("%Y-%m-%d %H:%M:%S")
            if isinstance(toAppend, six.string_types):
              toAppend = '\'%s\'' % (toAppend)
            if i == 0:
              sql = '%s%s' % (sql, toAppend)
            else:
              sql = '%s, %s' % (sql, toAppend)
          sql = '%s )' % (sql)
        else:
          continue
      elif isinstance(matchFields[key], six.string_types):
        sql = '`%s` %s \'%s\'' % (actualKey, comparison, matchFields[key])
      elif isinstance(matchFields[key], datetime):
        sql = '%s %s \'%s\'' % \
            (actualKey,
             comparison,
             matchFields[key].strftime("%Y-%m-%d %H:%M:%S"))
      else:
        sql = '`%s` %s %s' % (actualKey, comparison, matchFields[key])

      filteredTemp = filtered.filter(text(sql))
      try:
        session.execute(filteredTemp)
        session.commit()
      except Exception as e:
        return S_ERROR('Could not filter the fields: %s' % (e))
      filtered = filteredTemp

    return S_OK(filtered)

