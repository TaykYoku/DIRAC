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

from authlib.integrations.sqla_oauth2 import OAuth2ClientMixin, OAuth2TokenMixin
from sqlalchemy.orm import relationship, scoped_session
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer
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
  id = Column(Integer, primary_key=True, nullable=False)

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

  def addToken(self, client_id=None, token_type=None, scope=None, revoked=None, issued_at=None, expires_in=None,
               access_token=None, refresh_token=None, **metadata):

    token = Token(client_id=client_id,
                    token_type=token_type or "Baerer",
                    **metadata)
    
    session = self.session()
    try:
      session.add(token)
      session.commit()
    except Exception as e:
      session.rollback()
      session.close()
      return S_ERROR('Could not add Client: %s' % (e))

    session.close()
    return S_OK('Component successfully added')
  
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

