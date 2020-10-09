from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from time import time
from pprint import pprint

from DIRAC import gLogger
from DIRAC.Core.Utilities import ThreadSafe
from DIRAC.Core.Utilities.DictCache import DictCache

__RCSID__ = "$Id$"

gCacheSession = ThreadSafe.Synchronizer()


class Session(dict):
  """A dict instance to represent a Session object."""
  def __init__(self, sessionID, data, exp, created=None):
    super(Session, self).__init__(id=sessionID, expires_at=int(time()) + exp, **data)
    self.id = sessionID
    self.created = created or int(time())

  @property
  def status(self):
    """ Session status
    
        :return: int
    """
    return self.get('Status', 'submited')

  @property
  def age(self):
    """ Session age
    
        :return: int
    """
    return int(time()) - self.created
  
  @property
  def token(self):
    """ Tokens
    
      :return: object
    """
    return self.get('tokens')


class SessionManager(object):
  def __init__(self, addTime=300, maxAge=3600 * 12):
    self.__sessions = DictCache()
    self.__addTime = addTime
    self.__maxAge = maxAge

  @gCacheSession
  def addSession(self, session, exp=None, **kwargs):
    print('ADD SESSION:')
    exp = exp or self.__addTime
    if not isinstance(session, Session):
      session = Session(session, kwargs, exp)
    if session.age > self.__maxAge:
      return self.__sessions.delete(session.id)
    print('id: %s' % session.id)
    pprint(dict(session))
    print('------------')
    self.__sessions.add(session.id, min(exp, self.__maxAge), session)

  @gCacheSession
  def getSession(self, session):
    return self.__sessions.get(session.id if isinstance(session, Session) else session)

  @gCacheSession
  def getSessions(self):
    return self.__sessions.getDict()
  
  @gCacheSession
  def removeSession(self, session):
    self.__sessions.delete(session.id if isinstance(session, Session) else session)

  def updateSession(self, session, exp=None, **kwargs):
    print('UPDATE SESSION:')
    exp = exp or self.__addTime
    sObj = self.getSession(session.id if isinstance(session, Session) else session)
    pprint(dict(session))
    if sObj and sObj.age < self.__maxAge:
      if (sObj.age + exp) > self.__maxAge:
        exp = self.__maxAge - sObj.age
      for k, v in kwargs.items() or {}:
        sObj[k] = v
      self.addSession(sObj, exp)
  
  def getSessionByOption(self, key, value):
    if key and value:
      sessions = self.getSessions()
      for session, data in sessions.items():
        if data.get(key) == value:
          return session, data
    return None, None
