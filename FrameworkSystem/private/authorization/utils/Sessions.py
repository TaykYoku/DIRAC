from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from DIRAC import gLogger
from DIRAC.Core.Utilities import ThreadSafe
from DIRAC.Core.Utilities.DictCache import DictCache

__RCSID__ = "$Id$"

gCacheSession = ThreadSafe.Synchronizer()

class SessionManager(object):
  def __init__(self):
    self.__sessions = DictCache()

  @gCacheSession
  def addSession(self, session, exp=300, **kwargs):
    kwargs['Status'] = kwargs.get('Status', 'submited')
    self.__sessions.add(session, exp, kwargs)

  @gCacheSession
  def getSession(self, session=None):
    return self.__sessions.get(session) if session else self.__sessions.getDict()
  
  @gCacheSession
  def removeSession(self, session):
    self.__sessions.delete(session)

  def updateSession(self, session, exp=300, **kwargs):
    origData = self.getSession(session) or {}
    for k, v in kwargs.items():
      origData[k] = v
    self.addSession(session, exp, **origData)
  
  def getSessionByOption(self, key, value):
    if key and value:
      sessions = self.getSession()
      for session, data in sessions.items():
        if data.get(key) == value:
          return session, data
    return None, {}