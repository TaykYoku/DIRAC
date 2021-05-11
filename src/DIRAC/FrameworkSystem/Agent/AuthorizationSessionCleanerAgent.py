""" CAUpdateAgent is meant to be used in a multi-server installations
    where one server has some machinery of keeping up to date the CA's data
    and other servers are just synchronized with the master one without "official" CA installations locally.

    It's like installing CAs in the pilot in dirac-install but for the servers.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

__RCSID__ = "$Id$"

from DIRAC import S_OK
from DIRAC.Core.Base.AgentModule import AgentModule
from DIRAC.FrameworkSystem.DB.AuthDB import AuthDB


class AuthorizationSessionCleanerAgent(AgentModule):
  """ Remove expired sessions and tokens
  """

  def initialize(self):
    self.db = AuthDB()
    self.am_setOption("PollingTime", 3600)
    return S_OK()

  def execute(self):
    """ The main agent execution method
    """
    result = self.db.removeExpiredTokens()
    if not result['OK']:
      self.log.error("Error while remove expired tokens", result['Message'])
    result = self.db.removeExpiredSessions()
    if not result['OK']:
      self.log.error("Error while remove expired sessions", result['Message'])

    return S_OK()
