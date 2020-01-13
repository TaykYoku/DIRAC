"""
SystemLoggingHandler is the implementation of the Logging service
in the DISET framework.

The following methods are available in the Service interface::

    addMessages()

"""

__RCSID__ = "$Id$"

from DIRAC import S_OK, S_ERROR, gLogger
from DIRAC.Core.DISET.RequestHandler import RequestHandler
from DIRAC.FrameworkSystem.private.standardLogging.Message import tupleToMessage
from DIRAC.FrameworkSystem.DB.SystemLoggingDB import SystemLoggingDB


# This is a global instance of the SystemLoggingDB class
gLogDB = False


def initializeSystemLoggingHandler(serviceInfo):
  """ Check that we can connect to the DB and that the tables are properly created or updated
  """
  global gLogDB
  gLogDB = SystemLoggingDB()
  res = gLogDB._connect()
  if not res['OK']:
    return res

  return S_OK()


class SystemLoggingHandler(RequestHandler):
  """ This is server
  """

  def __addMessage(self, messageObject, site, nodeFQDN):
    """
    This is the function that actually adds the Message to
    the log Database
    """
    credentials = self.getRemoteCredentials()
    if 'DN' in credentials:
      userDN = credentials['DN']
    else:
      userDN = 'unknown'
    if 'group' in credentials:
      userGroup = credentials['group']
    else:
      userGroup = 'unknown'

    remoteAddress = self.getRemoteAddress()[0]
    return gLogDB.insertMessage(messageObject, site, nodeFQDN, userDN, userGroup, remoteAddress)

  types_addMessages = [list, basestring, basestring]

  def export_addMessages(self, messagesList, site, nodeFQDN):
    """
    This is the interface to the service
    Inputs:

      msgList contains a list of Message Objects.

    Outputs:

      S_OK if no exception was raised
      S_ERROR if an exception was raised

    """
    for messageTuple in messagesList:
      messageObject = tupleToMessage(messageTuple)
      result = self.__addMessage(messageObject, site, nodeFQDN)
      if not result['OK']:
        gLogger.error('The Log Message could not be inserted into the DB',
                      'because: "%s"' % result['Message'])
        return S_ERROR(result['Message'])
    return S_OK()
