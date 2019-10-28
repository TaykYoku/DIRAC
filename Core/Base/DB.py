""" DB is a base class for multiple DIRAC databases that are based on MySQL.
    It uniforms the way the database objects are constructed
"""

from DIRAC import gLogger, gConfig
from DIRAC.Core.Utilities.MySQL import MySQL
from DIRAC.ConfigurationSystem.Client.Utilities import getDBParameters
from DIRAC.ConfigurationSystem.Client.PathFinder import getDatabaseSection

__RCSID__ = "$Id$"


class DB(MySQL):
  """ All DIRAC DB classes should inherit from this one (unless using sqlalchemy)
  """

  def __init__(self, dbname, fullname, debug=False):
    """ C'or

        :param basestring dbname: DB name
        :param basestring fullname: full name
        :param boolean debug: debug mode
    """
    self.versionDB = 0
    self.fullname = fullname
    database_name = dbname
    self.versionTable = '%s_Version' % database_name
    self.log = gLogger.getSubLogger(database_name)

    result = getDBParameters(fullname)
    if not result['OK']:
      raise RuntimeError('Cannot get database parameters: %s' % result['Message'])

    dbParameters = result['Value']
    self.dbHost = dbParameters['Host']
    self.dbPort = dbParameters['Port']
    self.dbUser = dbParameters['User']
    self.dbPass = dbParameters['Password']
    self.dbName = dbParameters['DBName']

    super(DB, self).__init__(hostName=self.dbHost,
                             userName=self.dbUser,
                             passwd=self.dbPass,
                             dbName=self.dbName,
                             port=self.dbPort,
                             debug=debug)

    if not self._connected:
      raise RuntimeError("Can not connect to DB '%s', exiting..." % self.dbName)

    # Initialize version
    result = self._query("show tables")
    if result['OK']:
      if self.versionTable not in [t[0] for t in result['Value']]:
        result = self._createTables({self.versionTable: {'Fields': {'Version': 'INTEGER NOT NULL'},
                                                         'PrimaryKey': 'Version'}})
    if not result['OK']:
      raise RuntimeError("Can not initialize %s DB version: %s" % (self.dbName, result['Message']))
    result = self._query("SELECT Version FROM `%s`" % self.versionTable)
    if result['OK']:
      if len(result['Value']) > 0:
        self.versionDB = result['Value'][0][0]
      else:
        result = self._update("INSERT INTO `%s` (Version) VALUES (%s)" % (self.versionTable, self.versionDB))
    if not result['OK']:
      raise RuntimeError("Can not initialize %s DB version: %s" % (self.dbName, result['Message']))

    self.log.info("===================== MySQL ======================")
    self.log.info("User:           " + self.dbUser)
    self.log.info("Host:           " + self.dbHost)
    self.log.info("Port:           " + str(self.dbPort))
    #self.log.info("Password:       "+self.dbPass)
    self.log.info("DBName:         " + self.dbName)
    self.log.info("==================================================")

#############################################################################
  def getCSOption(self, optionName, defaultValue=None):
    """ Get option from CS

        :param basestring optionName: option name
        :param basestring,list defaultValue: default value

        :return basestring or list
    """
    cs_path = getDatabaseSection(self.fullname)
    return gConfig.getValue("/%s/%s" % (cs_path, optionName), defaultValue)
  
  def updateDBVersion(self, version):
    """ Update DB version

        :param int version: version number

        :return: S_OK()/S_ERROR()
    """
    result = self._update("INSERT INTO `%s_Version` (Version) VALUES (%s)" % (database_name, version))
    if not result['OK']:
      return S_ERROR("Can not initialize %s DB version: %s" % (self.dbName, result['Message']))
    self.versionDB = version
    return S_OK()
