""" TokenManagement service

    .. literalinclude:: ../ConfigTemplate.cfg
      :start-after: ##BEGIN TokenManager:
      :end-before: ##END
      :dedent: 2
      :caption: TokenManager options
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

__RCSID__ = "$Id$"

import six
from DIRAC import gLogger, S_OK, S_ERROR
from DIRAC.Core.DISET.RequestHandler import RequestHandler
# from DIRAC.Core.Tornado.Server.TornadoService import TornadoService
from DIRAC.Core.Security import Properties
from DIRAC.Core.Utilities.ThreadScheduler import gThreadScheduler
from DIRAC.Core.Utilities.ObjectLoader import ObjectLoader
from DIRAC.ConfigurationSystem.Client.Helpers import Registry
from DIRAC.Resources.IdProvider.IdProviderFactory import IdProviderFactory


class TokenManagerHandler(RequestHandler):

  __maxExtraLifeFactor = 1.5
  __tokenDB = None

  @classmethod
  def initializeHandler(cls, serviceInfoDict):
    try:
      result = ObjectLoader().loadObject('FrameworkSystem.DB.TokenDB')
      if not result['OK']:
        gLogger.error('Failed to load TokenDB class: %s' % result['Message'])
        return result
      dbClass = result['Value']

      cls.__tokenDB = dbClass()

    except RuntimeError as excp:
      return S_ERROR("Can't connect to TokenDB: %s" % excp)
    cls.idps = IdProviderFactory()
    return S_OK()

  def __generateUserTokensInfo(self):
    """ Generate information dict about user tokens

        :return: dict
    """
    tokensInfo = []
    credDict = self.getRemoteCredentials()
    result = Registry.getDNForUsername(credDict['username'])
    if not result['OK']:
      return result
    for dn in result['Value']:
      if dn.startswith("/O=DIRAC/CN="):
        result = self.__tokenDB.getTokensByUserID(dn.strip("/O=DIRAC/CN="))
        if not result['OK']:
          gLogger.error(result['Message'])
        tokensInfo += result['Value']
    return tokensInfo

  def __addKnownUserTokensInfo(self, retDict):
    """ Given a S_OK/S_ERR add a tokens entry with info of all the tokens a user has uploaded

        :return: S_OK(dict)/S_ERROR()
    """
    retDict['tokens'] = self.__generateUserTokensInfo()
    return retDict

  auth_getUserTokensInfo = ['authenticated']
  types_getUserTokensInfo = []

  def export_getUserTokensInfo(self):
    """ Get the info about the user tokens in the system

        :return: S_OK(dict)
    """
    return S_OK(self.__generateUserTokensInfo())

  types_uploadToken = ['authenticated']
  types_uploadToken = []

  def export_storeToken(self, token):
    """ Request to delegate tokens to DIRAC

        :param dict token: token

        :return: S_OK(dict)/S_ERROR() -- dict contain uploaded tokens info
    """
    result = self.__tokenDB.updateToken(token)
    return self.__addKnownUserTokensInfo(result)

  def __checkProperties(self, requestedUserDN, requestedUserGroup):
    """ Check the properties and return if they can only download limited tokens if authorized

        :param str requestedUserDN: user DN
        :param str requestedUserGroup: DIRAC group

        :return: S_OK(boolean)/S_ERROR()
    """
    credDict = self.getRemoteCredentials()
    if Properties.FULL_DELEGATION in credDict['properties']:
      return S_OK(False)
    if Properties.LIMITED_DELEGATION in credDict['properties']:
      return S_OK(True)
    if Properties.PRIVATE_LIMITED_DELEGATION in credDict['properties']:
      if credDict['DN'] != requestedUserDN:
        return S_ERROR("You are not allowed to download any proxy")
      if Properties.PRIVATE_LIMITED_DELEGATION not in Registry.getPropertiesForGroup(requestedUserGroup):
        return S_ERROR("You can't download tokens for that group")
      return S_OK(True)
    # Not authorized!
    return S_ERROR("You can't get tokens!")

  types_getToken = [six.string_types, six.string_types]

  def export_getToken(self, username, userGroup):
    """ Get a access token for a user/group

          * Properties:
              * FullDelegation <- permits full delegation of tokens
              * LimitedDelegation <- permits downloading only limited tokens
              * PrivateLimitedDelegation <- permits downloading only limited tokens for one self
    """
    userID = []
    result = Registry.getIdPForGroup(userGroup)
    if not result['OK']:
      return result
    idP = result['Value']
    result = self.__tokenDB.getTokensByProvider(idP)
    if not result['OK']:
      return result
    tokens = result['Value']
    result = Registry.getDNForUsername(username)
    if not result['OK']:
      return result
    for dn in result['Value']:
      if dn.startswith("/O=DIRAC/CN="):
        userID.append(dn.strip("/O=DIRAC/CN="))
    if not userID:
      return S_ERROR('No user id found for %s' % username)
    
    result = self.idps.getIdProvider(idP)
    if not result['OK']:
      return result
    idpObj = result['Value']

    for token in tokens:
      if token.user_id in userID:
        idpObj.token = token

    credDict = self.getRemoteCredentials()
    result = self.__checkProperties("/O=DIRAC/CN=" + idpObj.token.user_id, userGroup)
    if not result['OK']:
      return result

    return idpObj.exchangeGroup(userGroup)

  types_deleteToken = [six.string_types]

  def export_deleteToken(self, userDN):
    """ Delete a token from the DB

        :param str userDN: user DN

        :return: S_OK()/S_ERROR()
    """
    credDict = self.getRemoteCredentials()
    if Properties.PROXY_MANAGEMENT not in credDict['properties']:
      if userDN != credDict['DN']:
        return S_ERROR("You aren't allowed!")
    retVal = self.__tokenDB.removeToken(user_id=userDN.strip("/O=DIRAC/CN="))
    if not retVal['OK']:
      return retVal
    self.__tokenDB.logAction("delete proxy", credDict['DN'], credDict['group'], userDN, userGroup)
    return S_OK()
