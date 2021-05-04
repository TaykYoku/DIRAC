########################################################################
# File :   IdProviderFactory.py
# Author : A.T.
########################################################################

"""  The Identity Provider Factory instantiates IdProvider objects
     according to their configuration
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from DIRAC import S_OK, S_ERROR, gLogger
from DIRAC.Core.Utilities import ObjectLoader, ThreadSafe
from DIRAC.Core.Utilities.DictCache import DictCache
from DIRAC.ConfigurationSystem.Client.Helpers.Resources import getProviderInfo

__RCSID__ = "$Id$"


gCacheMetadata = ThreadSafe.Synchronizer()

class IdProviderFactory(object):

  #############################################################################
  def __init__(self):
    """ Standard constructor
    """
    self.log = gLogger.getSubLogger('IdProviderFactory')
    self.cacheMetadata = DictCache()

  @gCacheMetadata
  def getMetadata(self, idP):
    return self.cacheMetadata.get(idP)

  @gCacheMetadata
  def addMetadata(self, idP, data, time=24 * 3600):
    if data:
      self.cacheMetadata.add(idP, time, data)

  def getIdProviderForToken(self, token):
    """ This method returns a IdProvider instance corresponding to the supplied
        issuer in a token.

        :param str token: token jwt

        :return: S_OK(IdProvider)/S_ERROR()
    """
    # Read token without verification to get issuer
    issuer = jwt.decode(token, options=dict(verify_signature=False))['iss'].strip('/')
    result = getIdProviderForIssuer(issuer)
    if not result['OK']:
      return result
    result['Value']['token'] = token
    return self.getIdProvider(result['Value'])

  #############################################################################
  def getIdProvider(self, idProvider, **kwargs):
    """ This method returns a IdProvider instance corresponding to the supplied
        name.

        :param str idProvider: the name of the Identity Provider

        :return: S_OK(IdProvider)/S_ERROR()
    """
    if isinstance(idProvider, dict):
      pDict = idProvider
    else:
      result = getProviderInfo(idProvider)
      if not result['OK']:
        self.log.error('Failed to read configuration', '%s: %s' % (idProvider, result['Message']))
        return result
      pDict = result['Value']
      pDict['ProviderName'] = idProvider
    pDict.update(kwargs)
    pType = pDict['ProviderType']

    self.log.verbose('Creating IdProvider of %s type with the name %s' % (pType, idProvider))
    subClassName = "%sIdProvider" % (pType)

    objectLoader = ObjectLoader.ObjectLoader()
    result = objectLoader.loadObject('Resources.IdProvider.%s' % subClassName, subClassName)
    if not result['OK']:
      self.log.error('Failed to load object', '%s: %s' % (subClassName, result['Message']))
      return result

    pClass = result['Value']
    try:
      meta = self.getMetadata(idProvider)
      if meta:
        pDict.update(meta)
      provider = pClass(**pDict)
      if not meta and hasattr(provider, 'metadata'):
        self.addMetadata(idProvider, provider.metadata)
    except Exception as x:
      msg = 'IdProviderFactory could not instantiate %s object: %s' % (subClassName, str(x))
      self.log.exception()
      self.log.warn(msg)
      return S_ERROR(msg)

    return S_OK(provider)
