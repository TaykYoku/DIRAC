""" Utilities for the IdProvider package
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

__RCSID__ = "$Id$"

from DIRAC import S_OK, S_ERROR, gConfig


def getSettingsNamesForIdPIssuer(issuer):
  """ Get identity providers for issuer

      :param str issuer: issuer

      :return: S_OK(list)/S_ERROR()
  """
  names = []
  result = getProvidersForInstance('Id')
  if not result['OK']:
    return result
  for name in result['Value']:
    nameIssuer = gConfig.getValue('/Resources/IdProviders/%s/issuer' % name)
    if nameIssuer and issuer.strip('/') == nameIssuer.strip('/'):
      names.append(name)
  return S_OK(names) if names else S_ERROR('Not found provider with %s issuer.' % issuer)


def getProvidersForInstance(instance, providerType=None):
  """ Get providers for instance

      :param str instance: instance of what this providers
      :param str providerType: provider type

      :return: S_OK(list)/S_ERROR()
  """
  providers = []
  instance = "%sProviders" % instance
  result = gConfig.getSections('/Resources/%s' % instance)

  # Return an empty list if the section does not exist
  if not result['OK'] or not result['Value'] or not providerType:
    return result

  for prov in result['Value']:
    if providerType == gConfig.getValue('/Resources/%s/%s/ProviderType' % (instance, prov)):
      providers.append(prov)
  return S_OK(providers)


def getProviderInfo(provider):
  """ Get provider info

      :param str provider: provider

      :return: S_OK(dict)/S_ERROR()
  """
  result = gConfig.getSections('/Resources')
  if not result['OK']:
    return result
  for section in result['Value']:
    if section.endswith('Providers'):
      result = getProvidersForInstance(section[:-9])
      if not result['OK']:
        return result
      if provider in result['Value']:
        return gConfig.getOptionsDictRecursively("/Resources/%s/%s/" % (section, provider))
  return S_ERROR('%s provider not found.' % provider)