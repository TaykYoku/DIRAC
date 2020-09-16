""" IdProvider based on OAuth2 protocol
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import re
import pprint
from authlib.integrations.requests_client import OAuth2Session
from authlib.oidc.discovery.well_known import get_well_known_url
from requests import exceptions

from DIRAC.FrameworkSystem.Client.AuthManagerClient import gSessionManager

from DIRAC import S_OK, S_ERROR, gLogger
from DIRAC.Resources.IdProvider.IdProvider import IdProvider
from DIRAC.ConfigurationSystem.Client.Helpers.Resources import getProviderByAlias

__RCSID__ = "$Id$"


class OAuth2IdProvider(IdProvider, OAuth2Session):
  def __init__(self, name=None, issuer=None, client_id=None,
               client_secret=None, token_endpoint_auth_method=None,
               revocation_endpoint_auth_method=None,
               scope=None, redirect_uri=None,
               token=None, token_placement='header',
               update_token=None, **parameters):
    """ OIDCClient constructor
    """
    IdProvider.__init__(self, **parameters)
    OAuth2Session.__init__(self, client_id=client_id, client_secret=client_secret,
                           token_endpoint_auth_method=token_endpoint_auth_method,
                           revocation_endpoint_auth_method=revocation_endpoint_auth_method,
                           scope=scope, redirect_uri=redirect_uri,
                           token=token, token_placement=token_placement,
                           update_token=update_token, **parameters)
    # Convert scope to list
    self.scope = [s.strip() for s in scope.strip().replace('+',' ').split(',' if ',' in scope else ' ')]
    self.parameters = parameters
    self.exceptions = exceptions
    self.name = name or parameters.get('ProviderName')
    self.issuer = issuer
    self.redirect_uri = redirect_uri or 'https://marosvn32.in2p3.fr/DIRAC/auth/redirect'
    self.client_id = client_id
    self.client_secret = client_secret
    self.server_metadata_url = parameters.get('server_metadata_url', get_well_known_url(self.issuer, True))
    # Add hooks to raise HTTP errors
    self.hooks['response'] = lambda r, *args, **kwargs: r.raise_for_status()
    # Here "t" is `OAuth2Token` type
    self.update_token = lambda t, rt: gSessionManager.updateToken(dict(t), rt)

  def checkResponse(func):
    def function_wrapper(*args, **kwargs):
        try:
          return func(*args, **kwargs)
        except exceptions.Timeout:
          return S_ERROR('Time out')
        except exceptions.RequestException as ex:
          return S_ERROR(str(ex))
    return function_wrapper
  
  @checkResponse
  def getServerParameter(self, parameter):
    """ Get identity server parameter

        :param str parameter: requester parameter

        :return: S_OK()/S_ERROR()
    """
    if parameter not in self.metadata and not self.metadata.get('updated'):
      r = None
      try:
        r = self.request('GET', self.server_metadata_url, withhold_token=True)
        servMetadata = r.json()
        for k, v in servMetadata.items():
          if k not in self.metadata:
            self.metadata[k] = v
        self.metadata['updated'] = True
      except ValueError as e:
        return S_ERROR("Cannot update %s server. %s: %s" % (self.name, e.message, r.text if r else ''))
    return S_OK(self.metadata.get(parameter))

  def getIDsMetadata(self, ids=None):
    """ Metadata for IDs
    """
    metadata = {}
    result = self.isSessionManagerAble()
    if not result['OK']:
      return result
    result = self.sessionManager.getIdPTokens(self.name, ids)
    if not result['OK']:
      return result
    for token in result['Value']:
      if token['user_id'] in metadata:
        continue
      result = self.__getUserInfo(token)
      if result['OK']:
        result = self.__parseUserProfile(result['Value'])
        if result['OK']:
          metadatatoken['user_id'] = result['Value']
    
    return S_OK(resDict)

  def submitNewSession(self, session):
    """ Submit new authorization session

        :param str session: session number

        :return: S_OK(str)/S_ERROR()
    """
    result = self.getServerParameter('authorization_endpoint')
    if not result['OK']:
      return result
    authEndpoint = result['Value']
    return S_OK(self.create_authorization_url(authEndpoint, state=session))

  @checkResponse
  def parseAuthResponse(self, response, session=None):
    """ Make user info dict:
          - username(preferd user name)
          - nosupport(VOs in response that not in DIRAC)
          - UsrOptns(User profile that convert to DIRAC user options)
          - Tokens(Contain refreshed tokens, type and etc.)
          - Groups(New DIRAC groups that need created)

        :param object response: response on request to get user profile
        :param str session: session

        :return: S_OK(dict)/S_ERROR()
    """
    result = self.getServerParameter('token_endpoint')
    if not result['OK']:
      return result
    tokenEndpoint = result['Value']
    token = self.fetch_access_token(tokenEndpoint, authorization_response=response.uri)
    
    # Get user info
    result = self.__getUserInfo(token)
    if result['OK']:
      result = self.__parseUserProfile(result['Value'])
    if not result['OK']:
      return result
    userProfile = result['Value']
    
    # Store token
    pprint.pprint(token)
    token['client_id'] = self.client_id
    token['provider'] = self.name
    token['user_id'] = userProfile['ID']
    result = gSessionManager.storeToken(dict(token))
    if not result['OK']:
      return result

    self.log.debug('Got response dictionary:\n', pprint.pformat(userProfile))
    return S_OK(userProfile)

  def __getUserInfo(self, token):
    if token.is_expired():
      result = self.getServerParameter('token_endpoint')
      if not result['OK']:
        return result
      tokenEndpoint = result['Value']
      token = self.refresh_token(tokenEndpoint, refresh_token=token['refresh_token'])

    result = self.getServerParameter('userinfo_endpoint')
    if not result['OK']:
      return result
    userinfoEndpoint = result['Value']
    try:
      r = self.request('GET', userinfoEndpoint,
                      headers={'Authorization': 'Bearer ' + token['access_token']})
      r.raise_for_status()
      userinfo = r.json()
    except (self.exceptions.RequestException, ValueError) as e:
      return S_ERROR("%s: %s" % (e.message, r.text))

    return S_OK(userinfo)

  def __parseUserProfile(self, userProfile):
    """ Parse user profile

        :param dict userProfile: user profile in OAuht2 format

        :return: S_OK()/S_ERROR()
    """
    # Generate username
    gname = userProfile.get('given_name')
    fname = userProfile.get('family_name')
    pname = userProfile.get('preferred_username')
    name = userProfile.get('name') and userProfile['name'].split(' ')
    username = pname or gname and fname and gname[0] + fname
    username = username or name and len(name) > 1 and name[0][0] + name[1] or ''
    username = re.sub('[^A-Za-z0-9]+', '', username.lower())[:13]
    self.log.debug('Parse user name:', username)

    profile = {}

    # Set provider
    profile['Provider'] = self.name

    # Collect user info    
    profile['ID'] = userProfile.get('sub')
    if not profile['ID']:
      return S_ERROR('No ID of user found.')
    profile['Email'] = userProfile.get('email')
    profile['FullName'] = gname and fname and ' '.join([gname, fname]) or name and ' '.join(name) or ''
    self.log.debug('Parse user profile:\n', profile)

    # Default DIRAC groups
    profile['Groups'] = self.parameters.get('DiracGroups') or []
    if not isinstance(profile['Groups'], list):
      profile['Groups'] = profile['Groups'].replace(' ', '').split(',')
    self.log.debug('Default for groups:', ', '.join(profile['Groups']))
    self.log.debug('Response Information:', pprint.pformat(userProfile))

    # Read regex syntax to get DNs describe dictionary
    profile['DNs'] = {}
    dictItemRegex, listItemRegex = {}, None
    try:
      dnClaim = self.parameters['Syntax']['DNs']['claim']
      for k, v in self.parameters['Syntax']['DNs'].items():
        if isinstance(v, dict) and v.get('item'):
          dictItemRegex[k] = v['item']
        elif k == 'item':
          listItemRegex = v
    except Exception as e:
      if not profile['Groups']:
        self.log.warn('No "DiracGroups", no claim with DNs decsribe in Syntax/DNs section found.')
      return S_OK(resDict)

    if not userProfile.get(dnClaim) and not profile['Groups']:
      self.log.warn('No "DiracGroups", no claim "%s" that decsribe DNs found.' % dnClaim)
    else:

      if not isinstance(userProfile[dnClaim], list):
        userProfile[dnClaim] = userProfile[dnClaim].split(',')

      for item in userProfile[dnClaim]:
        dnInfo = {}
        if isinstance(item, dict):
          for subClaim, reg in dictItemRegex.items():
            result = re.compile(reg).match(item[subClaim])
            if result:
              for k, v in result.groupdict().items():
                dnInfo[k] = v
        elif listItemRegex:
          result = re.compile(listItemRegex).match(item)
          if result:
            for k, v in result.groupdict().items():
              dnInfo[k] = v

        if dnInfo.get('DN'):
          if not dnInfo['DN'].startswith('/'):
            items = dnInfo['DN'].split(',')
            items.reverse()
            dnInfo['DN'] = '/' + '/'.join(items)
          if dnInfo.get('PROVIDER'):
            result = getProviderByAlias(dnInfo['PROVIDER'], instance='Proxy')
            dnInfo['PROVIDER'] = result['Value'] if result['OK'] else 'Certificate'
          profile['DNs'][dnInfo['DN']] = dnInfo

    return S_OK(username, profile)
