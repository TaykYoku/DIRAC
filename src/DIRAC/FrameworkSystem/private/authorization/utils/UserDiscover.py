from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

__RCSID__ = "$Id$"


"""
{
  <Provider name>:
  {
    ...
    <User ID>: {
      ...
      DNs: {
        <DN>: {
          ProxyProvider: ...,
          VOMSRoles: ...,
        }
      }
      VOs: {
        <VOName>: {
          ...
          <VORole>: {
            ...
          }
        }
      }
    }
  }
}
"""


class ProfileParser(object):
  def __init__(self, **parameters):
    self.provider = parameters['ProviderName']
    self.user_id = None
    self.profile = {self.provider: {}}
  
  def parseBasic(self, claimDict):
    """ Parse basic claims

        :param dict claimDict: claims

        :return: S_OK(dict)/S_ERROR()
    """
    self.user_id = claimDict['sub']
    self.profile[self.provider][self.user_id] = {'DNs': {}, 'VOs': {}}
    if claimDict.get('email'):
      self.profile[self.provider][self.user_id]['Email'] = claimDict['email']
    gname = claimDict.get('given_name')
    fname = claimDict.get('family_name')
    pname = claimDict.get('preferred_username')
    name = claimDict.get('name') and claimDict['name'].split(' ')
    username = pname or gname and fname and gname[0] + fname
    username = username or name and len(name) > 1 and name[0][0] + name[1] or ''
    username = re.sub('[^A-Za-z0-9]+', '', username.lower())[:13]
    fullname = gname and fname and ' '.join([gname, fname]) or name and ' '.join(name) or ''
    self.profile[self.provider][self.user_id]['FullName'] = fullname
    return self.profile

  def parseCertEntitlement(self, claimDict):
    """ Parse cert_entitlement claim

        :param dict claimDict: claims

        :return: dict
    """
    attributes = {
        'cert_entitlement': {
            'cert_iss': '(?P<PROXYPROVIDER>.*)',
            'cert_subject_dn': '(?P<DN>.*)',
            'eduperson_entitlement': '^(?P<NAMESPACE>[A-z,.,_,-,:]+):(group:registry|group):\
                                     (?P<VO>[A-z,.,_,-]+):role=(?P<GROUP>[A-z,.,_,-]+)[:#].*'
        }
    }
    result = claimParser(claimDict, attributes)
    if result:
      for data in result['cert_entitlement']:
        self.profile[self.provider][self.user_id]['DNs'][data['cert_subject_dn']['DN']] = {
            'ProxyProvider': data['cert_iss']['PROXYPROVIDER'],
            'VOMSRoles': [data['eduperson_entitlement']['GROUP']]
        }
    return self.profile

  def parseEduperson(self, claimDict):
    """ Parse eduperson claims

        :param dict claimDict: claims

        :return: dict
    """
    attributes = {
        'eduperson_unique_id': '^(?P<ID>.*)',
        'eduperson_entitlement': '^(?P<NAMESPACE>[A-z,.,_,-,:]+):(group:registry|group):\
                                 (?P<VO>[A-z,.,_,-]+):role=(?P<VOMSRole>[A-z,.,_,-]+)[:#].*'
    }
    resDict = claimParser(claimDict, attributes)
    if not resDict:
      return self.profile

    self.user_id = resDict['eduperson_unique_id']['ID']
    for voDict in resDict['eduperson_entitlement']:
      self.profile[self.provider][self.user_id]['VOs'][voDict['VO']] = {voDict['VOMSRole']: {}}
    return self.profile

  def claimParser(self, claimDict, attributes, profile={}):
    """ Parse claims to write it as DIRAC profile

        :param dict claimDict: claims
        :param dict attributes: contain claim and regex to parse it
        :param dict profile: to fill parsed data

        :return: dict
    """
    result = None
    for claim, reg in attributes:
      if isinstance(claimDict[claim], dict):
        result = claimParser(claimDict[claim], reg)
        if result:
          profile[claim] = result
      elif isinstance(claimDict[claim], str):
        result = re.compile(reg).match(claimDict[claim])
        if result:
          for k, v in result.groupdict().items():
            profile[claim][k] = v
      else:
        profile[claim] = []
        for claimItem in claimDict[claim]:
          if isinstance(reg, dict):
            result = claimParser(claimItem, reg)
            if result:
              profile[claim].append(result)
          else:
            result = re.compile(reg).match(claimItem)
            if result:
              profile[claim].append(result.groupdict())

    return profile
