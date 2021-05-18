""" IdProvider based on OAuth2 protocol
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from DIRAC import S_ERROR, S_OK
from DIRAC.Resources.IdProvider.OAuth2IdProvider import OAuth2IdProvider
from DIRAC.FrameworkSystem.private.authorization.AuthServer import collectMetadata

__RCSID__ = "$Id$"


class DIRACIdProvider(OAuth2IdProvider):

  def fetch_metadata(self, url=None):
    """ Fetch metada
    """
    print('>>> DIRAC fetch_metadata')
    return collectMetadata(self.metadata['issuer'])

  def researchGroup(self, payload, token):
    """ Research group
    """
    print('>>> DIRAC researchGroup')
    pass
