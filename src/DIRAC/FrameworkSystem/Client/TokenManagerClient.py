""" The TokenManagerClient is a class representing the client of the DIRAC
    TokenManager service. It has also methods to update the Configuration
    Service with the DIRAC components options
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

__RCSID__ = "$Id$"

from DIRAC.Core.Base.Client import Client, createClient


@createClient('Framework/TokenManager')
class TokenManagerClient(Client):

  pass
