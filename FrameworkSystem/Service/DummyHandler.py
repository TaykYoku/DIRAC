import time
from DIRAC.Core.Tornado.Server.TornadoService import TornadoService

class DummyHandler(TornadoService):

  @classmethod
  def initializeHandler(cls, infosDict):
    print('Called 1 time, at first request')

  def initializeRequest(self):
    print('Called at each request')

  auth_someMethod = ['all']
  def export_someMethod(self):
    print('Start sleep method')
    time.sleep(5)
    print('End sleep method')
    return {}
