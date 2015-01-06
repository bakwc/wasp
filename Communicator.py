import pickle

class Communicator:
    def subscribe(self, selfAddress, onDataReceivedCallback):
        pass

    def send(self, selfAddress, address, packet):
        assert type(address) == type('')
        assert len(address) < 100
        assert len(selfAddress) < 100

        #print selfAddress, '=>', address , ': ', packet

        data = pickle.dumps(packet, -1)
        self._doSend(selfAddress, address, data)

    def _doSend(self, selfAddress, address, data):
        pass

    def _onReceived(self, address, data, callback):
        packet = pickle.loads(data)
        callback(address, packet)
