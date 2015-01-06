import msgpack

KEYS = [
    'type',
    'id',
    'rand_seq',
    'closest_friends',
    'request_id',
    'response_id',
    'confirm',
    'confirm_confirm',
    'exchange',
    'search',
    'search_response',
    'exchange_response',
    'ping',
    'pong',
]
KEY_TO_ID = {key: value for (value, key) in enumerate(KEYS)}
ID_TO_KEY = {key: value for (key, value) in enumerate(KEYS)}


def dictToList(packet):
    res = []
    for key, value in packet.iteritems():
        if key == 'type':
            value = KEY_TO_ID[value]
        key = KEY_TO_ID[key]
        res.append(key)
        res.append(value)
    return res

def listToDict(packet):
    res = {}
    for i in xrange(0, len(packet), 2):
        key = ID_TO_KEY[packet[i]]
        value = packet[i + 1]
        if key == 'type':
            value = ID_TO_KEY[value]
        res[key] = value
    return res


class Communicator:
    def subscribe(self, selfAddress, onDataReceivedCallback):
        pass

    def send(self, selfAddress, address, packet):
        assert type(address) == type('')
        assert len(address) < 100
        assert len(selfAddress) < 100

        packet = dictToList(packet)
        data = msgpack.packb(packet)

        self._doSend(selfAddress, address, data)

    def _doSend(self, selfAddress, address, data):
        pass

    def _onReceived(self, address, data, callback):
        packet = msgpack.unpackb(data)
        packet = listToDict(packet)

        callback(address, packet)
