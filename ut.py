from random import randint

from DHT import DHT
from Time import Time
from Communicator import Communicator
from CryptoUtils import _enableCache, _enableFakeCrypto

import constants

class MockTime(Time):
    def __init__(self):
        self.__ts = 12345678.0

        # func_ts => [functions]
        self.__funcs = {}

    def getCurrentTimestamp(self):
        return self.__ts

    def scheduleFunc(self, func, interval):
        self.__funcs.setdefault(self.__ts + interval, []).append((func, interval))

    def scroll(self, interval):
        nextTs = self.__ts + interval
        if len(self.__funcs) == 0:
            self.__ts = nextTs
            return
        while True:
            funcsToExecuteTs = sorted(self.__funcs.keys())[0]
            if funcsToExecuteTs > nextTs:
                self.__ts = nextTs
                break
            self.__ts = funcsToExecuteTs
            funcsToExecute = self.__funcs[funcsToExecuteTs]
            for func, interval in funcsToExecute:
                func()
                self.scheduleFunc(func, interval)
            del self.__funcs[funcsToExecuteTs]

class MockCommunicator(Communicator):
    def __init__(self):
        self.__addressToCallback = {}
        self.__traffic = 0

    def subscribe(self, selfAddress, onDataReceivedCallback):
        self.__addressToCallback[selfAddress] = onDataReceivedCallback

    def unsubscribe(self, selfAddress):
        del self.__addressToCallback[selfAddress]

    def _doSend(self, selfAddress, address, data):
        callback = self.__addressToCallback.get(address, None)
        self.__traffic += len(data)
        if callback is not None:
            self._onReceived(selfAddress, data, callback)

    def getTraffic(self):
        return self.__traffic

def simpleUt():
    time = MockTime()
    communicator = MockCommunicator()

    dht1 = DHT('login1', 'pass1', '/dev/non-exits', communicator, 'addr1', '', time)
    dht2 = DHT('login2', 'pass2', '/dev/non-exits', communicator, 'addr2', 'addr1', time)
    dht3 = DHT('login3', 'pass3', '/dev/non-exits', communicator, 'addr3', 'addr2', time)

    time.scroll(constants.FRIENDS_EXCHANGE_INTERVAL)

    assert dht1.getId() != dht2.getId()
    assert dht2.getId() != dht3.getId()
    assert dht3.getId() != dht1.getId()

    assert dht1.getFriendsSize() == 2
    assert dht2.getFriendsSize() == 2
    assert dht3.getFriendsSize() == 2

def bigUt():
    time = MockTime()
    communicator = MockCommunicator()

    # Create network
    nodes = []
    nodes.append(DHT('login0', 'pass0', '/dev/non-exits', communicator, 'addr0', '', time))
    while len(nodes) < 1000:
        time.scroll(0.01)
        selfAddr = 'addr' + str(len(nodes))
        otherAddr = 'addr' + str(randint(0, len(nodes) - 1))
        login = 'login' + str(len(nodes))
        password = 'password' + str(len(nodes))
        nodes.append(DHT(login, password, '/dev/non-exits', communicator, selfAddr, otherAddr, time))
        if len(nodes) % 100 == 0:
            print '[STATUS] added', len(nodes), 'nodes'

    # Wait few minutes for friends exchange
    avg = 0
    print '[STATUS] added all nodes!'
    for i in xrange(1, 23):
        time.scroll(10)
        avg = 0
        for node in nodes:
            avg += node.getFriendsSize()
        avg = float(avg) / len(nodes)
        print '[STATUS] modeled', i * 10, 'seconds, avg friends:', avg, 'traffic:', communicator.getTraffic()

    assert avg >= constants.MAX_FRIENDS
    assert avg < constants.MAX_FRIENDS * 2

    # Remove half of the friends
    while len(nodes) > 500:
        nodeNum = randint(0, len(nodes) - 1)
        node = nodes[nodeNum]
        communicator.unsubscribe(node.getAddress())
        del nodes[nodeNum]

    # Wait and ensure that have enough friends and all friends are online
    for i in xrange(23, 54):
        time.scroll(10)
        avg = 0
        for node in nodes:
            avg += node.getFriendsSize()
        avg = float(avg) / len(nodes)
        print '[STATUS] modeled', i * 10, 'seconds, avg friends:', avg, 'traffic:', communicator.getTraffic()

    onlineAddresses = set()
    for node in nodes:
        onlineAddresses.add(node.getAddress())

    for node in nodes:
        friendsAddressed = node.getFriendsAddresses()
        for addr in friendsAddressed:
            assert addr in onlineAddresses


def runUt():
    print '[RUNNING]'
    simpleUt()
    print '[UT  #1]: OK'


    _enableCache()
    _enableFakeCrypto()
    bigUt()
    print '[UT  #2]: OK'
    print '[DONE]'

if __name__ == '__main__':
    runUt()
