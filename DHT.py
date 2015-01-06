import pickle
import os.path

from CryptoUtils import CryptoUtils, distance
from constants import FRIENDS_PER_REQUEST, MAX_FRIENDS, FRIENDS_EXCHANGE_INTERVAL,\
    PING_INTERVAL, FRIENDS_TIMEOUT, RAND_SEQ_LENGTH


class _DHT_Friend:
    def __init__(self, id, address, data = ''):
        self.id = id                # unique friend id = rsa publick key (2048 length)
        self.address = address      # ip address: port
        self.data = data            # friend data - encrypted list of nodes, storing content

class _DHT_FriendDynamic:
    def __init__(self, lastPingResponse, lastExchange = 0):
        self.lastPingResponse = lastPingResponse
        self.lastExchange = lastExchange

class _DHT_FriendFull(_DHT_Friend, _DHT_FriendDynamic):
    def __init__(self, base, dynamic):
        _DHT_Friend.__init__(self, base.id, base.address, base.data)
        _DHT_FriendDynamic.__init__(self, dynamic.lastPingResponse, dynamic.lastExchange)

class _DHT_Friends:
    def __init__(self, stateFile, time, authorizator):
        self.__stateFile = stateFile
        self.__time = time
        self.__authorizator = authorizator

        # friend_id => _DHT_Friend
        self.__friends = {}

        # friend_id => _DHT_FriendDynamic
        self.__friendsDynamic = {}

        self.__initialized = False
        self.__load()

    def __load(self):
        if os.path.isfile(self.__stateFile):
            with open(self.__stateFile, 'rb') as f:
                self.__friends = pickle.loads(f.read())

    def __save(self):
        data = pickle.dumps(self.__friends, -1)
        with open(self.__stateFile, 'wb') as f:
            f.write(data)

    def empty(self):
        return len(self.__friends) == 0

    def add(self, friendId, friendAddress):
        if not friendId in self.__friends:
            self.__friends[friendId] = _DHT_Friend(friendId, friendAddress)
            self.__friendsDynamic[friendId] = _DHT_FriendDynamic(self.__time.getCurrentTimestamp(), self.__time.getCurrentTimestamp() - FRIENDS_EXCHANGE_INTERVAL + 15)

    def size(self):
        return len(self.__friends)

    def remove(self, id):
        del self.__friends[id]
        del self.__friendsDynamic[id]

    def has(self, id):
        return id in self.__friends

    def haveEnough(self):
        return len(self.__friends) >= MAX_FRIENDS

    def findClosest(self, id, count = FRIENDS_PER_REQUEST, reverse = False, onlyAuthorized = False):
        closestFriends = []
        for frnd in self.__friends.itervalues():
            if not onlyAuthorized or self.__authorizator.isAuthorized(frnd.id):
                closestFriends.append((distance(id, frnd.id), frnd.id, frnd.address))
                if len(closestFriends) > count:
                    break
        return sorted(closestFriends, reverse=reverse)

    def getAll(self):
        res = []
        for friendId in self.__friends.keys():
            res.append(_DHT_FriendFull(self.__friends[friendId], self.__friendsDynamic[friendId]))
        return res

    def getLastExchange(self, id):
        return self.__friendsDynamic[id].lastExchange

    def markExchanged(self, id):
        self.__friendsDynamic[id].lastExchange = self.__time.getCurrentTimestamp()

    def getLastPingResponse(self, id):
        return self.__friendsDynamic[id].lastPingResponse

    def markPingResponse(self, id):
        self.__friendsDynamic[id].lastPingResponse = self.__time.getCurrentTimestamp()

    def dump(self):
        for friend in self.__friends.values():
            print friend.address
            print friend.id
            print ''

    def getAddresses(self):
        res = []
        for friend in self.__friends.values():
            res.append(friend.address)
        return res

class _AuthStatusTypes:
    UNAUTHORIZED = 0
    WAITING_ID = 1
    WAITING_CONFIRM = 2
    AUTHORIZED = 3

class _AuthStatus:
    def __init__(self, address, selfAddress):
        self.status = _AuthStatusTypes.UNAUTHORIZED
        self.randSeq = selfAddress + os.urandom(RAND_SEQ_LENGTH)
        self.commandsQueue = []
        self.address = address
        self.id = None

class _Authorizator():
    def __init__(self, communicator, dht, crypto):
        self.__statuses = {} # address => _AuthStatus
        self.__idToStatus = {} # id => _AuthStatus
        self.__communicator = communicator
        self.__dht = dht
        self.__crypto = crypto

    def onPacketReceived(self, requesterAddress, packet):
        if packet['type'] == 'request_id':
            response = {
                'type': 'response_id',
                'id': self.__dht.getId(),
            }
            self.__communicator.send(self.__dht.getAddress(), requesterAddress, response)
            return
        if packet['type'] == 'confirm':
            randSeq = self.__crypto.decrypt(self.__dht.getPrivKey(), packet['rand_seq'])
            if not randSeq.startswith(requesterAddress):
                # todo: process hacking attempt
                if requesterAddress in self.__statuses:
                    del self.__statuses[requesterAddress]
                return
            response = {
                'type': 'confirm_confirm',
                'rand_seq': randSeq,
            }
            self.__communicator.send(self.__dht.getAddress(), requesterAddress, response)
            return

        status = self.__statuses.setdefault(requesterAddress, _AuthStatus(requesterAddress, self.__dht.getAddress()))
        if status.status == _AuthStatusTypes.UNAUTHORIZED:
            status.commandsQueue.append(packet)
            response = {
                'type': 'request_id',
            }
            status.status = _AuthStatusTypes.WAITING_ID
            self.__communicator.send(self.__dht.getAddress(), requesterAddress, response)
            return
        if status.status == _AuthStatusTypes.WAITING_ID:
            if packet['type'] == 'response_id':
                status.status = _AuthStatusTypes.WAITING_CONFIRM
                status.id = packet['id']
                response = {
                    'type': 'confirm',
                    'rand_seq': self.__crypto.encrypt(status.id, status.randSeq),
                }
                self.__communicator.send(self.__dht.getAddress(), requesterAddress, response)
            else:
                status.commandsQueue.append(packet)
            return
        if status.status == _AuthStatusTypes.WAITING_CONFIRM:
            if packet['type'] == 'confirm_confirm':
                if packet['rand_seq'] == status.randSeq:
                    status.status = _AuthStatusTypes.AUTHORIZED
                    self.__idToStatus[status.id] = status
                    for cmd in status.commandsQueue:
                        self.__dht._onPacketReceived(status.address, status.id, cmd)
                    status.commandsQueue = []
                else:
                    # todo: process hacking attempt
                    del self.__statuses[requesterAddress]
            else:
                status.commandsQueue.append(packet)
            return
        if status.status == _AuthStatusTypes.AUTHORIZED:
            self.__dht._onPacketReceived(status.address, status.id, packet)

    def isAuthorized(self, id):
        status = self.__idToStatus.get(id, None)
        if status is None:
            return False
        return status.status == _AuthStatusTypes.AUTHORIZED

    def remove(self, addr):
        status = self.__statuses.get(addr, None)
        if status is None:
            return
        id = status.id
        if id in self.__idToStatus:
            del self.__idToStatus[id]
        del self.__statuses[addr]

class DHT:
    def __init__(self, login, password, stateFile, communicator, selfAddress, initialAddress, time):
        self.__login = login
        self.__password = password
        self.__address = selfAddress

        self.__crypto = CryptoUtils()

        self.__generateKeys()

        self.__communicator = communicator
        self.__authorizator = _Authorizator(self.__communicator, self, self.__crypto)
        self.__communicator.subscribe(selfAddress, self.__authorizator.onPacketReceived)
        self.__time = time

        self.__friends = _DHT_Friends(stateFile, time, self.__authorizator)
        if self.__friends.empty() and initialAddress:
            self.sendSearchRequest(initialAddress)
        self.__time.scheduleFunc(self.__exchangeFriends, FRIENDS_EXCHANGE_INTERVAL / MAX_FRIENDS)
        self.__time.scheduleFunc(self.__pingFriends, PING_INTERVAL)

    def __removeFriendsIfRequired(self):
        if self.__friends.size() > 1.3 * MAX_FRIENDS:
            requiredToRemove = 0.15 * MAX_FRIENDS
            farthestFriends = self.__friends.findClosest(self.__id, count=requiredToRemove, reverse=True)
            for f in farthestFriends:
                self.__authorizator.remove(f[2])
                self.__friends.remove(f[1])

    def __exchangeFriends(self):
        closestFriends = self.__friends.findClosest(self.__id, MAX_FRIENDS)
        now = self.__time.getCurrentTimestamp()
        for _, id, address in closestFriends:
            if now - self.__friends.getLastExchange(id) > FRIENDS_EXCHANGE_INTERVAL:
                packet = {
                    'type': 'exchange',
                }
                self.__friends.markExchanged(id)
                self.__communicator.send(self.__address, address, packet)
                break

    def __pingFriends(self):
        allFriends = self.__friends.getAll()
        packet = {
            'type': 'ping',
        }
        now = self.__time.getCurrentTimestamp()
        for friend in allFriends:
            interval = now - friend.lastPingResponse
            if interval > PING_INTERVAL:
                if interval > FRIENDS_TIMEOUT:
                    self.__authorizator.remove(friend.address)
                    self.__friends.remove(friend.id)
                else:
                    self.__communicator.send(self.__address, friend.address, packet)

    def __generateKeys(self):
        self.__privateKey, self.__id = self.__crypto.generateKeys(self.__login, self.__password)

    def sendSearchRequest(self, address):
        searchPacket = {
            'type': 'search',
        }
        self.__communicator.send(self.__address, address, searchPacket)


    def _onPacketReceived(self, requesterAddress, requesterId, packet):
        if packet['type'] == 'search':
            closestFriends = self.__friends.findClosest(requesterId, onlyAuthorized=True)
            closestFriends.append((distance(self.__id, requesterId), self.__id, self.__address))
            closestFriends = sorted(closestFriends)[:FRIENDS_PER_REQUEST]
            newClosestFriends = []
            for _, id, address in closestFriends:
                newClosestFriends.append((id, address))
            response = {
                'type' : 'search_response',
                'closest_friends': newClosestFriends,
            }
            self.__communicator.send(self.__address, requesterAddress, response)
            if self.__friends.size() == 0:
                self.sendSearchRequest(requesterAddress)

        elif packet['type'] == 'search_response':
            # todo: check that u really requested this
            prevClosest = self.__friends.findClosest(self.__id, 1)[0] if self.__friends.size() > 0 else None
            for closestFriend in packet['closest_friends']:
                id, address = closestFriend
                if id != self.__id:
                    self.__friends.add(id, address)
                    self.__removeFriendsIfRequired()
            newClosest = self.__friends.findClosest(self.__id, 1)[0] if self.__friends.size() > 0 else None
            if newClosest != prevClosest:
                self.sendSearchRequest(newClosest[2])

        elif packet['type'] == 'exchange':
            closestFriends = self.__friends.findClosest(requesterId, MAX_FRIENDS, onlyAuthorized=True)
            newClosestFriends = []
            for _, id, address in closestFriends:
                newClosestFriends.append((id, address))
            response = {
                'type': 'exchange_response',
                'closest_friends': newClosestFriends,
            }
            self.__communicator.send(self.__address, requesterAddress, response)
            if self.__friends.size() == 0:
                self.sendSearchRequest(requesterAddress)

        elif packet['type'] == 'exchange_response':
            # todo: check that u really requested this
            for closestFriend in packet['closest_friends']:
                id, address = closestFriend
                if id != self.__id:
                    self.__friends.add(id, address)
                    self.__removeFriendsIfRequired()

        elif packet['type'] == 'ping':
            if self.__friends.has(requesterId):
                self.__friends.markPingResponse(requesterId)
            else:
                self.__friends.add(requesterId, requesterAddress)
                self.__removeFriendsIfRequired()
            packet = {
                'type': 'pong'
            }
            self.__communicator.send(self.__address, requesterAddress, packet)
            if self.__friends.size() == 0:
                self.sendSearchRequest(requesterAddress)

        elif packet['type'] == 'pong':
            if self.__friends.has(requesterId):
                self.__friends.markPingResponse(requesterId)

    def getFriendsSize(self):
        return self.__friends.size()

    def getId(self):
        return self.__id

    def getAddress(self):
        return self.__address

    def getPrivKey(self):
        return self.__privateKey

    def dumpFriends(self):
        self.__friends.dump()

    def getFriendsAddresses(self):
        return self.__friends.getAddresses()