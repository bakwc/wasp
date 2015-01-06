from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import PKCS1_OAEP
import os, os.path

def _readFile(fname):
    with open(fname, 'rb') as f:
        return f.read()

def _writeFile(fname, data):
    with open(fname, 'wb') as f:
        f.write(data)

class CryptoUtils:

    def myRand(self, n):
        self.__counter += 1
        return PBKDF2(self.__masterKey, "myRand:%d" % self.__counter, dkLen=n, count=1)

    def generateKeys(self, login, password):
        fname = ''
        if _g_cache_enabled:
            fname = 'cache/' + login + '_' + password
            if os.path.isfile(fname + '_pub'):
                return (_readFile(fname + '_priv'), _readFile(fname + '_pub'))

        self.__masterKey = PBKDF2(password, login, count=2500)
        self.__counter = 0
        key = RSA.generate(2048, randfunc=self.myRand)
        privKey = key.exportKey('DER')
        pubKey = key.publickey().exportKey('DER')
        if _g_cache_enabled:
            _writeFile(fname + '_priv', privKey)
            _writeFile(fname + '_pub', pubKey)
        return (privKey, pubKey)

    def encrypt(self, pubKey, message):
        if _g_fake_crypto:
            return message
        key = RSA.importKey(pubKey)
        key = PKCS1_OAEP.new(key)
        return key.encrypt(message)

    def decrypt(self, privKey, message):
        if _g_fake_crypto:
            return message
        key = RSA.importKey(privKey)
        key = PKCS1_OAEP.new(key)
        return key.decrypt(message)

def distance(a, b):
    global _g_distanceCache
    if (a, b) in _g_distanceCache:
        return _g_distanceCache[(a, b)]
    assert len(a) == len(b)
    c = ''
    if b > a:
        a, b = b, a
    carry = False
    for i in xrange(len(a) - 1, -1, -1):
        up = ord(a[i])
        down = ord(b[i])
        res = up - down - int(carry)
        carry = res < 0
        if carry:
            res += 256
        c = chr(res) + c
    _g_distanceCache[(a, b)] = c
    return c

def _distanceUT():
    a = ''
    b = ''
    a += chr(10)
    b += chr(4)
    c = distance(a, b)
    assert len(c) == 1
    assert c[0] == chr(6)
    assert c == distance(b, a)

    a = chr(255) + chr(255) + chr(255)
    b = chr(0) + chr(0) + chr(0)
    c = distance(a, b)
    assert len(c) == 3
    assert c[0] == chr(255)
    assert c[1] == chr(255)
    assert c[2] == chr(255)
    assert c == distance(b, a)

    a = chr(255) + chr(10) + chr(10)
    b = chr(0) + chr(20) + chr(20)
    c = distance(a, b)
    assert len(c) == 3

    assert c[0] == chr(254)
    assert c[1] == chr(245)
    assert c[2] == chr(246)
    assert c == distance(b, a)


def _UT():
    crypto = CryptoUtils()
    priv1, pub1 = crypto.generateKeys('login1', 'password1')
    priv2, pub2 = crypto.generateKeys('login2', 'password2')
    priv3, pub3 = crypto.generateKeys('login1', 'password1')
    assert priv1 == priv3
    assert pub1 == pub3
    assert priv1 != priv2
    assert pub1 != pub2

_g_distanceCache = {}

_g_cache_enabled = False
_g_fake_crypto = False

def _enableCache():
    global _g_cache_enabled
    _g_cache_enabled = True
    if not os.path.isdir('cache'):
        os.makedirs('cache')

def _enableFakeCrypto():
    global _g_fake_crypto
    _g_fake_crypto = True

if __name__ == '__main__':
    _UT()
    _distanceUT()
