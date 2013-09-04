"""
Wrapper around scrypt.
"""
import scrypt

from os import urandom
from twisted.internet import reactor, threads
from twisted.python import threadpool


class Wrapper(object):
    urandom = staticmethod(urandom)

    def __init__(self, reactor, threadPool, saltLength, maxTime):
        self.reactor = reactor
        self.threadPool = threadPool
        self.saltLength = saltLength
        self.maxTime = maxTime


    def _deferToThread(self, f, *a):
        """
        Defers to the thread pool.
        """
        return threads.deferToThreadPool(self.reactor, self.threadPool, f, *a)


    def checkPassword(self, stored, provided):
        """
        Checks that the stored key was computed from the provided password.

        Returns a deferred that will fire with ``True`` (if the password was
        correct) or ``False`` otherwise.
        """
        decoded = stored.decode("base64")
        d = self._deferToThread(scrypt.decrypt, decoded, provided)

        def _swallowResult(_result):
            """
            Swallows the result (the original salt) and returns ``True``.
            """
            return True

        def _scryptErrback(failure):
            """
            Catches scrypt errors and returns ``False``.
            """
            failure.trap(scrypt.error)
            return False

        return d.addCallbacks(_swallowResult, _scryptErrback)


    def computeKey(self, password):
        """
        Computes a key from the password using a secure key derivation function.
        """
        salt = self.urandom(self.saltLength)
        d = self._deferToThread(scrypt.encrypt, salt, password, self.maxTime)
        return d.addCallback(lambda s: s.encode("base64").strip())



DEFAULT_SALT_LENGTH = 256 // 8
DEFAULT_MAX_TIME = .1

_pool = threadpool.ThreadPool()
_wrapper = Wrapper(reactor, _pool, DEFAULT_SALT_LENGTH, DEFAULT_MAX_TIME)
computeKey  = _wrapper.computeKey
checkPassword = _wrapper.checkPassword

# Keep a reference to the reactor thread pool so I can unit test that
# the module-level instance isn't using it, despite t.trial
# shennanigans.
_reactorPool = reactor.getThreadPool()
