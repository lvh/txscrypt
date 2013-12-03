"""
Wrapper around scrypt.
"""
from os import urandom
from scrypt import hash
from twisted.internet import reactor
from twisted.internet.threads import deferToThreadPool
from twisted.python import threadpool


class Wrapper(object):
    urandom = staticmethod(urandom)

    def __init__(self, reactor, threadPool, saltLength, **kwargs):
        self.reactor = reactor
        self.threadPool = threadPool
        self.saltLength = saltLength
        self.kwargs = kwargs


    def _deferToThread(self, f, *a, **kw):
        """Defers to the thread pool.

        If the thread pool has not been started yet, starts the thread
        pool and schedules it to be stopped before the reactor stops.

        """
        if not self.threadPool.started:
            self.threadPool.start()
            self.reactor.addSystemEventTrigger(
                "before", "shutdown", self.threadPool.stop)

        return deferToThreadPool(self.reactor, self.threadPool, f, *a, **kw)


    def _hash(self, password):
        """Computes the hash of the given password, with the wrapper's
        parameters.

        """
        salt = self.urandom(self.saltLength)
        return self._deferToThread(hash, password, salt, **self.kwargs)


    def checkPassword(self, stored, provided):
        """Checks that the stored key was computed from the provided password.

        Returns a deferred that will fire with ``True``, if the
        password was correct, or ``False`` otherwise.

        """
        d = self._hash(provided)
        return d.addCallback(stored.decode("base64").__eq__)


    def computeKey(self, password):
        """Computes a key from the password using a secure key derivation
        function.

        """
        return self._hash(password).addCallback(self._encode)


    def _encode(self, computedKey):
        """
        Base64-encodes the key.
        """
        return computedKey.encode("base64").strip()



DEFAULT_SALT_LENGTH = 256 // 8
DEFAULT_ITERATIONS = 2 ** 15

_pool = threadpool.ThreadPool()
_wrapper = Wrapper(reactor, _pool, DEFAULT_SALT_LENGTH, N=DEFAULT_ITERATIONS)
computeKey  = _wrapper.computeKey
checkPassword = _wrapper.checkPassword

# Keep a reference to the reactor thread pool so I can unit test that
# the module-level instance isn't using it, despite t.trial
# shennanigans.
_reactorPool = reactor.getThreadPool()
