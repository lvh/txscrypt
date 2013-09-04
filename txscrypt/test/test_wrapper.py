"""
Tests for the scrypt wrapper.
"""
import scrypt
from twisted.trial import unittest
from txscrypt import wrapper as w


class WrapperTests(unittest.TestCase):
    def setUp(self):
        self.reactor = _FakeReactor()
        self.threadPool = _FakeThreadPool()
        self.saltLength, self.maxTime = 3141, 5926
        self.wrapper = w.Wrapper(self.reactor, self.threadPool,
                                 self.saltLength, self.maxTime)
        self.wrapper.urandom = self._urandom


    def _urandom(self, n):
        self.randomBytesRequested = n
        return "RANDOM_BYTES" # YOLO


    def test_parameters(self):
        """
        The wrapper has the parameters it was given as attributes.
        """
        self.assertEqual(self.wrapper.reactor, self.reactor)
        self.assertEqual(self.wrapper.threadPool, self.threadPool)
        self.assertEqual(self.wrapper.saltLength, self.saltLength)
        self.assertEqual(self.wrapper.maxTime, self.maxTime)


    def test_computeKey(self):
        """
        Computing a key works. The result is base64 encoded.
        """
        self.threadPool.success = True
        self.threadPool.result = "STORED_PASSWORD"

        d = self.wrapper.computeKey("THE_PASSWORD")
        result = self.successResultOf(d)

        expected = "STORED_PASSWORD".encode("base64").strip()
        self.assertEqual(result, expected)

        self.assertEqual(self.threadPool.f, scrypt.encrypt)
        expectedArgs = "RANDOM_BYTES", "THE_PASSWORD", self.wrapper.maxTime
        self.assertEqual(self.threadPool.args, expectedArgs)
        self.assertEqual(self.threadPool.kwargs, {})

        self.assertEqual(self.randomBytesRequested, self.wrapper.saltLength)


    def test_checkValidPassword(self):
        """
        Checking a valid password provides a deferred that fires with
        True.
        """
        self.threadPool.success = True
        self.threadPool.result = "THE_SALT"

        stored = "STORED_PASSWORD".encode("base64").strip()
        d = self.wrapper.checkPassword(stored, "REAL_PASSWORD")
        self.assertTrue(self.successResultOf(d))

        self.assertEqual(self.threadPool.f, scrypt.decrypt)
        expectedArgs = "STORED_PASSWORD", "REAL_PASSWORD"
        self.assertEqual(self.threadPool.args, expectedArgs)
        self.assertEqual(self.threadPool.kwargs, {})


    def test_checkInvalidPassword(self):
        """
        Checking an invalid password provides a deferred that fires with
        False.
        """
        self.threadPool.success = False
        self.threadPool.result = scrypt.error(0)

        stored = "STORED_PASSWORD".encode("base64").strip()
        d = self.wrapper.checkPassword(stored, "FAKE_PASSWORD")
        self.assertFalse(self.successResultOf(d))

        self.assertEqual(self.threadPool.f, scrypt.decrypt)
        expectedArgs = "STORED_PASSWORD", "FAKE_PASSWORD"
        self.assertEqual(self.threadPool.args, expectedArgs)
        self.assertEqual(self.threadPool.kwargs, {})



class _FakeThreadPool(object):
    """Fake thread pool for testing purposes.

    A fake thread pool that pretends to let you call things in a
    thread with a callback. It remembers what it was called with, and
    calls the callback synchronously.

    """
    def __init__(self):
        self.success = True
        self.result = None


    def callInThreadWithCallback(self, onResult, f, *args, **kwargs):
        self.f, self.args, self.kwargs = f, args, kwargs
        onResult(self.success, self.result)



class _FakeReactor(object):
    """
    A fake reactor that pretends to be able to be called from a thread.
    """
    def callFromThread(self, f, *a, **kw):
        """
        Just call the function in this thread.
        """
        f(*a, **kw)



class DefaultParameterTests(unittest.TestCase):
    """
    Tests the default values of scrypt parameters.
    """
    def test_saltLength(self):
        """
        The default salt length is 256 bits.
        """
        self.assertEqual(w.DEFAULT_SALT_LENGTH, 256 // 8)


    def test_maxTime(self):
        """
        The default maximum computation time is 0.1 seconds.
        """
        self.assertEqual(w.DEFAULT_MAX_TIME, .1)



class DefaultWrapperTests(unittest.TestCase):
    def test_methods(self):
        """
        The module-level API functions are methods of the wrapper.
        """
        for a in ["computeKey", "checkPassword"]:
            moduleLevel = getattr(w, a).im_func
            instanceLevel = getattr(w._wrapper, a).im_func
            self.assertIdentical(moduleLevel, instanceLevel)


    def test_parameters(self):
        """
        The module-level wrapper uses the default parameter values.
        """
        self.assertIdentical(w._wrapper.saltLength, w.DEFAULT_SALT_LENGTH)
        self.assertIdentical(w._wrapper.maxTime, w.DEFAULT_MAX_TIME)


    def test_threadPool(self):
        """
        The module level wrapper does not use the reactor thread pool.

        This test can not call reactor.getThreadPool() because trial
        makes sure there's a new thread pool between tests.
        """
        self.assertNotIdentical(w._reactorPool, w._wrapper.threadPool)
