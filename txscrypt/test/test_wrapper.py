"""
Tests for the scrypt wrapper.
"""
from json import dumps, loads
from scrypt import hash
from twisted.trial import unittest
from txscrypt import wrapper as w


class WrapperTests(unittest.TestCase):
    def setUp(self):
        self.reactor = _FakeReactor()

        self.threadPool = _FakeThreadPool()
        self.threadPool.success = True

        self.saltLength, self.iterations = 3141, 5926
        self.wrapper = w.Wrapper(self.reactor, self.threadPool,
                                 self.saltLength, N=self.iterations)

        self.randomBytesRequested = None
        self.wrapper.urandom = self._urandom

        self.storedParams = {"N": 1234, "r": 10, "p": 10}
        key, salt = [s.encode("base64").strip() for s in ["KEY", "SALT"]]
        params = dumps(self.storedParams)
        self.stored = "txscrypt${0}${1}${2}".format(params, key, salt)


    def _urandom(self, n):
        self.randomBytesRequested = n
        return "SALT" # YOLO


    def test_startAndStopThreadPool(self):
        """
        The thread pool starts stopped, and can be started and stopped again.
        """
        self.assertFalse(self.threadPool.started)

        self.threadPool.start()
        self.assertTrue(self.threadPool.started)

        self.threadPool.stop()
        self.assertFalse(self.threadPool.started)


    def assertThreadPoolStartedAndStopScheduled(self):
        """
        Asserts that the thread pool has been started, and that there is
        exactly one scheduled system event, to stop the thread pool
        before reactor shutdown.
        """
        self.assertEqual(len(self.reactor.eventTriggers), 1)
        phase, eventType, f, args, kwargs = self.reactor.eventTriggers[0]
        self.assertEqual(phase, "before")
        self.assertEqual(eventType, "shutdown")
        self.assertEqual(f.im_func, self.threadPool.stop.im_func)
        self.assertEqual(args, ())
        self.assertEqual(kwargs, {})


    def test_parameters(self):
        """The wrapper has the parameters it was given as attributes.

        """
        self.assertEqual(self.wrapper.reactor, self.reactor)
        self.assertEqual(self.wrapper.threadPool, self.threadPool)
        self.assertEqual(self.wrapper.saltLength, self.saltLength)
        self.assertEqual(self.wrapper._params, {"N": self.iterations})


    def assertFailsWithValueError(self, storedValue, substring):
        """Asserts that one of the early sanity checks on the structure of the
        provided stored value fail with ValueError, and that the given
        substring is in the error message.

        """
        d = self.wrapper.checkPassword(storedValue, "")
        failure = self.failureResultOf(d, ValueError)
        self.assertIn(substring, failure.value.message)


    def test_raisesOnIncorrectNumberOfFields(self):
        """When the number of fields is incorrect, the returned deferred
        fails with ValueError.

        """
        self.assertFailsWithValueError("$", "fields")
        self.assertFailsWithValueError("$$", "fields")
        self.assertFailsWithValueError("$$$$", "fields")


    def test_raisesOnBadComment(self):
        """When the comment is incorrect, the returned deferred fails with
        ValueError.

        """
        self.assertFailsWithValueError("BOGUS$$$", "prefix")


    def assertHashCalled(self, password, salt, expectedParams):
        """The scrypt hash function is deferred to a thread with the
        appropriate arguments.

        """
        self.assertEqual(self.threadPool.f, hash)
        self.assertEqual(self.threadPool.args, (password, salt))
        self.assertEqual(self.threadPool.kwargs, expectedParams)
        self.assertTrue(self.threadPool.started)


    def test_computeKey(self):
        """Computing a key returns a deferred that fires with the base64
        encoded derived key. The thread pool is started as necessary.
        The default parameters are passed to the hash function.

        """
        self.threadPool.result = "KEY"

        d = self.wrapper.computeKey("THE_PASSWORD")
        result = self.successResultOf(d)

        self.assertEqual(result, 'txscrypt${"N": 5926}$S0VZ$U0FMVA==')

        self.assertHashCalled("THE_PASSWORD", "SALT", self.wrapper._params)
        self.assertEqual(self.randomBytesRequested, self.wrapper.saltLength)
        self.assertThreadPoolStartedAndStopScheduled()


    def test_computeKeyMultipleTimes(self):
        """
        When computing keys multiple times, the thread pool is started once.
        """
        self.test_computeKey()
        self.test_computeKey()


    def test_checkValidPassword(self):
        """Checking a valid password returns a deferred that fires with True.
        The thread pool is started as necessary. The parameters
        encoded in the stored value are passed to the hash function.

        """
        self.threadPool.result = "KEY"

        d = self.wrapper.checkPassword(self.stored, "THE_PASSWORD")
        self.assertTrue(self.successResultOf(d))

        self.assertHashCalled("THE_PASSWORD", "SALT", self.storedParams)
        self.assertEqual(self.randomBytesRequested, None)
        self.assertThreadPoolStartedAndStopScheduled()


    def test_checkInvalidPassword(self):
        """
        Checking an invalid password provides a deferred that fires with
        False. The thread pool is started as necessary. The parameters
        encoded in the stored value are passed to the hash function.
        """
        self.threadPool.result = "DIFFERENT_KEY"

        d = self.wrapper.checkPassword(self.stored, "FAKE_PASSWORD")
        self.assertFalse(self.successResultOf(d))

        self.assertHashCalled("FAKE_PASSWORD", "SALT", self.storedParams)
        self.assertEqual(self.randomBytesRequested, None)
        self.assertThreadPoolStartedAndStopScheduled()


    def test_checkPasswordMultipleTimes(self):
        """
        When checking passwords multiple times, the thread pool is started
        once.
        """
        self.test_checkValidPassword()
        self.test_checkValidPassword()



class _FakeThreadPool(object):
    """Fake thread pool for testing purposes.

    A fake thread pool that pretends to let you call things in a
    thread with a callback. It remembers what it was called with, and
    calls the callback synchronously.

    """
    def __init__(self):
        self.started = False
        self.success = True
        self.result = None


    def start(self):
        """
        Sets the started attribute to True.
        """
        self.started = True


    def stop(self):
        """
        Sets the started attribute to True.
        """
        self.started = False


    def callInThreadWithCallback(self, onResult, f, *args, **kwargs):
        self.f, self.args, self.kwargs = f, args, kwargs
        onResult(self.success, self.result)



class _FakeReactor(object):
    """
    A fake reactor that pretends to be able to be called from a thread.
    """
    def __init__(self):
        self.eventTriggers = []


    def callFromThread(self, f, *a, **kw):
        """
        Just call the function in this thread.
        """
        f(*a, **kw)


    def addSystemEventTrigger(self, phase, eventType, callable, *args, **kw):
        """
        Stores the event trigger.
        """
        trigger = phase, eventType, callable, args, kw
        self.eventTriggers.append(trigger)



class DefaultParameterTests(unittest.TestCase):
    """
    Tests the default values of scrypt parameters.
    """
    def test_saltLength(self):
        """
        The default salt length is 256 bits.
        """
        self.assertEqual(w.DEFAULT_SALT_LENGTH, 256 // 8)


    def test_iterations(self):
        """
        The default number of iterations is 2 ** 15.
        """
        self.assertEqual(w.DEFAULT_ITERATIONS, 2 ** 15)



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
        self.assertEqual(w._wrapper._params, {"N": w.DEFAULT_ITERATIONS})


    def test_separateThreadPool(self):
        """
        The module level wrapper does not use the reactor thread pool.

        This test can not call reactor.getThreadPool() because trial
        makes sure there's a new thread pool between tests.
        """
        self.assertNotIdentical(w._reactorPool, w._wrapper.threadPool)
