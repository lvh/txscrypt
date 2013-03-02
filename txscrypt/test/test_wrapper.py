"""
Tests for the scrypt wrapper.
"""
import mock
import scrypt
import warnings

from twisted.cred import error
from twisted.internet import defer
from twisted.trial import unittest

from txscrypt import wrapper as w


_deferToThread = "twisted.internet.threads.deferToThread"


class _PasswordTestCase(unittest.TestCase):
    """
    A test case that precomputes a key from a password.
    """
    @defer.inlineCallbacks
    def setUp(self):
        self.computed = yield w.computeKey("password", maxTime=0.0001)



class VerifyPasswordTests(_PasswordTestCase):
    """
    Tests for verifying a stored key matches a given password.
    """
    def _verifyPassword(self, password):
        """
        Verifies a password
        """
        return w.verifyPassword(self.computed, password)


    def test_success(self):
        """
        Tests that ``verifyPassword`` returns ``None`` if the password was
        correct.
        """
        d = self._verifyPassword("password")
        return d.addCallback(self.assertIdentical, None)


    def test_failure(self):
        """
        Tests that ``verifyPassword`` returns a deferred that fails with
        ``error.UnauthorizedLogin`` if the password was wrong.
        """
        d = self._verifyPassword("BOGUS")
        self.assertFailure(d, error.UnauthorizedLogin)
        return d


    def test_deprecated(self):
        with warnings.catch_warnings(record=True) as c:
            self._verifyPassword("password")
            self.assertEqual(len(c), 1)
            self.assertEqual(c[-1].category, DeprecationWarning)

            message = str(c[-1].message)
            self.assertIn("deprecated", message)
            self.assertIn("checkPassword", message)


class CheckPasswordTests(_PasswordTestCase):
    """
    Tests for ``checkPassword``.
    """
    def _checkPassword(self, password):
        """
        Checks the provided password against the precomputed key.
        """
        return w.checkPassword(self.computed, password)


    def test_success(self):
        """
        Tests that when the provided password is right, the deferred fires
        with ``True``.
        """
        return self._checkPassword("password").addCallback(self.assertTrue)


    def test_failure(self):
        """
        Tests that when the provided password is wrong, the deferred fires
        with ``False``.
        """
        return self._checkPassword("BOGUS").addCallback(self.assertFalse)



class ComputeKeyTests(unittest.TestCase):
    """
    Tests for computing a new key from a password.
    """
    def _test_computeKey(self, nonceLength=w.NONCE_LENGTH, maxTime=w.MAX_TIME):
        with mock.patch("os.urandom") as mu, mock.patch(_deferToThread) as md:
            w.computeKey("a", nonceLength, maxTime)
            mu.assert_called_once_with(nonceLength)
            args = scrypt.encrypt, mu.return_value, "a", maxTime
            md.assert_called_once_with(*args)


    def test_defaults(self):
        """
        Tests the default values ``computeKey`` gets called with.
        """
        return self._test_computeKey()


    def test_differentParameters(self):
        """
        Tests that the default values for ``computeKey`` can be overridden.
        """
        return self._test_computeKey(object(), object())
