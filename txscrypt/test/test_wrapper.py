"""
Tests for the scrypt wrapper.
"""
import mock
import scrypt

from twisted.cred import error
from twisted.internet import defer
from twisted.trial import unittest

from txscrypt import wrapper as w


_deferToThread = "twisted.internet.threads.deferToThread"


class VerifyPasswordTests(unittest.TestCase):
    """
    Tests for verifying a stored key matches a given password.
    """
    def _test_verifyPassword(self, returnValue, stored, provided):
        """
        Generic password verifying test.
        """
        with mock.patch(_deferToThread) as m:
            m.return_value = returnValue
            d = w.verifyPassword(stored, provided)
            m.assert_called_once_with(scrypt.decrypt, stored, provided)

        return d


    def test_success(self):
        """
        Tests the happy case of verifying a password.
        """
        returnValue, stored, provided = defer.succeed(""), "a", "a"
        d = self._test_verifyPassword(returnValue, stored, provided)
        return d.addCallback(self.assertIdentical, None)


    def test_failure(self):
        """
        Failing test for verifying a password.

        This could be because the password was wrong, or because it took too
        long to decrypt.
        """
        returnValue, stored, provided = defer.fail(scrypt.error()), "a", "b"
        d = self._test_verifyPassword(returnValue, stored, provided)
        return self.assertFailure(d, error.UnauthorizedLogin)



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
        return self._test_computeKey()


    def test_differentParameters(self):
        return self._test_computeKey(object(), object())
