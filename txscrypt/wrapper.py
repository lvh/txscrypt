"""
Wrapper around scrypt.
"""
import os
import scrypt

from twisted.cred import error
from twisted.internet import threads


NONCE_LENGTH = 64
MAX_TIME = .1


def verifyPassword(stored, provided):
    """
    Verifies that the stored derived key was computed from the provided
    password.
    """
    d = threads.deferToThread(scrypt.decrypt, stored, provided)

    def _swallowResult(_result):
        """
        Swallows the result (the original nonce).
        """
        return None

    def _scryptErrback(failure):
        """
        Catches the scrypt error and turns it into a Twisted Cred error.
        """
        failure.trap(scrypt.error)
        raise error.UnauthorizedLogin()

    return d.addCallbacks(_swallowResult, _scryptErrback)


def computeKey(password, nonceLength=NONCE_LENGTH, maxTime=MAX_TIME):
    """
    Computes a key from the password using a secure key derivation function.
    """
    nonce = os.urandom(nonceLength)
    return threads.deferToThread(scrypt.encrypt, nonce, password, maxTime)
