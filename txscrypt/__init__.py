"""
A Twisted-friendly wrapper for scrypt.
"""
from txscrypt.wrapper import computeKey, verifyPassword
from txscrypt._version import __version__

__all__ = ["computeKey", "verifyPassword"]
