"""
A Twisted-friendly wrapper for scrypt.
"""
from txscrypt.wrapper import computeKey, verifyPassword

__all__ = ["computeKey", "verifyPassword"]
