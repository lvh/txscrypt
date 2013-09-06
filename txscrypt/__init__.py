"""
A Twisted-friendly wrapper for scrypt.
"""
from txscrypt.wrapper import checkPassword, computeKey
from txscrypt._version import __version__

__all__ = ["checkPassword", "computeKey"]
