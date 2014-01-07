==========
 txscrypt
==========

`txscrypt`_ is a `Twisted`_-friendly wrapper for `scrypt`_. `scrypt`_
is a key derivation function. It's the kind of thing you want to use
to store user's passwords securely, if you're writing a password
storage library. (If you're not, use one.)

.. _`txscrypt`: https://github.com/lvh/txscrypt
.. _`Twisted`: https://www.twistedmatrix.com
.. _`scrypt`: https://www.tarsnap.com/scrypt.html

.. image:: https://dl.dropbox.com/u/38476311/Logos/txscrypt.png
    :align: center
    :width: 300px

How do I store a password?
==========================

Easy.

.. code:: python

    from txscrypt import computeKey
    d = computeKey(password)
    d.addCallback(storeSomewhere)

``computeKey`` is a function. You give it the plaintext password, in
bytes. If your user is giving you a password in Unicode, encode it
first. You get a deferred that will fire, at some point, with a
magical string of bytes. Store it.

Okay. How do I check a password?
================================

.. code:: python

    from txscrypt import checkPassword
    d = checkPassword(stored, provided)

In this snippet, ``stored`` is the thing you got from ``computeKey``.
``provided`` is the password as provided by the user. Give it the same
treatment you gave the password before you passed it to
``computeKey``. For example, if it's Unicode, encode it.

You get a deferred. At some point in the future, it will fire with
either ``True`` if the password matched or ``False`` if it didn't.

Why is the magical string base64-encoded?
=========================================

You're not supposed to care about what's in it.

It's not entirely base64 encoded, but it does contain some base64
encoded parts. If it weren't, it'd have a bunch of NUL bytes and other
gnarly stuff (i.e. not printable ASCII) in it, and that makes a lot of
storage stuff balk.

If you must know, it looks like this::

  COMMENT$PARAMS$ENCODED_KEY$ENCODED_SALT

Where ``COMMENT`` is currently always ``txscrypt``, ``PARAMS`` is a
JSON object containing the parameters used to invoke the scrypt hash
function (N, r, p, buflen), ``ENCODED_KEY`` is the base64 encoded key,
``ENCODED_SALT`` is the base64 encoded salt.

Earlier versions of txscrypt used the raw bytes produced by scrypt.
Some third party tools bit off those strings after the first NUL byte.
Unluckily, this was immediately after the word "scrypt", which were
the first bytes of that string.

But what about salts?
=====================

txscrypt takes care of this for you.

(It computes a salt of sufficient length using your OS'
cryptographically secure random number generator. Currently, that
length is 256 bits.)

But what about timing attacks?
==============================

txscrypt takes care of this for you.

(It relies on salts being of sufficient length. There might be side
channels related to multiple executions of ``scrypt`` on the same
machine; but to the author's knowledge this has never been
demonstrated as an attack.)

But what about starving the thread pool?
========================================

txscrypt takes care of this for you.

(It creates a new thread pool just for running scrypt in. This means
that scrypt doesn't compete against, say, DNS resolution, or things
you pass to ``deferToThread``.)

But what about shutting down the thread pool?
=============================================

txscrypt takes care of this for you.

(It tells the reactor to stop the thread pool at the start of its own
shutdown procedure. That does mean that you have to have the reactor
running for any computations to work.)

When should I create my own Wrapper object?
===========================================

If you want to change:

- the salt length
- the thread pool
- any of the default scrypt hash parameters (N, r, p, buflen)

So, basically, never. If the number of iterations is insecure, file a
bug with txscrypt, so it can be amended.

Changelog
=========

3.0.0
-----

**Incompatible change with previous versions!**

The internal format now stores the parameters, so that changing them
(e.g. upgrading the number of iterations) will result in a smooth
forward transition.

2.0.1
-----

README updates and test suite updates.

2.0.0
-----

**Incompatible change with previous versions!**

- Now uses the newly exposed ``hash`` function, making key derivation
  fully deterministic.
- The ``maxTime`` argument has been removed.

1.1.1
-----

- Remove stale references to verifyPassword in documentation and
  __all__

Thanks Matt Haggard for the bug report!

1.1.0
-----

- Only start the thread pool on first use
- Stop the thread pool when the reactor starts shutting down

1.0.0
-----

**Incompatible change with previous versions!**

- Remove deprecated verifyPassword API
- Use less high-quality entropy for salt bits
- Use term "salt", consistency with scrypt paper
- Base64s output, prevents other software choking on NUL bytes
- Internal rewrite, easier to test
