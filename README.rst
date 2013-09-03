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

Okay. How do I verify a password?
=================================

.. code:: python

    from txscrypt import verifyPassword
    d = verifyPassword(stored, provided)

In this snippet, ``stored`` is the thing you got from ``computeKey``.
``provided`` is the password as provided by the user. Give it the same
treatment you gave the password before you passed it to
``computeKey``. For example, if it's Unicode, encode it.

You get a deferred. At some point in the future, it will fire with
either ``True`` if the password matched or ``False`` if it didn't.

But what about salts?
=====================

txscrypt takes care of this for you.

But what about timing attacks?
==============================

txscrypt takes care of this for you.

(That is, unless there are side channels related to multiple
executions of ``scrypt`` on the same machine.)
