# coding: utf-8

"""
    PyLucid.tools.crypt
    ~~~~~~~~~~~~~~~~~~~

    Routines for the PyLucid SHA-JS-Login.
    more info:
        http://www.pylucid.org/permalink/42/secure-login-without-https

    unittest: ./dev_scripts/unittests/unittest_crypt.py

    >>> seed_generator.DEBUG=True # Generate always the same seed for tests
    >>> encrypted_with_hash = encrypt(txt="foo", key="bar")
    >>> encrypted_with_hash
    'sha1$DEBUG_123456$197987f5ca3fd97da45acac3541e3464198a1cee$BA4d'

    >>> seed_generator.DEBUG=True # Generate always the same seed for tests
    >>> decrypt(encrypted_with_hash, key="bar")
    'foo'

    >>> decrypt('sha1$DEBUG_123456$197987f5ca3fd97da45aXXc3541e3464198a1cee$BA4d', key="bar")
    Traceback (most recent call last):
        ...
    SaltHashError: salt-sha1hash compare failed.

    :copyleft: 2007-2015 by the PyLucid team, see AUTHORS for more details.
    :license: GNU GPL v3 or above, see LICENSE for more details.
"""

from __future__ import unicode_literals

import base64
import hashlib
import logging
import os
import random
import re
import sys
import time
import binascii

if __name__ == "__main__":
    print("Local DocTest...")
    settings = type('Mock', (object,), {})()
    settings.SECRET_KEY = "DocTest"
else:
    from django.conf import settings

from django.utils import six
from django.utils.encoding import force_bytes, force_text


log = logging.getLogger("secure_js_login")

# Warning: Debug must always be False in productive environment!
# DEBUG = True
DEBUG = False
if DEBUG:
    import warnings
    warnings.warn("Debugmode is on", UserWarning)

HASH_TYP = "sha1"

OLD_SALT_LEN = 5 # old length of the random salt value

# Django used 12 as default in hashers.SHA1PasswordHasher()
# number comes from django.utils.crypto.get_random_string()
SALT_LEN = 12 # new length of the random salt value

HASH_LEN = 40 # length of a SHA-1 hexdigest
HALF_HASH_LEN = 20

# SHA-1 hexdigest + "sha1" + (2x "$") + salt length
SALT_HASH_LEN = HASH_LEN + 4 + 2 + SALT_LEN
OLD_SALT_HASH_LEN = HASH_LEN + 4 + 2 + OLD_SALT_LEN


class SaltHashError(Exception):
    pass

#______________________________________________________________________________

SHA1_RE = re.compile(r'[a-f0-9]{40}$')


def hash_hexdigest(txt):
    assert isinstance(txt, six.text_type), "txt: %s is not text type!" % repr(txt)
    return hashlib.sha1(force_bytes(txt)).hexdigest()


def validate_sha_value(sha_value):
    """
    Check if the given >sha_value< is a possible SHA1 hexdigest ;)
    returned true or false

    Should we better use a RE method?
    http://www.python-forum.de/post-74657.html

    >>> validate_sha_value("wrong length")
    False
    >>> validate_sha_value(1234)
    False
    >>> validate_sha_value("right length but not a SHA1 hexdigest!!!")
    False
    >>> validate_sha_value("790f2ebcb902c966fb0e232515ec1319dc9118af")
    True
    """
    if not isinstance(sha_value, six.text_type):
        return False

    if SHA1_RE.match(sha_value):
        return True

    return False
#
#    if not (isinstance(sha_value, basestring) and len(sha_value) == HASH_LEN):
#        return False
#
#    try:
#        int(sha_value, 16)
#    except (ValueError, OverflowError), e:
#        return False
#    else:
#        return True


class SeedGenerator(object):
    """
    Generate a new, random seed values.

    >>> seed_generator.DEBUG=True # Generate always the same seed for tests
    >>> seed_generator()
    'DEBUG_1234567890'

    try to check if every new seed is unique:
    >>> seed_generator.DEBUG=False
    >>> seeds = ['DEBUG_1234567890']
    >>> for _ in range(10):
    ...     seed = seed_generator()
    ...     assert len(seed) == HASH_LEN, "Wrong length: %s" % len(seed)
    ...     assert seed not in seeds
    ...     seeds.append(seed)
    >>> len(seeds)
    11
    """
    DEBUG=False
    def __call__(self):
        if self.DEBUG:
            log.critical("Use DEBUG seed!")
            return "DEBUG_1234567890"

        raw_seed = "%s%s%s%s" % (
            random.randint(0, sys.maxsize - 1), os.getpid(), time.time(),
            settings.SECRET_KEY
        )
        return hash_hexdigest(raw_seed)

seed_generator = SeedGenerator()


def get_new_salt():
    """
    Generate a new, random salt value.

    >>> seed_generator.DEBUG=True # Generate always the same seed for tests
    >>> get_new_salt() # DEBUG is True in DocTest!
    'DEBUG_123456'

    try to check if every new salt is unique:
    >>> seed_generator.DEBUG=False
    >>> salts = ['DEBUG_123456']
    >>> for _ in range(10):
    ...     salt = get_new_salt()
    ...     assert len(salt) == SALT_LEN, "Wrong length: %s" % len(salt)
    ...     assert salt not in salts
    ...     salts.append(salt)
    >>> len(salts)
    11
    """
    seed = seed_generator()
    return seed[:SALT_LEN]


def get_pseudo_salt(*args):
    """
    generate a pseudo salt (used, if user is wrong)
    """
    temp = "".join([arg for arg in args])
    return hash_hexdigest(temp)[:SALT_LEN]


def make_hash(txt, salt):
    """
    make a SHA1 hexdigest from the given >txt< and >salt<.
    IMPORTANT:
        This routine must work like
        django.contrib.auth.models.User.set_password()!

    >>> make_hash(txt="test", salt='DEBUG')
    '790f2ebcb902c966fb0e232515ec1319dc9118af'
    """
    assert isinstance(txt, six.text_type), "txt: %s is not text type!" % repr(txt)
    assert isinstance(salt, six.text_type), "salt: %s is not text type!" % repr(salt)

    sha1hash = hash_hexdigest(salt + txt)
    return sha1hash


def get_salt_and_hash(txt):
    """
    Generate a hast value with a random salt
    returned salt and sha1hash as a tuple

    >>> seed_generator.DEBUG=True # Generate always the same seed for tests
    >>> get_salt_and_hash("test")
    ('sha1', 'DEBUG_123456', '9f5ee85f5c91adb5741d8f93483386989d5d49ae')

    try to check if every new salt/hash is unique:
    >>> salts = ['DEBUG_123456']
    >>> hashes = ['9f5ee85f5c91adb5741d8f93483386989d5d49ae']
    >>> seed_generator.DEBUG=False
    >>> for _ in range(10):
    ...     hash_type, salt, hash = get_salt_and_hash("test")
    ...     assert len(salt) == SALT_LEN, "Wrong length: %s" % len(salt)
    ...     assert len(hash) == HASH_LEN, "Wrong length: %s" % len(salt)
    ...     assert salt not in salts
    ...     salts.append(salt)
    ...     assert hash not in hashes
    ...     hashes.append(hash)
    >>> len(salts), len(hashes)
    (11, 11)
    """
    assert isinstance(txt, six.text_type), "txt: %s is not text type!" % repr(txt)

    salt = get_new_salt()
    sha1hash = make_hash(txt, salt)

    return (HASH_TYP, salt, sha1hash)


def make_salt_hash(txt):
    """
    make from the given string a hash with a salt value
    returned one string back

    >>> seed_generator.DEBUG=True # Generate always the same seed for tests
    >>> make_salt_hash("test")
    'sha1$DEBUG_123456$9f5ee85f5c91adb5741d8f93483386989d5d49ae'

    try to check if every new salt/hash is unique:
    >>> seed_generator.DEBUG=False
    >>> salt_hashes = ['sha1$DEBUG_123456$9f5ee85f5c91adb5741d8f93483386989d5d49ae']
    >>> for _ in range(10):
    ...     salt_hash = make_salt_hash("test")
    ...     assert len(salt_hash) == SALT_HASH_LEN, "Wrong length: %s" % len(salt)
    ...     assert salt_hash not in salt_hashes
    ...     salt_hashes.append(salt_hash)
    >>> len(salt_hashes)
    11
    """
    assert isinstance(txt, six.text_type), "txt: %s is not text type!" % repr(txt)
    salt_hash = "$".join(get_salt_and_hash(txt))
    return salt_hash


def check_salt_hash(txt, salt_hash):
    """
    compare txt with the salt-sha1hash.

    TODO: Should we used the django function for this?
        Look at: django.contrib.auth.models.check_password

    >>> seed_generator.DEBUG=True # Generate always the same seed for tests
    >>> salt_hash = make_salt_hash("test")
    >>> salt_hash
    'sha1$DEBUG_123456$9f5ee85f5c91adb5741d8f93483386989d5d49ae'
    >>> check_salt_hash("test", salt_hash)
    True
    """
    assert isinstance(txt, six.text_type), "txt: %s is not text type!" % repr(txt)
    assert isinstance(salt_hash, six.text_type), "salt_hash: %s is not text type!" % repr(salt_hash)

    if len(salt_hash) not in (SALT_HASH_LEN, OLD_SALT_HASH_LEN):
        raise SaltHashError("Wrong salt-sha1hash length.")

    try:
        hash_type, salt, sha1hash = salt_hash.split("$")
    except ValueError:
        raise SaltHashError("Wrong salt-sha1hash format.")

    if hash_type != "sha1":
        raise SaltHashError("Unsupported sha1hash method.")

    test_hash = make_hash(txt, salt)

    if sha1hash != test_hash:
        msg = "salt-sha1hash compare failed."
        if DEBUG:
            msg += " (txt: '%s', salt: '%s', sha1hash: '%s', test_hash: '%s')" % (
                txt, salt, sha1hash, test_hash
            )
        raise SaltHashError(msg)

    return True


def salt_hash_to_dict(salt_hash):
    """
    >>> result = salt_hash_to_dict("sha$salt_value$the_SHA_value")
    >>> result == {'salt': 'salt_value', 'hash_type': 'sha', 'hash_value': 'the_SHA_value'}
    True
    """
    hash_type, salt, hash_value = salt_hash.split("$")
    return {
        "hash_type": hash_type,
        "salt": salt,
        "hash_value": hash_value
    }



class CryptLengthError(AssertionError):
    pass


class XorCryptor(object):
    """
    XOR ciphering

    >>> crypt(b"1234", b"ABCD")
    b'pppp'
    """
    def __call__(self, txt, key):
        assert isinstance(txt, six.binary_type), "txt: %s is not binary type!" % repr(txt)
        assert isinstance(key, six.binary_type), "key: %s is not binary type!" % repr(key)

        if len(txt) != len(key):
            raise CryptLengthError("XOR cipher error: %r and %r must have the same length!" % (txt, key))

        if six.PY2:
            crypted = "".join([chr(ord(t) ^ ord(k)) for t, k in zip(txt, key)])
        else:
            crypted = [(t ^ k) for t, k in zip(txt, key)]
            crypted = bytes(crypted)
        return crypted

crypt=XorCryptor()


def encrypt(txt, key):
    """
    XOR ciphering with a SHA salt-hash checksum

    >>> seed_generator.DEBUG=True # Generate always the same seed for tests
    >>> make_salt_hash("1234")
    'sha1$DEBUG_123456$7a3a52f5e751461ed74f09d18010dcd6e3acf653'

    >>> seed_generator.DEBUG=True # Generate always the same seed for tests
    >>> encrypt("1234", "ABCD")
    'sha1$DEBUG_123456$7a3a52f5e751461ed74f09d18010dcd6e3acf653$cHBwcA=='
    """
    assert isinstance(txt, six.text_type), "txt: %s is not text type!" % repr(txt)
    assert isinstance(key, six.text_type), "key: %s is not text type!" % repr(key)

    if len(txt) != len(key):
        raise CryptLengthError("encrypt error: %r and %r must have the same length!" % (txt, key))

    salt_hash = make_salt_hash(txt)

    txt=force_bytes(txt)
    key=force_bytes(key)

    crypted = crypt(txt, key)
    crypted = base64.b64encode(crypted)

    crypted = six.text_type(crypted, "ascii")
    return "%s$%s" % (salt_hash, crypted)


def decrypt(txt, key):
    """
    1. Decrypt a XOR crypted String.
    2. Compare the inserted SHA salt-hash checksum.

    >>> seed_generator.DEBUG=True # Generate always the same seed for tests
    >>> decrypt("sha1$DEBUG_123456$7a3a52f5e751461ed74f09d18010dcd6e3acf653$cHBwcA==", "ABCD")
    '1234'
    """
    assert isinstance(txt, six.text_type), "txt: %s is not text type!" % repr(txt)
    assert isinstance(key, six.text_type), "key: %s is not text type!" % repr(key)

    salt_hash, crypted = txt.rsplit("$",1)

    if not seed_generator.DEBUG and len(salt_hash)!=SALT_HASH_LEN:
        raise CryptLengthError(
            "encrypt error: Salt-hash %s with length %i must be length %i!" % (
                repr(salt_hash), len(salt_hash), SALT_HASH_LEN
            )
        )

    try:
        crypted = base64.b64decode(crypted, validate=True)
    except binascii.Error as err:
        raise CryptLengthError("b64decode error: %s with data: %s" % (err, repr(crypted)))

    if len(crypted) != len(key):
        raise CryptLengthError("encrypt error: %r and %r must have the same length!" % (crypted, key))

    key=force_bytes(key)
    decrypted = crypt(crypted, key)

    try:
        decrypted = force_text(decrypted)
    except UnicodeDecodeError:
        raise SaltHashError("Can't decode data.")

    # raised a SaltHashError() if the checksum is wrong:
    check_salt_hash(decrypted, salt_hash)

    return decrypted



# def django_to_sha_checksum(django_salt_hash):
#     """
#     Create a JS-SHA-Checksum from the django user password.
#     (For the unittest)
#
#     The >django_salt_hash< is:
#         user = User.objects.get(...)
#         django_salt_hash = user.password
#
#     >>> django_to_sha_checksum("sha1$DEBUG$50b412a7ef09f4035f2daca882a1f8bfbe263b62")
#     ('DEBUG', 'crypt 50b412a7ef09f4035f2d with aca882a1f8bfbe263b62')
#     """
#     hash_typ, salt, hash_value = django_salt_hash.split("$")
#     assert hash_typ == "sha1", "hash_value typ not supported!"
#     assert len(hash_value) == HASH_LEN, "Wrong hash_value length! (Not a SHA1 hash_value?)"
#
#     # Split the SHA1-Hash in two pieces
#     sha_a = hash_value[:HALF_HASH_LEN]
#     sha_b = hash_value[HALF_HASH_LEN:]
#
#     sha_checksum = encrypt(txt=sha_a, key=sha_b)
#
#     return salt, sha_checksum


def make_sha_checksum2(raw_password):
    """
    Create a SHA1-JS-Login checksum from a plaintext password.

    >>> seed_generator.DEBUG=True # Generate always the same seed for tests
    >>> make_sha_checksum2("test")
    ('DEBUG_123456', 'sha1$DEBUG_123456$a25864a25dc950270a88853e26b027b3a59f953d$AQAMVlEABlUNVQAJWABXUQMNUAE=')
    """
    _, salt, hash_value = get_salt_and_hash(raw_password)

    return salt, make_sha_checksum(hash_value)


def make_sha_checksum(hash_value):
    """
    Made the needed sha_checksum for the SHA1-JS-Login.

    >>> hash = hash_hexdigest("foobar")
    >>> hash
    '8843d7f92416211de9ebb963ff4ce28125932878'

    # Split the hash:
    >>> sha_a = "8843d7f92416211de9eb"
    >>> sha_b = "b963ff4ce28125932878"

    # Make the SHA-Checksum:
    >>> seed_generator.DEBUG=True # Generate always the same seed for tests
    >>> sha_checksum = make_sha_checksum(hash)
    >>> sha_checksum
    'sha1$DEBUG_123456$7213c1ffd40d305496b98c493adffd04e2a312c4$WgECAAJRUlpXBgkHAAQIV1cBUlo='

    # Test the created checksum:
    >>> test = decrypt(sha_checksum, key=sha_b)
    >>> test
    '8843d7f92416211de9eb'
    >>> test == sha_a
    True
    """
    assert len(hash_value)==HASH_LEN

    # Split the SHA1-Hash in two pieces
    sha_a = hash_value[:HALF_HASH_LEN]
    sha_b = hash_value[HALF_HASH_LEN:]
    # print(sha_a, sha_b)

    sha_checksum = encrypt(txt=sha_a, key=sha_b)
    return sha_checksum


def check_js_sha_checksum(challenge, sha_a, sha_b, sha_checksum, loop_count, cnonce):
    """
    Check a PyLucid JS-SHA-Login

    >>> salt1 = "a salt value"
    >>> challenge = "debug"
    >>> loop_count = 5
    >>> cnonce = "0123456789abcdef0123456789abcdef01234567"
    >>> password = "test"
    >>>
    >>> hash_value = make_hash(password, salt1)
    >>> hash_value
    'f893fc3ebdfd886836822161b6bc2ccac955e014'
    >>> seed_generator.DEBUG=True # Generate always the same seed for tests
    >>> sha_checksum = make_sha_checksum(hash_value)
    >>> sha_checksum
    'sha1$DEBUG_123456$b323acd534000e3e35a690a5648fe73db783ac70$VAkPAgRVUQZQBwUFWwEDDVYGCQY='
    >>>
    >>> sha_a = hash_value[:HALF_HASH_LEN]
    >>> sha_a
    'f893fc3ebdfd88683682'
    >>> sha_b = hash_value[HALF_HASH_LEN:]
    >>> sha_b
    '2161b6bc2ccac955e014'
    >>> for i in range(loop_count):
    ...    sha_a
    ...    sha_a = hash_hexdigest("%s%s%s%s" % (sha_a, i, challenge, cnonce))
    'f893fc3ebdfd88683682'
    '7416451ba99917ccd09cfb5168678308933ed82c'
    'ec569defb31299e6134ad8e0c03ff40ab37972da'
    'c8036fe582d777da7090a941e8405982b39a5a71'
    'a0a793881a87782364816ab3e433d02f4527acbb'
    >>> sha_a
    'fa5746d279f5be31fa031100837a6a6b0233467c'
    >>> check_js_sha_checksum(challenge, sha_a, sha_b, sha_checksum, loop_count, cnonce)
    True
    """
    local_sha_a = decrypt(sha_checksum, sha_b)
    log.debug("decrypt %r to %r" % (sha_checksum, local_sha_a))

    for i in range(loop_count):
        local_sha_a = hash_hexdigest(
            "%s%s%s%s" % (local_sha_a, i, challenge, cnonce)
        )

    if local_sha_a == sha_a:
        return True

    log.debug("Hash check failed: %r != %r" % (local_sha_a, sha_a))
    return False



if __name__ == "__main__":
    # print(crypt(b"1234", b"ABCD"))

    import doctest
    print(doctest.testmod(
        verbose=False
    ))
