# coding: utf-8

"""
    Secure JavaScript Login
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyleft: 2007-2015 by the secure-js-login team, see AUTHORS for more details.
    :created: by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from __future__ import unicode_literals

import codecs
import hashlib
import logging
import os
import pprint
import random
import re
import sys
import time
import binascii

if __name__ == "__main__":
    os.environ['DJANGO_SETTINGS_MODULE'] = 'tests.test_utils.test_settings'
    print("\nUse DJANGO_SETTINGS_MODULE=%r" % os.environ["DJANGO_SETTINGS_MODULE"])

from django.conf import settings
from django.utils import six, crypto
from django.utils.encoding import force_bytes, force_text
from django.contrib.auth.hashers import PBKDF2SHA1PasswordHasher

from secure_js_login import settings as app_settings


log = logging.getLogger("secure_js_login")

# Warning: Debug must always be False in productive environment!
# DEBUG = True
DEBUG = False
if DEBUG:
    import warnings
    warnings.warn("Debugmode is on", UserWarning)


PBKDF2_HEX_LENGTH = int(app_settings.PBKDF2_BYTE_LENGTH * 2)
PBKDF2_HALF_HEX_LENGTH = int(PBKDF2_HEX_LENGTH / 2)

assert PBKDF2_HALF_HEX_LENGTH == app_settings.PBKDF2_BYTE_LENGTH


class CryptError(Exception):
    pass


def hash_hexdigest(txt):
    assert isinstance(txt, six.text_type), "txt: %s is not text type!" % repr(txt)
    return hashlib.sha1(force_bytes(txt)).hexdigest()


class SeedGenerator(object):
    """
    Generate a new, random seed values.

    >>> seed_generator.DEBUG=True # Generate always the same seed for tests
    >>> seed_generator(20)
    'DEBUG_78901234567890'
    >>> seed_generator(12)
    'DEBUG_789012'

    try to check if every new seed is unique:
    >>> seed_generator.DEBUG=False
    >>> seeds = ['DEBUG_789012']
    >>> for _ in range(10):
    ...     seed = seed_generator(12)
    ...     assert len(seed) == 12
    ...     assert seed not in seeds
    ...     seeds.append(seed)
    >>> len(seeds)
    11
    """
    DEBUG=False
    def __call__(self, length):
        if self.DEBUG:
            # log.critical("Use DEBUG seed!")
            #            12345678901234567890123456789012345678901234567890
            debug_value="DEBUG_78901234567890123456789012345678901234567890"
            return debug_value[:length]

        return crypto.get_random_string(length=length)

seed_generator = SeedGenerator()


def get_pseudo_salt(length, *args):
    """
    generate a pseudo salt (used, if user is wrong)
    """
    temp = "".join([arg for arg in args])
    return hash_hexdigest(temp)[:length]


def hexlify_pbkdf2(password, salt, iterations, length, digest=hashlib.sha1):
    """
    >>> hexlify_pbkdf2("not secret", "a salt value", iterations=100, length=16)
    '0b919231515dde16f76364666cf07107'
    """
    # log.debug("hexlify_pbkdf2 with iterations=%i", iterations)
    hash = crypto.pbkdf2(password, salt, iterations=iterations, dklen=length, digest=digest)
    hash = binascii.hexlify(hash)
    hash = six.text_type(hash, "ascii")
    return hash


class PBKDF2SHA1Hasher(PBKDF2SHA1PasswordHasher):
    """
    Similar to origin django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher but:
        * variable: iterations, length
        * hexlify the PBKDF2 bytes instead of use base64 encoding (To get always the same length)

    >>> h = PBKDF2SHA1Hasher(iterations=1000, length=32)
    >>> hash = h.encode(password="not secret", salt="a salt value")
    >>> hash
    'pbkdf2_sha1$1000$a salt value$9bbc7565baa47ce8e9f5ef181ea2a8959bec965d2ab09b7671e6b1920c67685f'

    >>> h.verify(password="not secret", encoded=hash)
    True
    >>> h.verify(password="wrong secret", encoded=hash)
    False

    >>> PBKDF2SHA1Hasher(iterations=100, length=32).verify(password="not secret", encoded=hash)
    Traceback (most recent call last):
        ...
    AssertionError: wrong iterations

    >>> PBKDF2SHA1Hasher(iterations=1000, length=16).verify(password="not secret", encoded=hash)
    Traceback (most recent call last):
        ...
    AssertionError: wrong hash length

    >>> PBKDF2SHA1Hasher(iterations=1000, length=32).must_update(encoded=hash)
    False
    >>> PBKDF2SHA1Hasher(iterations=10000, length=32).must_update(encoded=hash)
    True
    >>> PBKDF2SHA1Hasher(iterations=1000, length=24).must_update(encoded=hash)
    True

    Used in secure_js_login.js to check the PBKDF2 JavaScript implementation:
    >>> test_string=" 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    >>> PBKDF2SHA1Hasher(iterations=5, length=16).get_hash(password=test_string, salt=test_string)
    '4460365dc7df037dbdd851f1ffed7130'
    """
    def __init__(self, iterations, length):
        self.iterations = iterations
        self.length = length

    def encode(self, password, salt, iterations=None):
        assert password is not None, "password is None"
        assert salt and '$' not in salt, "salt contains &"
        if iterations is not None:
            assert iterations==self.iterations, "wrong iterations"

        hash = hexlify_pbkdf2(password, salt, iterations=self.iterations, length=self.length, digest=self.digest)
        # log.debug("locals():\n%s", pprint.pformat(locals()))
        return "%s$%d$%s$%s" % (self.algorithm, self.iterations, salt, hash)

    def get_hash(self, password, salt):
        return self.encode(password, salt).rsplit("$",1)[1]

    def get_salt_hash(self, txt):
        salt=seed_generator(length=app_settings.PBKDF2_SALT_LENGTH)
        return self.encode(txt, salt)

    def verify(self, password, encoded):
        try:
            algorithm, iterations, salt, hash = encoded.split('$', 3)
        except ValueError as err:
            raise CryptError("Encoded split error: %s" % err)

        if algorithm != self.algorithm:
            raise CryptError("wrong algorithm")

        if len(hash)/2 != self.length:
            raise CryptError("wrong hash length")

        encoded_2 = self.encode(password, salt, int(iterations))
        return crypto.constant_time_compare(encoded, encoded_2)

    def must_update(self, encoded):
        algorithm, iterations, salt, hash = encoded.split('$', 3)
        if int(iterations) != self.iterations:
            return True
        if len(hash)/2 != self.length:
            return True
        return False


class PBKDF2SHA1Hasher1(PBKDF2SHA1Hasher):
    """
    Use ITERATIONS1

    >>> seed_generator.DEBUG=True # Generate always the same seed for tests
    >>> app_settings.ITERATIONS1=10
    >>> pbkdf2 = PBKDF2SHA1Hasher1().get_salt_hash("not secret")
    >>> pbkdf2
    'pbkdf2_sha1$10$DEBUG_789012$7a4c36dc97dcea39842f80e6034b431e0235cfe742f819362db794d385368268'
    """
    def __init__(self):
        self.iterations = app_settings.ITERATIONS1
        self.length = app_settings.PBKDF2_BYTE_LENGTH

class PBKDF2SHA1Hasher2(PBKDF2SHA1Hasher):
    """
    Use ITERATIONS2

    >>> seed_generator.DEBUG=True # Generate always the same seed for tests
    >>> app_settings.ITERATIONS2=15
    >>> pbkdf2 = PBKDF2SHA1Hasher2().get_salt_hash("not secret")
    >>> pbkdf2
    'pbkdf2_sha1$15$DEBUG_789012$b232825d8a4aa84cbac0bbb2186fe08eb374e77d6d6a78061368fd59cdc7e35f'
    """
    def __init__(self):
        self.iterations = app_settings.ITERATIONS2
        self.length = app_settings.PBKDF2_BYTE_LENGTH


class CryptLengthError(AssertionError):
    pass


class XorCryptor(object):
    """
    XOR ciphering

    TODO: Use hex instead of base64 to get always the same length

    >>> seed_generator.DEBUG=True # Generate always the same seed for tests
    >>> app_settings.ITERATIONS1=10
    >>> xor = XorCryptor()

    >>> encrypted = xor.encrypt("1234", "ABCD")
    >>> encrypted
    'pbkdf2_sha1$10$DEBUG_789012$77adb6b9ffb2cc958747997da971a2930cadc60ba0fceb2cc9d8b0f0cfed058e$cHBwcA=='

    >>> xor.decrypt(encrypted, "ABCD")
    '1234'

    >>> xor.decrypt(encrypted, "AXXD")
    Traceback (most recent call last):
    ...
    CryptError: PBKDF2 hash test failed

    >>> wrong = encrypted.replace("971a29", "XXXXXX")
    >>> xor.decrypt(wrong, "ABCD")
    Traceback (most recent call last):
    ...
    CryptError: PBKDF2 hash test failed

    >>> xor.decrypt(encrypted, "wrong pass")
    Traceback (most recent call last):
    ...
    CryptError: encrypt error: b'pppp' and 'wrong pass' must have the same length!

    >>> wrong = encrypted.replace("cA==", "XXXXXX")
    >>> xor.decrypt(wrong, "ABCD")
    Traceback (most recent call last):
    ...
    CryptError: b64decode error: Incorrect padding with data: 'cHBwXXXXXX'
    """
    def xor(self, txt, key):
        """
        >>> XorCryptor().xor(b"1234", b"ABCD")
        b'pppp'
        >>> XorCryptor().xor(b'pppp', b"ABCD")
        b'1234'
        """
        assert isinstance(txt, six.binary_type), "txt: %s is not binary type!" % repr(txt)
        assert isinstance(key, six.binary_type), "key: %s is not binary type!" % repr(key)

        if len(txt) != len(key):
            raise CryptLengthError("XOR cipher error: %r and %r must have the same length!" % (txt, key))

        if six.PY2:
            crypted = "".join([chr(ord(t) ^ ord(k)) for t, k in zip(txt, key)])
        else:
            crypted = [(t ^ k) for t, k in zip(txt, key)]
            crypted = bytes(crypted)
        # log.debug("xor(txt=%r, key=%r): %r", txt, key, crypted)
        return crypted

    def encrypt(self, txt, key):
        """
        XOR ciphering with a PBKDF2 checksum
        """
        # log.debug("encrypt(txt=%r, key=%r)", txt, key)
        assert isinstance(txt, six.text_type), "txt: %s is not text type!" % repr(txt)
        assert isinstance(key, six.text_type), "key: %s is not text type!" % repr(key)

        if len(txt) != len(key):
            raise CryptLengthError("encrypt error: %r and %r must have the same length!" % (txt, key))

        pbkdf2_hash = PBKDF2SHA1Hasher1().get_salt_hash(txt)

        txt=force_bytes(txt)
        key=force_bytes(key)
        crypted = self.xor(txt, key)
        crypted = binascii.hexlify(crypted)
        crypted = six.text_type(crypted, "ascii")
        return "%s$%s" % (pbkdf2_hash, crypted)


    def decrypt(self, txt, key):
        """
        1. Decrypt a XOR crypted String.
        2. Compare the inserted SHA salt-hash checksum.
        """
        # log.debug("decrypt(txt=%r, key=%r)", txt, key)
        assert isinstance(txt, six.text_type), "txt: %s is not text type!" % repr(txt)
        assert isinstance(key, six.text_type), "key: %s is not text type!" % repr(key)

        pbkdf2_hash, crypted = txt.rsplit("$",1)

        # if not seed_generator.DEBUG and len(pbkdf2_hash)!=SALT_HASH_LEN:
        #     raise CryptLengthError(
        #         "encrypt error: Salt-hash %s with length %i must be length %i!" % (
        #             repr(pbkdf2_hash), len(pbkdf2_hash), SALT_HASH_LEN
        #         )
        #     )

        try:
            crypted = binascii.unhexlify(crypted)
        except (binascii.Error, TypeError) as err:
            # Py2 will raise TypeError - Py3 the binascii.Error
            raise CryptError("unhexlify error: %s with data: %s" % (err, repr(crypted)))

        if len(crypted) != len(key):
            raise CryptError("encrypt error: %r and %r must have the same length!" % (crypted, key))

        key=force_bytes(key)
        decrypted = self.xor(crypted, key)

        try:
            decrypted = force_text(decrypted)
        except UnicodeDecodeError:
            raise CryptError("Can't decode data.")

        test = PBKDF2SHA1Hasher1().verify(decrypted, pbkdf2_hash)
        if not test:
            raise CryptError("XOR decrypted data: PBKDF2 hash test failed")

        return decrypted

xor_crypt=XorCryptor()


def salt_hash_from_plaintext(password):
    """
    Create a XOR encrypted PBKDF2 salted checksum from a plaintext password.

    >>> seed_generator.DEBUG=True # Generate always the same seed for tests
    >>> app_settings.ITERATIONS1=10

    >>> salt, data = salt_hash_from_plaintext("test")
    >>> salt
    'DEBUG_789012'
    >>> data
    'pbkdf2_sha1$10$DEBUG_789012$9345c4d9ebcdae15931fefc11199022da569673b81d54d768ec449b14c3d5f1c$CQVQBlNbAAAAVQhaBwtQBABRV1UBA1AIU10GUlQLUVU='
    """
    init_pbkdf2_salt = seed_generator(app_settings.PBKDF2_SALT_LENGTH)
    pbkdf2_temp_hash = hexlify_pbkdf2(
        password,
        salt=init_pbkdf2_salt,
        iterations=app_settings.ITERATIONS1,
        length=app_settings.PBKDF2_BYTE_LENGTH
    )

    first_pbkdf2_part = pbkdf2_temp_hash[:PBKDF2_HALF_HEX_LENGTH]
    second_pbkdf2_part = pbkdf2_temp_hash[PBKDF2_HALF_HEX_LENGTH:]

    encrypted_part = xor_crypt.encrypt(first_pbkdf2_part, key=second_pbkdf2_part)

    # log.debug("locals():\n%s", pprint.pformat(locals()))
    return init_pbkdf2_salt, encrypted_part


def _simulate_client(plaintext_password, init_pbkdf2_salt, cnonce, server_challenge):
    """
    A implementation of the JavaScript client part.
    Needful for finding bugs.
    """
    # log.debug("_simulate_client(plaintext_password=%r, init_pbkdf2_salt=%r, cnonce=%r, server_challenge=%r)",
    #     plaintext_password, init_pbkdf2_salt, cnonce, server_challenge
    # )
    pbkdf2_temp_hash = hexlify_pbkdf2(
        plaintext_password,
        salt=init_pbkdf2_salt,
        iterations=app_settings.ITERATIONS1,
        length=app_settings.PBKDF2_BYTE_LENGTH
    )
    first_pbkdf2_part = pbkdf2_temp_hash[:PBKDF2_HALF_HEX_LENGTH]
    second_pbkdf2_part = pbkdf2_temp_hash[PBKDF2_HALF_HEX_LENGTH:]

    second_pbkdf2_salt = cnonce + server_challenge
    pbkdf2_hash = hexlify_pbkdf2(
        first_pbkdf2_part,
        salt=second_pbkdf2_salt,
        iterations=app_settings.ITERATIONS2,
        length=app_settings.PBKDF2_BYTE_LENGTH
    )
    # log.debug("_simulate_client() locals():\n%s", pprint.pformat(locals()))
    return pbkdf2_hash, second_pbkdf2_part


# PBKDF2_BYTE_LENGTH*2 + "$" + PBKDF2_BYTE_LENGTH + "$" + CLIENT_NONCE_LENGTH
# or:
# PBKDF2_HEX_LENGTH + "$" + PBKDF2_HALF_HEX_LENGTH + "$" + CLIENT_NONCE_LENGTH
CLIENT_DATA_LEN = PBKDF2_HEX_LENGTH + PBKDF2_HALF_HEX_LENGTH + app_settings.CLIENT_NONCE_LENGTH + 2


class HashValidator(object):
    def __init__(self, name, length):
        self.name = name
        self.length = length
        self.regexp = re.compile(r"^[a-f0-9]{%i}$" % length)

    def validate(self, value):
        if len(value)!=self.length:
            raise ValueError("%s length error" % self.name)

        if not self.regexp.match(value):
            raise ValueError("%s regexp error" % self.name)

PBKDF2_HASH_Validator = HashValidator(name="pbkdf2_hash", length=PBKDF2_HEX_LENGTH)
SECOND_PBKDF2_PART_Validator = HashValidator(name="second_pbkdf2_part", length=PBKDF2_HALF_HEX_LENGTH)
CLIENT_NONCE_HEX_Validator = HashValidator(name="cnonce", length=app_settings.CLIENT_NONCE_LENGTH)


from django.core.cache import get_cache

class AppCache(object):
    KEY_PREFIX="secure-js-login"
    def __init__(self, backend, key_suffix, timeout):
        self.cache = get_cache(backend)
        self.key_prefix = "%s_%s_" % (self.KEY_PREFIX, key_suffix)
        self.timeout = timeout

    def exists_or_add(self, key):
        if self.cache.get(self.key_prefix + key) is None:
            self.cache.set(self.key_prefix + key, True, self.timeout)
            return False
        return True


cnonce_cache = AppCache(
    app_settings.CACHE_NAME, "cnonce",
    timeout=None # cache forever
)

def split_secure_password(secure_password):
    if secure_password.count("$") != 2:
        raise ValueError(
            "No two $ (found: %i) in password found in: %r" % (
                secure_password.count("$"), secure_password
            )
        )

    pbkdf2_hash, second_pbkdf2_part, cnonce = secure_password.split("$")

    CLIENT_NONCE_HEX_Validator.validate(cnonce)

    if cnonce_cache.exists_or_add(cnonce):
        raise ValueError("cnonce %r was used in the past!" % cnonce)

    PBKDF2_HASH_Validator.validate(pbkdf2_hash)
    SECOND_PBKDF2_PART_Validator.validate(second_pbkdf2_part)

    return (pbkdf2_hash, second_pbkdf2_part, cnonce)


def check_secure_js_login(secure_password, encrypted_part, server_challenge):
    """
    first_pbkdf2_part = xor_decrypt(encrypted_part, key=second_pbkdf2_part)
    test_hash = pbkdf2(first_pbkdf2_part, key=cnonce + server_challenge)
    compare test_hash with transmitted pbkdf2_hash
    """
    # log.debug("check_secure_js_login(secure_password=%r, encrypted_part=%r, server_challenge=%r)",
    #     secure_password, encrypted_part, server_challenge
    # )

    try:
        pbkdf2_hash, second_pbkdf2_part, cnonce = split_secure_password(secure_password)
    except ValueError as err:
        # log.error(err)
        return

    # log.debug("split_secure_password(): pbkdf2_hash=%r, second_pbkdf2_part=%r, cnonce=%r",
    #     pbkdf2_hash, second_pbkdf2_part, cnonce
    # )

    try:
        first_pbkdf2_part = xor_crypt.decrypt(encrypted_part, key=second_pbkdf2_part)
    except CryptError:
        return

    test_hash = hexlify_pbkdf2(
        first_pbkdf2_part,
        cnonce + server_challenge,
        iterations=app_settings.ITERATIONS2,
        length=app_settings.PBKDF2_BYTE_LENGTH
    )
    # log.debug("check_secure_js_login() locals():\n%s", pprint.pformat(locals()))
    return crypto.constant_time_compare(test_hash, pbkdf2_hash)


if __name__ == "__main__":
    # print(crypt(b"1234", b"ABCD"))

    import doctest
    print(doctest.testmod(
        verbose=False
    ))
