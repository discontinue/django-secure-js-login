# coding: utf-8

"""
    Secure JavaScript Login
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyleft: 2007-2015 by the secure-js-login team, see AUTHORS for more details.
    :created: by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from __future__ import unicode_literals

import hashlib
import logging
import re
import binascii

from django.utils import six, crypto
from django.utils.encoding import force_bytes, force_text
from django.contrib.auth.hashers import PBKDF2SHA1PasswordHasher

from secure_js_login.utils.cache import AppCache
from secure_js_login import settings as app_settings
from secure_js_login.exceptions import SecureJSLoginError


log = logging.getLogger("secure_js_login")


cnonce_cache = AppCache(
    app_settings.CACHE_NAME, "cnonce",
    timeout=None # cache forever
)


PBKDF2_HEX_LENGTH = int(app_settings.PBKDF2_BYTE_LENGTH * 2)
PBKDF2_HALF_HEX_LENGTH = int(PBKDF2_HEX_LENGTH / 2)

assert PBKDF2_HALF_HEX_LENGTH == app_settings.PBKDF2_BYTE_LENGTH



def hash_hexdigest(txt):
    assert isinstance(txt, six.text_type), "txt: %s is not text type!" % repr(txt)
    return hashlib.sha512(force_bytes(txt)).hexdigest()


class SeedGenerator(object):
    """
    Generate a new, random seed values.

    >>> seed_generator.DEBUG=True # Generate always the same seed for tests
    >>> seed_generator(20) == 'DEBUG_78901234567890'
    True
    >>> seed_generator(12) == 'DEBUG_789012'
    True

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
            log.critical("DEBUG seed with length: %i used!", length)
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
    >>> hash = hexlify_pbkdf2("not secret", "a salt value", iterations=100, length=16)
    >>> hash == '0b919231515dde16f76364666cf07107'
    True
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
    >>> hash == 'pbkdf2_sha1$1000$a salt value$9bbc7565baa47ce8e9f5ef181ea2a8959bec965d2ab09b7671e6b1920c67685f'
    True

    >>> h.verify(password="not secret", encoded=hash)
    True
    >>> h.verify(password="wrong secret", encoded=hash)
    False

    >>> PBKDF2SHA1Hasher(iterations=100, length=32).verify(password="not secret", encoded=hash)
    Traceback (most recent call last):
        ...
    AssertionError: wrong iterations: 1000 != 100

    >>> try:
    ...     PBKDF2SHA1Hasher(iterations=1000, length=16).verify(password="not secret", encoded=hash)
    ... except SecureJSLoginError as err:print(err)
    wrong hash length

    >>> PBKDF2SHA1Hasher(iterations=1000, length=32).must_update(encoded=hash)
    False
    >>> PBKDF2SHA1Hasher(iterations=10000, length=32).must_update(encoded=hash)
    True
    >>> PBKDF2SHA1Hasher(iterations=1000, length=24).must_update(encoded=hash)
    True

    Used in secure_js_login.js to check the PBKDF2 JavaScript implementation:
    >>> test_string=" 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    >>> hash = PBKDF2SHA1Hasher(iterations=5, length=16).get_hash(password=test_string, salt=test_string)
    >>> hash == '4460365dc7df037dbdd851f1ffed7130'
    True
    """
    def __init__(self, iterations, length):
        self.iterations = iterations
        self.length = length

    def encode(self, password, salt, iterations=None):
        assert password is not None, "password is None"
        assert salt and '$' not in salt, "salt contains &"
        if iterations is not None:
            assert iterations==self.iterations, "wrong iterations: %i != %i" % (iterations, self.iterations)

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
            raise SecureJSLoginError("Encoded split error: %s" % err)

        if algorithm != self.algorithm:
            raise SecureJSLoginError("wrong algorithm")

        if len(hash)/2 != self.length:
            raise SecureJSLoginError("wrong hash length")

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
    >>> pbkdf2 = PBKDF2SHA1Hasher1().get_salt_hash("not secret")
    >>> pbkdf2 == 'pbkdf2_sha1$5$DEBUG$ccd1d8f3efbfc6d1a7c477f0'
    True
    """
    def __init__(self):
        super(PBKDF2SHA1Hasher1, self).__init__(
            iterations=app_settings.ITERATIONS1,
            length=app_settings.PBKDF2_BYTE_LENGTH
        )


class PBKDF2SHA1Hasher2(PBKDF2SHA1Hasher):
    """
    Use ITERATIONS2

    >>> seed_generator.DEBUG=True # Generate always the same seed for tests
    >>> pbkdf2 = PBKDF2SHA1Hasher2().get_salt_hash("not secret")
    >>> pbkdf2 == 'pbkdf2_sha1$10$DEBUG$996599c7bfe3645f1d83f424'
    True
    """

    def __init__(self):
        super(PBKDF2SHA1Hasher2, self).__init__(
            iterations=app_settings.ITERATIONS2,
            length=app_settings.PBKDF2_BYTE_LENGTH
        )


class XorCryptor(object):
    """
    XOR ciphering

    >>> seed_generator.DEBUG=True # Generate always the same seed for tests
    >>> xor = XorCryptor()

    >>> encrypted = xor.encrypt("1234", "ABCD")
    >>> encrypted == 'pbkdf2_sha1$5$DEBUG$84a05bcd7077ae3e2a0956c8$70707070'
    True

    >>> xor.decrypt(encrypted, "ABCD") == '1234'
    True
    """
    def xor(self, txt, key):
        """
        >>> crypted = XorCryptor().xor(b"1234", b"ABCD")
        >>> crypted == b'pppp'
        True
        >>> txt = XorCryptor().xor(b'pppp', b"ABCD")
        >>> txt == b'1234'
        True
        """
        assert isinstance(txt, six.binary_type), "txt: %s is not binary type!" % repr(txt)
        assert isinstance(key, six.binary_type), "key: %s is not binary type!" % repr(key)

        if len(txt) != len(key):
            raise SecureJSLoginError("XOR cipher error: '%s' and '%s' must have the same length!" % (txt, key))

        if six.PY2:
            crypted = "".join([chr(ord(t) ^ ord(k)) for t, k in zip(txt, key)])
        else:
            crypted = [(t ^ k) for t, k in zip(txt, key)]
            crypted = bytes(crypted)
        # log.debug("xor(txt='%s', key='%s'): '%s'", txt, key, crypted)
        return crypted

    def encrypt(self, txt, key):
        """
        XOR ciphering with a PBKDF2 checksum
        """
        # log.debug("encrypt(txt='%s', key='%s')", txt, key)
        assert isinstance(txt, six.text_type), "txt: %s is not text type!" % repr(txt)
        assert isinstance(key, six.text_type), "key: %s is not text type!" % repr(key)

        if len(txt) != len(key):
            raise SecureJSLoginError("encrypt error: %s and '%s' must have the same length!" % (txt, key))

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
        # log.debug("decrypt(txt='%s', key='%s')", txt, key)
        assert isinstance(txt, six.text_type), "txt: %s is not text type!" % repr(txt)
        assert isinstance(key, six.text_type), "key: %s is not text type!" % repr(key)

        pbkdf2_hash, crypted = txt.rsplit("$",1)

        # if not seed_generator.DEBUG and len(pbkdf2_hash)!=SALT_HASH_LEN:
        #     raise SecureJSLoginError(
        #         "encrypt error: Salt-hash %s with length %i must be length %i!" % (
        #             repr(pbkdf2_hash), len(pbkdf2_hash), SALT_HASH_LEN
        #         )
        #     )

        try:
            crypted = binascii.unhexlify(crypted)
        except (binascii.Error, TypeError) as err:
            # Py2 will raise TypeError - Py3 the binascii.Error
            raise SecureJSLoginError("unhexlify error: %s with data: %s" % (err, crypted))

        if len(crypted) != len(key):
            raise SecureJSLoginError("encrypt error: %s and '%s' must have the same length!" % (crypted, key))

        key=force_bytes(key)
        decrypted = self.xor(crypted, key)

        try:
            decrypted = force_text(decrypted)
        except UnicodeDecodeError:
            raise SecureJSLoginError("Can't decode data.")

        test = PBKDF2SHA1Hasher1().verify(decrypted, pbkdf2_hash)
        if not test:
            raise SecureJSLoginError("XOR decrypted data: PBKDF2 hash test failed")

        return decrypted

xor_crypt=XorCryptor()


def salt_hash_from_plaintext(password):
    """
    Create a XOR encrypted PBKDF2 salted checksum from a plaintext password.

    >>> seed_generator.DEBUG=True # Generate always the same seed for tests

    >>> salt, data = salt_hash_from_plaintext("test")
    >>> salt == 'DEBUG'
    True
    >>> data =='pbkdf2_sha1$5$DEBUG$a2220ab7dea891f260edd481$50530c0e530f030b08070353'
    True
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
    # log.debug("_simulate_client(plaintext_password='%s', init_pbkdf2_salt='%s', cnonce='%s', server_challenge='%s')",
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
            raise SecureJSLoginError("%s length error" % self.name)

        if not self.regexp.match(value):
            raise SecureJSLoginError("%s regexp error" % self.name)

PBKDF2_HASH_Validator = HashValidator(name="pbkdf2_hash", length=PBKDF2_HEX_LENGTH)
SECOND_PBKDF2_PART_Validator = HashValidator(name="second_pbkdf2_part", length=PBKDF2_HALF_HEX_LENGTH)
CLIENT_NONCE_HEX_Validator = HashValidator(name="cnonce", length=app_settings.CLIENT_NONCE_LENGTH)




def split_secure_password(secure_password):
    if secure_password.count("$") != 2:
        raise SecureJSLoginError(
            "No two '$' (found: %i) in secure_password: '%s' !" % (
                secure_password.count("$"), secure_password
            )
        )

    pbkdf2_hash, second_pbkdf2_part, cnonce = secure_password.split("$")

    CLIENT_NONCE_HEX_Validator.validate(cnonce)

    if cnonce_cache.exists_or_add(cnonce):
        raise SecureJSLoginError("cnonce '%s' was used in the past!" % cnonce)

    PBKDF2_HASH_Validator.validate(pbkdf2_hash)
    SECOND_PBKDF2_PART_Validator.validate(second_pbkdf2_part)

    return (pbkdf2_hash, second_pbkdf2_part, cnonce)


def check_secure_js_login(secure_password, encrypted_part, server_challenge):
    """
    first_pbkdf2_part = xor_decrypt(encrypted_part, key=second_pbkdf2_part)
    test_hash = pbkdf2(first_pbkdf2_part, key=cnonce + server_challenge)
    compare test_hash with transmitted pbkdf2_hash
    """
    # log.debug("check_secure_js_login(secure_password='%s', encrypted_part='%s', server_challenge='%s')",
    #     secure_password, encrypted_part, server_challenge
    # )

    pbkdf2_hash, second_pbkdf2_part, cnonce = split_secure_password(secure_password)
    # log.debug("split_secure_password(): pbkdf2_hash='%s', second_pbkdf2_part='%s', cnonce='%s'",
    #     pbkdf2_hash, second_pbkdf2_part, cnonce
    # )

    first_pbkdf2_part = xor_crypt.decrypt(encrypted_part, key=second_pbkdf2_part)

    test_hash = hexlify_pbkdf2(
        first_pbkdf2_part,
        cnonce + server_challenge,
        iterations=app_settings.ITERATIONS2,
        length=app_settings.PBKDF2_BYTE_LENGTH
    )
    # log.debug("check_secure_js_login() locals():\n%s", pprint.pformat(locals()))
    if test_hash != pbkdf2_hash:
        raise SecureJSLoginError("test_hash != pbkdf2_hash")
    # log.debug("OK: test_hash == pbkdf2_hash")
    return True


if __name__ == "__main__":
    # print(crypt(b"1234", b"ABCD"))

    import doctest
    print(doctest.testmod(
        verbose=False
    ))
