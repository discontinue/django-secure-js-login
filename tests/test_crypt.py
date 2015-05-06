# coding: utf-8

"""
    Secure JavaScript Login
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyleft: 2007-2015 by the secure-js-login team, see AUTHORS for more details.
    :created: by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from __future__ import unicode_literals

import unittest

from secure_js_login.utils import crypt
from secure_js_login.utils.crypt import CryptError


class TestCrypt(unittest.TestCase):
    """
    Low-level tests without models/views etc.
    """
    def __init__(self, *args, **kwargs):
        super(TestCrypt, self).__init__(*args, **kwargs)
        self.test_string = "foo"
        self.test_key = "bar"
        crypt.seed_generator.DEBUG=True # Generate always the same seed for tests
        self.test_encrypted = crypt.xor_crypt.encrypt(self.test_string, key=self.test_key)
        crypt.seed_generator.DEBUG=False # Generate always the same seed for tests
        # self.assertEqual(self.test_encrypted,
        #     "pbkdf2_sha1$5$DEBUG$3104bd93d8$040e1d"
        # )


    def test_pbkdf2(self):
        self.assertEqual(
            crypt.hexlify_pbkdf2(password="not secret", salt="a salt value", iterations=10, length=16),
            "95b44f630c54591e8948256bd2529476"
        )

    def test_xor_crypt(self):
        crypted = crypt.xor_crypt.encrypt("foo", key="bar")
        decrypted = crypt.xor_crypt.decrypt(crypted, key="bar")
        self.assertEqual(decrypted, "foo")

    def test_wrong_key_size(self):
        # too long
        with self.assertRaises(CryptError) as err:
            crypt.xor_crypt.decrypt(self.test_encrypted, key="barr")
        self.assertIn("must have the same length!", err.exception.args[0])

        # to short
        with self.assertRaises(CryptError) as err:
            crypt.xor_crypt.decrypt(self.test_encrypted, key="ba")
        self.assertIn("must have the same length!", err.exception.args[0])

    def test_wrong_key(self):
        with self.assertRaises(CryptError) as err:
            crypt.xor_crypt.decrypt(self.test_encrypted, key="bXr")
        self.assertEqual("PBKDF2 hash test failed", err.exception.args[0])

    # e.g.: pbkdf2_sha1$100$DEBUG_789012$fb855b6c514ad76b5c0f99910f0a8bc5f1199f2555befd8ae016c4701dc7901b$BA4d

    def test_wrong_algorithm(self):
        data = self.test_encrypted
        data = data.replace("pbkdf2_sha1$", "pbkdf2_sha256$")
        with self.assertRaises(CryptError) as err:
            crypt.xor_crypt.decrypt(data, key="bar")
        self.assertEqual("wrong algorithm", err.exception.args[0])

    def test_wrong_salt(self):
        data = self.test_encrypted
        data = data[:14] + "X" + data[15:] # Replace one character in hash value
        with self.assertRaises(CryptError) as err:
            crypt.xor_crypt.decrypt(data, key="bar")
        self.assertEqual("PBKDF2 hash test failed", err.exception.args[0])

    def test_wrong_hash(self):
        data = self.test_encrypted
        data = data[:25] + "X" + data[26:] # Replace one character in hash value
        with self.assertRaises(CryptError) as err:
            crypt.xor_crypt.decrypt(data, key="bar")
        self.assertEqual("PBKDF2 hash test failed", err.exception.args[0])

    def test_wrong_data1(self):
        data = self.test_encrypted
        data += "X"
        with self.assertRaises(CryptError) as err:
            crypt.xor_crypt.decrypt(data, key="bar")
        self.assertEqual("unhexlify error: Odd-length string with data: '040e1dX'", err.exception.args[0])

    def test_wrong_data2(self):
        data = self.test_encrypted
        data = data[:-1] + "X"
        with self.assertRaises(CryptError) as err:
            crypt.xor_crypt.decrypt(data, key="bar")
        self.assertEqual("unhexlify error: Non-hexadecimal digit found with data: '040e1X'", err.exception.args[0])

    def test_wrong_data3(self):
        # data is a valid "hexlify" string, but the hash compare will failed
        data = self.test_encrypted
        data = data[:-1] + "f"
        with self.assertRaises(CryptError) as err:
            crypt.xor_crypt.decrypt(data, key="bar")
        self.assertEqual("PBKDF2 hash test failed", err.exception.args[0])

    def test_random_seeds(self):
        hasher = crypt.PBKDF2SHA1Hasher(iterations=1, length=8)
        salts = {}
        hashes = {}
        for _ in range(10):
            h = hasher.get_salt_hash("foobar")
            algorithm, iterations, salt, hash = h.split("$")
            self.assertNotIn(salt, salts)
            salts[salt] = None
            self.assertNotIn(hash, hashes)
            hashes[hash] = None