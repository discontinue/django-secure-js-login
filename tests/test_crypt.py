
import unittest

from secure_js_login.utils import crypt


# class TestCrypt(unittest.TestCase):
#     """
#     Low-level tests without models/views etc.
#     """
#     # def setUp(self):
#     #     crypt.seed_generator.DEBUG=True
#     #
#     # def tearDown(self):
#     #     crypt.seed_generator.DEBUG=False
#
#     def test_pbkdf2(self):
#         """
#         Also tested these pbkdf2 values in pbkdf2_test.html !
#
#         """
#         hash = crypt.pbkdf2(password="not secret", salt="a salt value", iterations=1000, length=32)
#         self.assertEqual(hash, '9bbc7565baa47ce8e9f5ef181ea2a8959bec965d2ab09b7671e6b1920c67685f')
#
#     def test_encrypt(self):
#         crypt.seed_generator.DEBUG=True # Generate always the same seed for tests
#         self.assertEqual(
#             crypt.xor_encrypt(txt="foo", key="bar"),
#             'sha1$DEBUG_123456$197987f5ca3fd97da45acac3541e3464198a1cee$BA4d'
#         )
#
#     def test_decrypted(self):
#         crypt.seed_generator.DEBUG=True # Generate always the same seed for tests
#         self.assertEqual(
#             crypt.xor_decrypt('sha1$DEBUG_123456$197987f5ca3fd97da45acac3541e3464198a1cee$BA4d', key="bar"),
#             'foo'
#         )
#
#     def test_decrypt_wrong_key(self):
#         self.assertRaises(crypt.CryptError,
#             crypt.xor_decrypt,
#             'sha1$DEBUG_123456$197987f5ca3fd97da45acac3541e3464198a1cee$BA4d',
#             key="bXr"
#         )
#
#     def test_decrypt_wrong_salt(self):
#         self.assertRaises(crypt.CryptError,
#             crypt.xor_decrypt,
#             'sha1$DEBUG_12XX56$197987f5ca3fd97da45acac3541e3464198a1cee$BA4d',
#             key="bar"
#         )
#
#     def test_decrypt_wrong_hash(self):
#         self.assertRaises(crypt.CryptError,
#             crypt.xor_decrypt,
#             'sha1$DEBUG_123456$197987f5ca3fd97da45aXXc3541e3464198a1cee$BA4d',
#             key="bar"
#         )
#
#     def test_decrypt_wrong_data(self):
#         self.assertRaises(crypt.CryptError,
#             crypt.xor_decrypt,
#             'sha1$DEBUG_123456$197987f5ca3fd97da45acac3541e3464198a1cee$BAXd',
#             key="bar"
#         )