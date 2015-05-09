# coding: utf-8

"""
    Secure JavaScript Login
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyleft: 2007-2015 by the secure-js-login team, see AUTHORS for more details.
    :created: by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from __future__ import unicode_literals

# set: DJANGO_SETTINGS_MODULE:tests.test_utils.test_settings to run the tests

from secure_js_login.honypot.models import HonypotAuth
from tests.test_utils.test_cases import SecureLoginBaseTestCase


class TestHoneypot(SecureLoginBaseTestCase):
    """
    Tests with django test client
    """
    def _login(self, username, plaintext_password):
        return self.client.post(self.honypot_url,
            data={
                'username': username,
                "password": plaintext_password,
            }
        )

    def test_not_existing_user(self):
        response = self._login(username="foo", plaintext_password="bar")
        self.assertSecureLoginFailed(response)

        entry = HonypotAuth.objects.all()[0]
        self.assertEqual(entry.username.username, "foo")
        self.assertEqual(entry.password.password, "bar")
        self.assertEqual(entry.username.count, 1)
        self.assertEqual(entry.password.count, 1)
        self.assertEqual(entry.count, 1)

    def test_existing_user(self):
        response = self._login(username=self.SUPER_USER_NAME, plaintext_password=self.SUPER_USER_PASS)
        self.assertSecureLoginFailed(response)

        entry = HonypotAuth.objects.all()[0]
        self.assertEqual(entry.username.username, self.SUPER_USER_NAME)
        self.assertEqual(entry.password.password, "***") # Mask only for existing users
        self.assertEqual(entry.count, 1)
        self.assertEqual(entry.username.count, 1)
        self.assertEqual(entry.password.count, 1)
