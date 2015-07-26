# coding: utf-8

"""
    Secure JavaScript Login
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyleft: 2007-2015 by the secure-js-login team, see AUTHORS for more details.
    :created: by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from __future__ import unicode_literals, print_function

from django.contrib.auth import SESSION_KEY

from secure_js_login.honypot.models import HonypotAuth
from secure_js_login.views import SERVER_CHALLENGE_KEY
from tests.test_utils.base_test_cases import SecureLoginBaseTestCase


class TestHoneypot(SecureLoginBaseTestCase):
    """
    Tests with django test client
    """
    def _login(self, username, plaintext_password):
        return self.client.post(self.honypot_url,
            data={
                'username': username,
                "password": plaintext_password,
            },
        )

    def test_not_existing_user(self):
        response = self._login(username="foo", plaintext_password="bar")
        self.assertLoginFailed(response)

        entry = HonypotAuth.objects.all()[0]
        self.assertEqual(entry.username.username, "foo")
        self.assertEqual(entry.password.password, "bar")
        self.assertEqual(entry.username.count, 1)
        self.assertEqual(entry.password.count, 1)
        self.assertEqual(entry.count, 1)

    def test_existing_user(self):
        response = self._login(username=self.SUPER_USER_NAME, plaintext_password=self.SUPER_USER_PASS)
        self.assertLoginFailed(response)

        entry = HonypotAuth.objects.all()[0]
        self.assertEqual(entry.username.username, self.SUPER_USER_NAME)
        self.assertEqual(entry.password.password, "***") # Mask only for existing users
        self.assertEqual(entry.count, 1)
        self.assertEqual(entry.username.count, 1)
        self.assertEqual(entry.password.count, 1)

    def assertLoginFailed(self, response):
        errornote = (
            '<p class="errornote">'
            'Please enter a correct username and password.'
            ' Note that both fields may be case-sensitive.'
            '</p>'
        )
        try:
            # Client is not logged in:
            self.assertNotIn(SESSION_KEY, self.client.session)

            # secure-js-login challenge
            self.assertNotIn(SERVER_CHALLENGE_KEY, self.client.session)

            self.assertNotContains(response,"You are logged in.", status_code=401, html=False)
            self.assertNotContains(response,"Last login was:", status_code=401, html=False)
            self.assertNotContains(response,"Log out", status_code=401, html=False)

            self.assertContains(response, errornote, status_code=401, html=True)

            self.assertNotContains(response, "Traceback", status_code=401, html=False)
        except AssertionError as err:
            self._verbose_assertion_error(response)