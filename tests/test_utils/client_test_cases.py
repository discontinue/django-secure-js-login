# coding: utf-8

"""
    Secure JavaScript Login
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyleft: 2012-2015 by the secure-js-login team, see AUTHORS for more details.
    :created: by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from __future__ import unicode_literals, print_function

from django.conf import settings
from django.utils import six
from django.utils.crypto import get_random_string

from secure_js_login import settings as app_settings
from secure_js_login.utils import crypt

from tests.test_utils.base_test_cases import SecureLoginBaseTestCase


class SecureLoginClientBaseTestCase(SecureLoginBaseTestCase):
    def _reset_secure_data(self):
        self.username = None
        self.plaintext_password = None
        self.server_challenge = None
        self.init_pbkdf2_salt = None
        self.cnonce = None
        self.secure_password = None

    def setUp(self):
        super(SecureLoginClientBaseTestCase, self).setUp()
        self._reset_secure_data()

    def _request_server_challenge(self):
        response = self.client.get(self.secure_login_url)
        csrf_cookie = response.cookies[settings.CSRF_COOKIE_NAME]
        # debug_response(response)
        self.server_challenge = response.context["challenge"]
        self.assertContains(response, 'challenge="%s";' % self.server_challenge)
        return self.server_challenge

    def _request_init_pbkdf2_salt(self):
        if self.server_challenge is None:
            self._request_server_challenge()

        if self.username is None:
            self.username = self.SUPER_USER_NAME

        response = self.client.post(
            self.get_salt_url,
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
            # HTTP_X_CSRFTOKEN=csrf_token,
            data={"username": self.username}
        )
        self.init_pbkdf2_salt = six.text_type(response.content, "ascii")
        return self.init_pbkdf2_salt

    def _get_cnonce(self):
        self.cnonce = get_random_string(
            length=app_settings.CLIENT_NONCE_LENGTH,
            allowed_chars="1234567890abcdef" # cnonce must a "valid" hex value
        )
        return self.cnonce

    def _calc_secure_password(self):
        if self.plaintext_password is None:
            self.plaintext_password = self.SUPER_USER_PASS

        if self.server_challenge is None:
            self._request_server_challenge()

        if self.init_pbkdf2_salt is None:
            self._request_init_pbkdf2_salt()

        if self.cnonce is None:
            self._get_cnonce()

        self.pbkdf2_hash, self.second_pbkdf2_part = crypt._simulate_client(
            plaintext_password=self.plaintext_password,
            init_pbkdf2_salt=self.init_pbkdf2_salt,
            cnonce=self.cnonce,
            server_challenge=self.server_challenge
        )
        self.secure_password = "$".join([self.pbkdf2_hash, self.second_pbkdf2_part, self.cnonce])
        return self.secure_password

    def _secure_login(self):
        if self.secure_password is None:
            self._calc_secure_password()

        response = self.client.post(self.secure_login_url,
            follow=True, # Redirect after successfully login
            data = {
                "username": self.username,
                "password": self.secure_password,
            }
        )
        return response