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

from django.conf import settings
from django.utils import six
from django.utils.crypto import get_random_string
from secure_js_login.utils import crypt


from secure_js_login import settings as app_settings
from tests.test_utils.test_cases import SecureLoginBaseTestCase, debug_response


class TestSecureLogin(SecureLoginBaseTestCase):
    """
    Tests with django test client
    """
    def _request_server_challenge(self):
        response = self.client.get(self.secure_login_url)
        csrf_cookie = response.cookies[settings.CSRF_COOKIE_NAME]
        # debug_response(response)
        server_challenge = response.context["challenge"]
        self.assertContains(response, 'challenge="%s";' % server_challenge)
        return server_challenge

    def _request_init_pbkdf2_salt(self, username):
        response = self.client.post(
            self.get_salt_url,
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
            # HTTP_X_CSRFTOKEN=csrf_token,
            data={"username": username}
        )
        init_pbkdf2_salt = six.text_type(response.content, "ascii")
        self.assertEqual(init_pbkdf2_salt, self.superuser_profile.init_pbkdf2_salt)
        return init_pbkdf2_salt

    def _calc_secure_password(self, server_challenge, init_pbkdf2_salt, plaintext_password):
        # cnonce must a "valid" hex value
        cnonce = get_random_string(
            length=app_settings.CLIENT_NONCE_LENGTH,
            allowed_chars="1234567890abcdef"
        )
        pbkdf2_hash, second_pbkdf2_part = crypt._simulate_client(
            plaintext_password=plaintext_password,
            init_pbkdf2_salt=init_pbkdf2_salt,
            cnonce=cnonce,
            server_challenge=server_challenge
        )
        return "$".join([pbkdf2_hash, second_pbkdf2_part, cnonce])

    def _get_secure_password(self, username, plaintext_password):
        server_challenge = self._request_server_challenge()
        init_pbkdf2_salt = self._request_init_pbkdf2_salt(username)

        return self._calc_secure_password(server_challenge, init_pbkdf2_salt, plaintext_password)

    def test_login_page(self):
        response = self.client.get(self.secure_login_url)
        # debug_response(response)
        self.assertContains(response, '<label for="id_username" class="required">Username:</label>', html=True)
        self.assertContains(response, '<label for="id_password" class="required">Password:</label>', html=True)

    def test_post_empty_form(self):
        response = self.client.post(self.secure_login_url, {}, follow=True)
        # debug_response(response)
        self.assertFormError(response, 'form', 'username', 'This field is required.')
        self.assertFormError(response, 'form', 'password', 'This field is required.')

    def test_wrong_username(self):
        """
        Request with a wrong username
        use a valid secure-pass, so that the password validation will not raised an error.
        """
        secure_password = self._get_secure_password(self.SUPER_USER_NAME, self.SUPER_USER_PASS)

        response = self.client.post(self.secure_login_url,
            follow=True, # Redirect after successfully login
            data = {
                'username': 'doesnt_exist',
                "password": secure_password,
            }
        )
        # debug_response(response)
        # XXX: Why here: %(username)s ?!?
        self.assertContains(response, "Please enter a correct %(username)s and password.")

    def test_login(self):
        secure_password = self._get_secure_password(self.SUPER_USER_NAME, self.SUPER_USER_PASS)

        response = self.client.post(self.secure_login_url,
            follow=True, # Redirect after successfully login
            data={
                "username": self.SUPER_USER_NAME,
                "password": secure_password,
            }
        )
        # debug_response(response)
        self.assertSecureLoginSuccess(response.content.decode("utf-8"))
