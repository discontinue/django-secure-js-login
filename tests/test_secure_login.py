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
        return init_pbkdf2_salt

    def _get_cnonce(self):
        return get_random_string(
            length=app_settings.CLIENT_NONCE_LENGTH,
            allowed_chars="1234567890abcdef" # cnonce must a "valid" hex value
        )

    def _calc_secure_password(self, server_challenge, cnonce, init_pbkdf2_salt, plaintext_password):
        pbkdf2_hash, second_pbkdf2_part = crypt._simulate_client(
            plaintext_password=plaintext_password,
            init_pbkdf2_salt=init_pbkdf2_salt,
            cnonce=cnonce,
            server_challenge=server_challenge
        )
        return "$".join([pbkdf2_hash, second_pbkdf2_part, cnonce])

    def _secure_login(self,
                      secure_password = None,
                      username=None, plaintext_password=None,
                      server_challenge=None, init_pbkdf2_salt=None, cnonce=None):
        if username is None:
            username = self.SUPER_USER_NAME

        if secure_password is None:
            if plaintext_password is None:
                plaintext_password = self.SUPER_USER_PASS
            if server_challenge is None:
                server_challenge = self._request_server_challenge()
            if init_pbkdf2_salt is None:
                init_pbkdf2_salt = self._request_init_pbkdf2_salt(username)
            if cnonce is None:
                cnonce = self._get_cnonce()

            secure_password = self._calc_secure_password(
                server_challenge, cnonce, init_pbkdf2_salt, plaintext_password
            )

        response = self.client.post(self.secure_login_url,
            follow=True, # Redirect after successfully login
            data = {
                'username': username,
                "password": secure_password,
            }
        )
        response._unittest_cnonce = cnonce
        response._unittest_salt = init_pbkdf2_salt
        response._unittest_challenge = server_challenge
        response._unittest_secure_password = secure_password
        return response

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

    def test_login(self):
        response = self._secure_login()
        # debug_response(response)
        self.assertSecureLoginSuccess(response)

    def test_wrong_username(self):
        """
        Request with a wrong username
        use a valid secure-pass, so that the password validation will not raised an error.
        """
        response = self._secure_login(username="doesnt_exist")
        # debug_response(response)
        self.assertContains(response, "Please enter a correct username and password.")

    def test_not_active_user(self):
        self.superuser.is_active = False
        self.superuser.save()

        response = self._secure_login()
        self.assertContains(response, "Please enter a correct username and password.")

        # We should get a "pseudo" salt value
        self.assertNotEqual(response._unittest_salt, self.superuser_profile.init_pbkdf2_salt)

        # however: try to login a inactive user with the right salt
        response = self._secure_login(init_pbkdf2_salt=self.superuser_profile.init_pbkdf2_salt)
        # debug_response(response)
        self.assertContains(response, "Please enter a correct username and password.")

    def test_use_same_cnonce(self):
        cnonce = self._get_cnonce()
        response = self._secure_login(cnonce=cnonce)
        # debug_response(response)
        self.assertSecureLoginSuccess(response)

        self.client.logout()

        # Try to login with the same cnonce again:
        response = self._secure_login(cnonce=cnonce)
        # debug_response(response)
        self.assertSecureLoginFailed(response)

    def test_use_same_challenge(self):
        response = self._secure_login()
        # debug_response(response)
        self.assertSecureLoginSuccess(response)

        old_challenge = response._unittest_challenge

        self.client.logout()

        # Try to login with the same cnonce again:
        response = self._secure_login(server_challenge=old_challenge)
        # debug_response(response)
        self.assertSecureLoginFailed(response)

    def test_use_same_secure_password(self):
        response = self._secure_login()
        # debug_response(response)
        self.assertSecureLoginSuccess(response)

        old_secure_password = response._unittest_secure_password

        self.client.logout()

        # Try to login with the same cnonce again:
        response = self._secure_login(secure_password=old_secure_password)
        # debug_response(response)
        self.assertSecureLoginFailed(response)