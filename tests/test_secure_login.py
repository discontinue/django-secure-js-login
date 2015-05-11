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
from django.http import HttpResponseBadRequest
from django.utils import six
from django.utils.crypto import get_random_string
from secure_js_login.utils import crypt


from secure_js_login import settings as app_settings
from secure_js_login.utils.crypt import CLIENT_DATA_LEN, HashValidator
from tests.test_utils.manipulators import secure_pass_manipulator
from tests.test_utils.test_cases import SecureLoginBaseTestCase, debug_response


class TestSecureLogin(SecureLoginBaseTestCase):
    """
    Tests with django test client
    """
    def _reset_secure_data(self):
        self.username = None
        self.plaintext_password = None
        self.server_challenge = None
        self.init_pbkdf2_salt = None
        self.cnonce = None
        self.secure_password = None

    def setUp(self):
        super(TestSecureLogin, self).setUp()
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
                'username': self.username,
                "password": self.secure_password,
            }
        )
        return response

    def test_login_page(self):
        response = self.client.get(self.secure_login_url)
        # debug_response(response)
        self.assertContains(response, '<label for="id_username" class="required">Username:</label>', html=True)
        self.assertContains(response, '<label for="id_password" class="required">Password:</label>', html=True)

    def test_post_empty_form(self):
        response = self.client.post(self.secure_login_url, {}, follow=True)
        self.assertIsInstance(response, HttpResponseBadRequest)

    def test_login(self):
        response = self._secure_login()
        # debug_response(response)
        self.assertSecureLoginSuccess(response)

    def test_wrong_username(self):
        """
        Request with a wrong username
        use a valid secure-pass, so that the password validation will not raised an error.
        """
        self.username="doesnt_exist"
        response = self._secure_login()
        # debug_response(response)
        self.assertSecureLoginFailed(response)

    def test_not_active_user(self):
        self.superuser.is_active = False
        self.superuser.save()

        response = self._secure_login()
        self.assertSecureLoginFailed(response)

        # We should get the "right" salt value
        self.assertEqual(self.init_pbkdf2_salt, self.superuser_profile.init_pbkdf2_salt)

    def test_use_same_cnonce(self):
        response = self._secure_login()
        # debug_response(response)
        self.assertSecureLoginSuccess(response)

        old_cnonce = self.cnonce

        self.client.logout()
        self._reset_secure_data()
        self.cnonce = old_cnonce

        # Try to login with the same cnonce again:
        response = self._secure_login()
        self.assertEqual(self.cnonce, old_cnonce)
        # debug_response(response)
        self.assertSecureLoginFailed(response)

    def test_use_same_challenge(self):
        response = self._secure_login()
        # debug_response(response)
        self.assertSecureLoginSuccess(response)

        old_challenge = self.server_challenge

        self.client.logout()
        self.init_pbkdf2_salt = None # Request salt again

        # Try to login with the same challenge again:
        response = self._secure_login()
        # BadRequest, because challenge will always removed in session after use
        self.assertIsInstance(response, HttpResponseBadRequest)

    def test_replay_attack(self):
        """
        Try to use the same secure_password again
        """
        response = self._secure_login()
        # debug_response(response)
        self.assertSecureLoginSuccess(response)

        old_secure_password = self.secure_password

        self.client.logout()

        # Note: Every login POST request will delete the challenge from session
        # So we must request the Login form again to save a new challenge to session
        # Otherwise the view will only return a HttpResponseBadRequest
        self._request_server_challenge()

        # Try to login with the same secure_password again:
        response = self._secure_login()
        # debug_response(response)
        self.assertEqual(self.secure_password, old_secure_password)
        self.assertSecureLoginFailed(response)

    def test_request_salt_without_username(self):
        response = self.client.post(
            self.get_salt_url,
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
        )
        self.assertEqual(response.status_code, 400) # BadRequest


    def test_no_init_pbkdf2_salt_exists(self):
        self.superuser_profile.init_pbkdf2_salt = ""
        self.superuser_profile.save()
        pseudo_salt = self._request_init_pbkdf2_salt()

        v = HashValidator(name="pseudo_salt", length=app_settings.PBKDF2_SALT_LENGTH)
        v.validate(pseudo_salt)

        # Check if we get the same pseudo_salt, again:
        pseudo_salt2 = self._request_init_pbkdf2_salt()
        self.assertEqual(pseudo_salt, pseudo_salt2)

    def test_wrong_password_length(self):
        self._calc_secure_password()
        self.secure_password = secure_pass_manipulator(self.secure_password, pbkdf2_hash_mid="")

        response = self._secure_login()
        # debug_response(response)
        self.assertSecureLoginFailed(response)
        self.assertFormError(response, "form", field="password",
            errors="Ensure this value has at least %i characters (it has %i)." % (
                CLIENT_DATA_LEN, CLIENT_DATA_LEN-1
            )
        )

    def test_pbkdf2_hash_no_hex(self):
        self._calc_secure_password()
        self.secure_password = secure_pass_manipulator(self.secure_password, pbkdf2_hash_mid="X")

        response = self._secure_login()
        # debug_response(response)
        self.assertSecureLoginFailed(response)

    def test_wrong_secure_password(self):
        self._calc_secure_password()
        self.secure_password = self.secure_password.replace("$", "0", 1)

        response = self._secure_login()
        # debug_response(response)
        self.assertSecureLoginFailed(response)