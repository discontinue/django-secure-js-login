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
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.http import HttpResponseBadRequest
from django.test import override_settings
from django.utils import six
from django.utils.crypto import get_random_string
import sys

from secure_js_login.signals import secure_js_login_failed
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

    def test_existing_superuser(self):
        """
        Tests that assume that:
        * The created test user exists
        * The normal django password is ok
        * the default django authenticate backend worked
        """
        self.assertTrue(self.superuser.check_password(self.SUPER_USER_PASS))
        user = authenticate(username=self.SUPER_USER_NAME, password=self.SUPER_USER_PASS)
        self.assertIsInstance(user, get_user_model())
        self.assertNoFailedSignals()

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

    def test_login_page(self):
        response = self.client.get(self.secure_login_url)
        # debug_response(response)
        self.assertContains(response, '<label for="id_username" class="required">Username:</label>', html=True)
        self.assertContains(response, '<label for="id_password" class="required">Password:</label>', html=True)

    def test_post_empty_form1(self):
        response = self.client.post(self.secure_login_url, {}, follow=True)
        self.assertIsInstance(response, HttpResponseBadRequest)
        self.assertFailedSignals(
            "Can't get 'server_challenge' from session!"
        )

    def test_post_empty_form2(self):
        self._request_server_challenge()

        response = self.client.post(self.secure_login_url, {}, follow=True)
        self.assertSecureLoginFailed(response)
        self.assertFailedSignals(
            "SecureLoginForm error:"
            " password:This field is required.,"
            " username:This field is required."
        )

    def test_successful_login(self):
        response = self._secure_login()
        # debug_response(response)
        self.assertSecureLoginSuccess(response)

    def _test_wrong_username(self):
        """
        Request with a wrong username
        use a valid secure-pass, so that the password validation will not raised an error.
        """
        self.username="doesnt_exist"
        response = self._secure_login()
        # debug_response(response)
        self.assertSecureLoginFailed(response)
        self.assertFailedSignals(
            "UsernameForm error: username:User 'doesnt_exist' doesn't exists!",
            "SecureLoginForm error: username:User 'doesnt_exist' doesn't exists!"
        )
        return response

    @override_settings(DEBUG=False)
    def test_wrong_username_no_debug(self):
        """ only common error while DEBUG=False """
        response = self._test_wrong_username()
        self.assertOnlyCommonFormError(response)

    @override_settings(DEBUG=True)
    def test_wrong_username_with_debug(self):
        """ detail form error while DEBUG=True """
        response = self._test_wrong_username()
        # debug_response(response)
        self.assertFormError(response, "form", field="username", errors=[
            "User 'doesnt_exist' doesn't exists!"
        ])

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
        self.assertFailedSignals(
            "cnonce '%s' was used in the past!" % old_cnonce,
            "SecureLoginForm error: __all__:authenticate() check failed."
        )

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
        self.assertFailedSignals(
            "Can't get 'server_challenge' from session!"
        )

    def test_replay_attack(self):
        """
        Try to use the same secure_password again
        """
        response = self._secure_login()
        # debug_response(response)
        self.assertSecureLoginSuccess(response)

        old_secure_password = self.secure_password

        self.client.logout()

        self.assertNoFailedSignals()

        # Note: Every login POST request will delete the challenge from session
        # So we must request the Login form again to save a new challenge to session
        # Otherwise the view will only return a HttpResponseBadRequest
        self._request_server_challenge()

        self.assertNoFailedSignals()

        # Try to login with the same secure_password again:
        response = self._secure_login()
        # debug_response(response)
        self.assertEqual(self.secure_password, old_secure_password)
        self.assertSecureLoginFailed(response)
        self.assertFailedSignals(
            "cnonce '%s' was used in the past!" % self.cnonce,
            "SecureLoginForm error: __all__:authenticate() check failed."
        )

    def test_request_salt_without_username(self):
        self._request_server_challenge() # make a existing challenge

        response = self.client.post(
            self.get_salt_url,
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
        )
        self.assertEqual(response.status_code, 400) # BadRequest

    def test_request_salt_without_challenge(self):
        """
        The "get salt" view checks if the challenge exists.
        The challenge was added to session data in the GET login form request
        """
        response = self.client.post(
            self.get_salt_url,
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
            data={"username": self.SUPER_USER_NAME}
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

    def _test_wrong_password_length(self):
        self._calc_secure_password()
        self.secure_password = secure_pass_manipulator(self.secure_password, pbkdf2_hash_mid="")

        response = self._secure_login()
        # debug_response(response)
        self.assertSecureLoginFailed(response)
        return response

    @override_settings(DEBUG=False)
    def test_wrong_password_length_no_debug(self):
        response = self._test_wrong_password_length()
        # debug_response(response)
        self.assertOnlyCommonFormError(response)
        self.assertFailedSignals(
            (
                "SecureLoginForm error:"
                " password:"
                "Ensure this value has at least %i characters (it has %i)."
            ) % (
                CLIENT_DATA_LEN, CLIENT_DATA_LEN-1
            )
        )

    @override_settings(DEBUG=True)
    def test_wrong_password_length_with_debug(self):
        response = self._test_wrong_password_length()
        error_msg = "Ensure this value has at least %i characters (it has %i)." % (
            CLIENT_DATA_LEN, CLIENT_DATA_LEN-1
        )
        self.assertFailedSignals("SecureLoginForm error: password:%s" % error_msg)
        self.assertFormError(response, "form", field="password", errors=[error_msg])

    def test_pbkdf2_hash_no_hex(self):
        self._calc_secure_password()
        self.secure_password = secure_pass_manipulator(self.secure_password, pbkdf2_hash_mid="X")

        response = self._secure_login()
        # debug_response(response)
        self.assertSecureLoginFailed(response)
        self.assertFailedSignals(
            "pbkdf2_hash regexp error",
            "SecureLoginForm error: __all__:authenticate() check failed."
        )
        self.assertFormError(response, "form", field="__all__", errors=[
            "Please enter a correct username and password. Note that both fields may be case-sensitive."
        ])

    def _test_wrong_secure_password(self):
        self._calc_secure_password()
        self.secure_password = self.secure_password.replace("$", "0", 1)

        response = self._secure_login()
        # debug_response(response)
        self.assertSecureLoginFailed(response)
        return response

    @override_settings(DEBUG=False)
    def test_wrong_secure_password_no_debug(self):
        """ without DEBUG: only common error message """
        response = self._test_wrong_secure_password()
        self.assertOnlyCommonFormError(response)
        self.assertFailedSignals(
            "No two '$' (found: 1) in secure_password: '%s' !" % self.secure_password,
            "SecureLoginForm error: __all__:authenticate() check failed."
        )

    @override_settings(DEBUG=True)
    def test_wrong_secure_password_with_debug(self):
        """ If DEBUG is on: Display more information in form errors """
        response = self._test_wrong_secure_password()
        self.assertFailedSignals(
            "No two '$' (found: 1) in secure_password: '%s' !" % self.secure_password,
            (
                "SecureLoginForm error: __all__:No two '$' (found: 1) in secure_password: '%s' !"
                ",authenticate() check failed."
            ) % self.secure_password
        )
        self.assertFormError(response, "form", field="__all__", errors=[
            "No two '$' (found: 1) in secure_password: '%s' !" % self.secure_password,
            'authenticate() check failed.'
        ])