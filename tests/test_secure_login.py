# coding: utf-8

"""
    Secure JavaScript Login
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyleft: 2007-2015 by the secure-js-login team, see AUTHORS for more details.
    :created: by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from __future__ import unicode_literals, print_function

# set: DJANGO_SETTINGS_MODULE:tests.test_utils.test_settings to run the tests

import django
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.http import HttpResponseBadRequest
from django.test import override_settings

from secure_js_login.utils import crypt
from secure_js_login import settings as app_settings
from secure_js_login.utils.crypt import CLIENT_DATA_LEN, HashValidator

from tests.test_utils.manipulators import secure_pass_manipulator
from tests.test_utils.client_test_cases import SecureLoginClientBaseTestCase


class TestSecureLogin(SecureLoginClientBaseTestCase):
    """
    Tests with django test client
    """

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

    def test_secure_login_page(self):
        response = self.client.get(self.secure_login_url)
        # debug_response(response)

        if django.VERSION >= (1, 8):
            required_html = "required"
        else:
            required_html = 'required="True"'

        self.assertContainsHtml(response,
            '<input id="id_username" maxlength="254" name="username" type="text" class="required" %s />' % required_html
        )
        self.assertContainsHtml(response,
            '<input id="id_password" maxlength="%i" name="password" type="password" class="required" %s />' % (
                crypt.CLIENT_DATA_LEN, required_html
            )
        )

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

        # We should get pseudo salt for inactiv users:
        self.assertNotEqual(self.init_pbkdf2_salt, self.superuser_profile.init_pbkdf2_salt)

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