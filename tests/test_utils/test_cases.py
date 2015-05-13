# coding: utf-8

"""
    Secure JavaScript Login
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyleft: 2012-2015 by the secure-js-login team, see AUTHORS for more details.
    :created: by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from __future__ import unicode_literals, print_function

import pprint
import traceback
import logging
import sys

from django.contrib.auth import SESSION_KEY
from django.core.urlresolvers import reverse
from django.http import HttpResponse, HttpResponseBadRequest
from django.test import SimpleTestCase
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import six
from django.utils.crypto import get_random_string

from secure_js_login.models import UserProfile
from secure_js_login.signals import secure_js_login_failed
from secure_js_login.utils import crypt
from secure_js_login import settings as app_settings


log = logging.getLogger("secure_js_login")

try:
    import django_tools
    from django_tools.unittest_utils.BrowserDebug import debug_response
except ImportError as err:
    msg=(
        "Install django-tools for debug_response()"
        " - https://github.com/jedie/django-tools/"
        " - Original error: %s"
    ) % err
    def debug_response(*args, **kwargs):
        print(msg)
        pprint.pprint(args)
        pprint.pprint(kwargs)


class AdditionalAssertmentsMixin(object):
    def _verbose_assertion_error(self, page_source):
        print("\n", file=sys.stderr)
        print("*" * 79, file=sys.stderr)
        traceback.print_exc()
        print(" -" * 40, file=sys.stderr)

        if isinstance(page_source, HttpResponse):
            print("Response info:", file=sys.stderr)
            print("\ttype: %r" % type(page_source), file=sys.stderr)
            print("\tstatus_code: %r" % page_source.status_code, file=sys.stderr)
            page_source = page_source.content.decode("utf-8")
            print(" -" * 40, file=sys.stderr)

        if not page_source.strip():
            print("[page coure is empty!]", file=sys.stderr)
        else:
            page_source = "\n".join([line for line in page_source.splitlines() if line.rstrip()])
            print(page_source, file=sys.stderr)

        print("*" * 79, file=sys.stderr)
        print("\n", file=sys.stderr)
        raise

    def assertContainsHtml(self, response, *args):
        self.assertIsInstance(response, HttpResponse)
        for html in args:
            try:
                self.assertContains(response, html, html=True)
            except AssertionError:
                self._verbose_assertion_error(response)

    def assertNotContainsHtml(self, response, *args):
        self.assertIsInstance(response, HttpResponse)
        for html in args:
            try:
                self.assertNotContains(response, html, html=True)
            except AssertionError:
                self._verbose_assertion_error(response)

    def assertSecureLoginSuccess(self, page_source):
        self.assertNoFailedSignals()
        if isinstance(page_source, HttpResponse):
            page_source = page_source.content.decode("utf-8")
            try:
                self.assertIn(SESSION_KEY, self.client.session)
            except AssertionError as err:
                self._verbose_assertion_error(page_source)
        try:
            self.assertIn("You are logged in.", page_source)
            self.assertIn("Last login was:", page_source)
            self.assertIn(self.SUPER_USER_NAME, page_source)
            self.assertIn("Log out", page_source)
            self.assertNotIn("Traceback", page_source)
        except AssertionError as err:
            self._verbose_assertion_error(page_source)

    def assertSecureLoginFailed(self, page_source1):
        if isinstance(page_source1, HttpResponse):
            page_source2 = page_source1.content.decode("utf-8")
            try:
                self.assertNotIsInstance(page_source1, HttpResponseBadRequest)
                self.assertNotIn(SESSION_KEY, self.client.session)
            except AssertionError as err:
                self._verbose_assertion_error(page_source1)
        else:
            page_source2=page_source1

        try:
            self.assertNotIn("You are logged in.", page_source2)
            self.assertNotIn("Last login was:", page_source2)
            self.assertNotIn("Log out", page_source2)
            self.assertIn("error", page_source2)
        except AssertionError as err:
            self._verbose_assertion_error(page_source1)

    def assertOnlyCommonFormError(self, page_source1):
        common_error_text = (
            "Please enter a correct username and password."
            " Note that both fields may be case-sensitive."
        )
        try:
            if isinstance(page_source1, HttpResponse):
                self.assertFormError(page_source1, "form",
                    field="__all__",
                    errors=[common_error_text]
                )
                page_source2 = page_source1.content.decode("utf-8")
            else:
                page_source2=page_source1
                self.assertIn(common_error_text, page_source2)

            # No field errors:
            self.assertNotIn("errorlist", page_source2)
        except AssertionError as err:
            self._verbose_assertion_error(page_source1)


class SecureLoginBaseTestCase(SimpleTestCase, AdditionalAssertmentsMixin):
    SUPER_USER_NAME = "super"
    SUPER_USER_PASS = "super secret"

    DEFAULT_SIGNAL_FORM_ERROR = (
        "SecureLoginForm error:"
        " '__all__':Please enter a correct username and password."
        " Note that both fields may be case-sensitive."
    )

    @classmethod
    def setUpClass(cls):
        super(SecureLoginBaseTestCase, cls).setUpClass()
        cls.secure_login_url = reverse("secure-js-login:login")
        cls.get_salt_url = reverse("secure-js-login:get_salt")
        cls.honypot_url = reverse("honypot-login:login")

    def _secure_js_login_failed_signal_receiver(self, sender, reason, **kwargs):
        print("\n\t*** receive 'secure_js_login_failed' signal:", file=sys.stderr)
        print("\t - sender: %r" % sender, file=sys.stderr)
        print("\t - reason: %r" % reason, file=sys.stderr)
        self.signal_reasons.append(reason)

    def assertFailedSignals(self, *should_reasons):
        msg = (
            "\n*** should reasons are:\n"
            "\t%s\n"
            "*** existing reasons:\n"
            "\t%s\n"
        ) % (
            "\n\t".join(should_reasons),
            "\n\t".join(self.signal_reasons)
        )
        existing_reasons="|".join(self.signal_reasons)
        should_reasons="|".join(should_reasons)
        self.assertEqual(existing_reasons, should_reasons, msg=msg)
        print("\t+++ Signals ok", file=sys.stderr)

    def assertNoFailedSignals(self):
        msg=(
            "They should be no signals, but there are: \n\t%s"
        ) % "\n\t".join(self.signal_reasons)
        self.assertEqual(len(self.signal_reasons), 0, msg=msg)

    def reset_signal_storage(self):
        self.signal_reasons = []

    def setUp(self):
        super(SecureLoginBaseTestCase, self).setUp()
        self.reset_signal_storage()
        secure_js_login_failed.connect(self._secure_js_login_failed_signal_receiver)

        self.superuser, created = get_user_model().objects.get_or_create(
            username=self.SUPER_USER_NAME
        )
        self.superuser.email='unittest@localhost'
        self.superuser.is_active = True
        self.superuser.is_staff = True
        self.superuser.is_superuser = True
        self.superuser.set_password(self.SUPER_USER_PASS)
        self.superuser.save()

        # Always get the current profile with new salt (after settings new password!)
        self.superuser_profile = UserProfile.objects.get_user_profile(self.superuser)
        # log.debug(
        #     "user %s created: init_pbkdf2_salt=%r, encrypted_part=%r",
        #     self.superuser, self.superuser_profile.init_pbkdf2_salt, self.superuser_profile.encrypted_part
        # )

    def tearDown(self):
        super(SecureLoginBaseTestCase, self).tearDown()
        secure_js_login_failed.disconnect(self._secure_js_login_failed_signal_receiver)



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