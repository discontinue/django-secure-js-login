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

import django
from django.contrib.auth import SESSION_KEY
from django.core.urlresolvers import reverse
from django.http import HttpResponse, HttpResponseBadRequest
from django.test import SimpleTestCase
from django.contrib.auth import get_user_model

from secure_js_login.models import UserProfile
from secure_js_login.signals import secure_js_login_failed
from secure_js_login.views import SERVER_CHALLENGE_KEY

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


class SecureLoginBaseTestCase(SimpleTestCase):
    VERBOSE = True
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
        cls.django_login_url = reverse("admin:login")

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

    def out(self, *args):
        print(*args, file=sys.stderr)

    def _verbose_assertion_error(self, page_source):
        sys.stderr.write("\n\n")
        sys.stderr.flush()
        sys.stderr.write("*" * 79)
        sys.stderr.write("\n")

        traceback.print_exc()

        sys.stderr.write(" -" * 40)
        sys.stderr.write("\n")

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

        sys.stderr.write("*" * 79)
        sys.stderr.write("\n")

        raise # raise the origin error

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

    def assertSecureLoginSuccess(self, response):
        """
        used with Django Test Client and in Selenium tests!
        """
        self.assertIsInstance(response, HttpResponse)

        self.assertNoFailedSignals()
        try:
            self.assertContains(response, "You are logged in.", html=False)
            self.assertContains(response, "Last login was:", html=False)
            self.assertContains(response, self.SUPER_USER_NAME, html=False)
            self.assertContains(response, "Log out", html=False)

            # Client is logged in:
            try:
                self.assertIn(SESSION_KEY, response.client.session)
            except AssertionError as err:
                raise AssertionError("%s\nclient.session: %s" % (
                    err, pprint.pformat(response.client.session)
                ))

            # secure-js-login challenge will be removed after login:
            self.assertNotIn(SERVER_CHALLENGE_KEY, response.client.session)

            self.assertNotContains(response, "Traceback", html=False)
        except AssertionError as err:
            self._verbose_assertion_error(response)

    def assertSecureLoginFailed(self, response):
        """
        used with Django Test Client and in Selenium tests!
        """
        self.assertIsInstance(response, HttpResponse)
        try:
            self.assertNotIsInstance(response, HttpResponseBadRequest)

            # Client is not logged in:
            self.assertNotIn(SESSION_KEY, response.client.session)

            # secure-js-login challenge in session:
            self.assertIn(SERVER_CHALLENGE_KEY, response.client.session)

            self.assertNotContains(response,"You are logged in.", html=False)
            self.assertNotContains(response,"Last login was:", html=False)
            self.assertNotContains(response,"Log out", html=False)

            # There are field errors:
            self.assertContains(response, "errorlist", html=False)

            self.assertNotContains(response, "Traceback", html=False)
        except AssertionError as err:
            self._verbose_assertion_error(response)

    def assertOnlyCommonFormError(self, response):
        """
        used with Django Test Client and in Selenium tests!
        """
        self.assertIsInstance(response, HttpResponse)

        if django.VERSION >= (1, 8):
            common_error_html = '<ul class="errorlist nonfield">'
        else:
            common_error_html = '<ul class="errorlist">'

        common_error_html += (
            '<li>'
            'Please enter a correct username and password.'
            ' Note that both fields may be case-sensitive.'
            '</li>'
            '</ul>'
        )
        try:
            self.assertContains(response, common_error_html, count=1, html=True)

            # Client is not logged in:
            self.assertNotIn(SESSION_KEY, response.client.session)

            # secure-js-login challenge in session:
            self.assertIn(SERVER_CHALLENGE_KEY, response.client.session)

            # No field errors: Only the common error should be exists.
            self.assertContains(response, "errorlist", count=1, html=False)

            self.assertNotContains(response, "Traceback", html=False)
        except AssertionError as err:
            self._verbose_assertion_error(response.content)

    def _secure_js_login_failed_signal_receiver(self, sender, reason, **kwargs):
        if self.VERBOSE:
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
        if self.VERBOSE:
            print("\t+++ Signals ok", file=sys.stderr)

    def assertNoFailedSignals(self):
        msg=(
            "They should be no signals, but there are: \n\t%s"
        ) % "\n\t".join(self.signal_reasons)
        self.assertEqual(len(self.signal_reasons), 0, msg=msg)

    def reset_signal_storage(self):
        self.signal_reasons = []




