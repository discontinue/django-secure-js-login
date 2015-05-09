#!/usr/bin/env python
# coding: utf-8

"""
    django-reversion-compare unittests
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    I used the setup from reversion_compare_test_project !

    TODO:
        * models.OneToOneField()
        * models.IntegerField()

    :copyleft: 2012 by the django-reversion-compare team, see AUTHORS for more details.
    :license: GNU GPL v3 or above, see LICENSE for more details.
"""

from __future__ import unicode_literals, print_function

import pprint
import sys
import traceback

from django.contrib.auth import get_user_model, authenticate, SESSION_KEY
from django.core.urlresolvers import reverse
from django.http import HttpResponse
from django.test import SimpleTestCase

from secure_js_login.models import UserProfile


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
        print("\n", flush=True, file=sys.stderr)
        print("*" * 79, file=sys.stderr)
        traceback.print_exc()
        print(" -" * 40, file=sys.stderr)
        if isinstance(page_source, HttpResponse):
            page_source = page_source.content
        page_source = "\n".join([line for line in page_source.splitlines() if line.rstrip()])
        print(page_source, file=sys.stderr)
        print("*" * 79, file=sys.stderr)
        print("\n", flush=True, file=sys.stderr)
        raise

    def assertContainsHtml(self, response, *args):
        for html in args:
            try:
                self.assertContains(response, html, html=True)
            except AssertionError as e:
                debug_response(response, msg="%s" % e) # from django-tools
                raise

    def assertNotContainsHtml(self, response, *args):
        for html in args:
            try:
                self.assertNotContains(response, html, html=True)
            except AssertionError as e:
                debug_response(response, msg="%s" % e) # from django-tools
                raise

    def assertSecureLoginSuccess(self, page_source):
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
            self.assertNotIn("error", page_source)
        except AssertionError as err:
            self._verbose_assertion_error(page_source)

    def assertSecureLoginFailed(self, page_source):
        if isinstance(page_source, HttpResponse):
            page_source = page_source.content.decode("utf-8")
            try:
                self.assertNotIn(SESSION_KEY, self.client.session)
            except AssertionError as err:
                self._verbose_assertion_error(page_source)

        try:
            self.assertNotIn("You are logged in.", page_source)
            self.assertNotIn("Last login was:", page_source)
            self.assertNotIn("Log out", page_source)
            self.assertIn("error", page_source)
        except AssertionError as err:
            self._verbose_assertion_error(page_source)


class SecureLoginBaseTestCase(SimpleTestCase, AdditionalAssertmentsMixin):
    SUPER_USER_NAME = "super"
    SUPER_USER_PASS = "super secret"

    @classmethod
    def setUpClass(cls):
        super(SecureLoginBaseTestCase, cls).setUpClass()
        cls.secure_login_url = reverse("secure-js-login:login")
        cls.get_salt_url = reverse("secure-js-login:get_salt")
        cls.honypot_url = reverse("honypot-login:login")

    def setUp(self):
        super(SecureLoginBaseTestCase, self).setUp()
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

