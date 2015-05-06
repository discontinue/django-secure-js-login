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

from __future__ import unicode_literals
from django.contrib.auth import get_user_model

from django.db.models.loading import get_models, get_app
from django.test import TestCase
from secure_js_login.models import UserProfile

try:
    import django_tools
except ImportError as err:
    msg = (
        "Please install django-tools for unittests"
        " - https://github.com/jedie/django-tools/"
        " - Original error: %s"
    ) % err
    raise ImportError(msg)
from django_tools.unittest_utils.BrowserDebug import debug_response


class BaseTestCase(TestCase):
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


class UserTestCaseMixin(object):
    SUPER_USER_NAME = "super"
    SUPER_USER_PASS = "super secret"

    def create_and_get_superuser(self):
        user = get_user_model().objects.create_superuser(
            username=self.SUPER_USER_NAME,
            email='unittest@localhost',
            password=self.SUPER_USER_PASS
        )
        return user


