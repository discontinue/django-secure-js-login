# coding: utf-8

"""
    Secure JavaScript Login
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyleft: 2007-2015 by the secure-js-login team, see AUTHORS for more details.
    :created: by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from __future__ import unicode_literals

import hashlib
import os
from django.conf import settings
from django.contrib.auth.models import User
from django.utils import six
from secure_js_login.models import UserProfile
from secure_js_login.utils import crypt

if __name__ == "__main__":
    os.environ['DJANGO_SETTINGS_MODULE'] = 'tests.test_utils.test_settings'
    print("\nUse DJANGO_SETTINGS_MODULE=%r" % os.environ["DJANGO_SETTINGS_MODULE"])

from django.core.urlresolvers import reverse
from django.test import SimpleTestCase

# https://github.com/jedie/django-tools/
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

from secure_js_login import settings as app_settings

#
#
# class TestCrypt(SimpleTestCase):
#     """
#     low level test with Models but not with Webpage
#     """
#     def test_create_user_and_decrypt(self):
#         password = 'this is not secret'
#         new_user = User.objects.create_superuser(username='super', email='super@localhost', password=password)
#         user, profile = UserProfile.objects.get_user_profile(username='super')
#
#         sha_login_checksum = profile.sha_login_checksum
#         sha_login_salt = profile.sha_login_salt
#
#         hash = hashlib.sha1(bytes(sha_login_salt + password, "ascii")).hexdigest()
#
#         sha_a = hash[:20]
#         sha_b = hash[20:]
#
#         test = crypt.xor_decrypt(sha_login_checksum, key=sha_b)
#         self.assertEqual(test, sha_a)
#
#
# class TestSecureLogin(SimpleTestCase):
#     """
#     Tests with djang test client
#     """
#     UNITTEST_USERNAME="unittest_user"
#     UNITTEST_PASSWORD="unittest user password"
#
#     def _create_and_get_superuser(self):
#         return User.objects.create_superuser(
#             username=self.UNITTEST_USERNAME,
#             email='unittest@localhost',
#             password=self.UNITTEST_PASSWORD
#         )
#
#
#     def test_login_page(self):
#         response = self.client.get(reverse("secure-js-login:login"))
#         # debug_response(response)
#
#         self.assertContains(response, '<label for="id_username" class="required">Username:</label>', html=True)
#         self.assertContains(response, '<label for="id_password" class="required">Password:</label>', html=True)
#
#     def test_post_empty_form(self):
#         response = self.client.post(reverse("secure-js-login:login"), {}, follow=True)
#         # debug_response(response)
#         self.assertFormError(response, 'form', 'username', 'This field is required.')
#         self.assertFormError(response, 'form', 'password', 'This field is required.')
#
#     def test_wrong_username(self):
#         response = self.client.post(reverse("secure-js-login:login"), {
#             'username': 'doesnt_exist',
#             'password': 'not_secret',
#         }, follow=True)
#
#         # XXX: Why here: %(username)s ?!?
#         self.assertContains(response, "Please enter a correct %(username)s and password.")
#
#
#     def _request_challenge(self):
#         response = self.client.get(reverse("secure-js-login:login"))
#         csrf_cookie = response.cookies[settings.CSRF_COOKIE_NAME]
#         csrf_token = csrf_cookie.value
#         # debug_response(response)
#         challenge = response.context["challenge"]
#         self.assertContains(response, 'challenge="%s";' % challenge)
#         return challenge
#
#     def _request_salt(self):
#         response = self.client.post(
#             reverse("secure-js-login:get_salt"),
#             HTTP_X_REQUESTED_WITH='XMLHttpRequest',
#             # HTTP_X_CSRFTOKEN=csrf_token,
#             data={"username": self.UNITTEST_USERNAME}
#         )
#         user, profile = UserProfile.objects.get_user_profile(username=self.UNITTEST_USERNAME)
#         response_salt = six.text_type(response.content, "ascii")
#         self.assertEqual(response_salt, profile.sha_login_salt)
#         return response_salt
#
#     def test_login(self):
#         self._create_and_get_superuser()
#
#         challenge = self._request_challenge()
#         salt = self._request_salt()
#
#         print("challenge", challenge)
#         print("salt", salt)
#
#         shapass = hashlib.sha1(bytes(salt + self.UNITTEST_PASSWORD, "ascii")).hexdigest()
#         sha_a = shapass[:20]
#         sha_b = shapass[20:]
#
#         cnonce = "0123456789abcdef0123456789abcdef01234567"
#
#         for i in range(app_settings.LOOP_COUNT):
#             sha_a = hashlib.sha1(
#                 bytes("%s%s%s%s" % (sha_a, i, challenge, cnonce), "ascii")
#             ).hexdigest()
#
#         result = sha_a + "$" + sha_b +"$" + cnonce
#
#         response = self.client.post(
#             reverse("secure-js-login:login"),
#             data={
#                 "username": self.UNITTEST_USERNAME,
#                 "password": result,
#             }
#         )
#         # debug_response(response)
#         self.assertEqual(response.content, "TODO")
