# coding: utf-8

"""
    Secure JavaScript Login
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyleft: 2007-2015 by the secure-js-login team, see AUTHORS for more details.
    :created: by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from __future__ import unicode_literals

import os

# set: DJANGO_SETTINGS_MODULE:tests.test_utils.test_settings to run the tests
assert os.environ["DJANGO_SETTINGS_MODULE"]=="tests.test_utils.test_settings"

from django.test import SimpleTestCase

from secure_js_login.models import UserProfile
from tests.test_utils.test_cases import UserTestCaseMixin
from secure_js_login import settings as app_settings
from secure_js_login.utils import crypt


class TestUserProfile(SimpleTestCase, UserTestCaseMixin):
    def test_get_profile(self):
        user = self.create_and_get_superuser()
        user_profile = UserProfile.objects.get_user_profile(user)
        self.assertEqual(user.pk, user_profile.user.pk)

    def test_get_profile(self):
        user = self.create_and_get_superuser()
        user_profile = UserProfile.objects.get_user_profile(user)

        init_pbkdf2_salt = user_profile.init_pbkdf2_salt
        encrypted_part = user_profile.encrypted_part

        self.assertEqual(len(init_pbkdf2_salt), app_settings.PBKDF2_SALT_LENGTH)
        # self.assertEqual(len(encrypted_part), crypt.PBKDF2_HALF_HEX_LENGTH)

        # Check the created data:
        cnonce="1"
        server_challenge="2"
        pbkdf2_hash, second_pbkdf2_part = crypt._simulate_client(
            plaintext_password=self.SUPER_USER_PASS,
            init_pbkdf2_salt=init_pbkdf2_salt,
            cnonce=cnonce,
            server_challenge=server_challenge,
        )

        check = crypt.check_secure_js_login(
            encrypted_part,
            server_challenge,
            pbkdf2_hash,
            second_pbkdf2_part,
            cnonce
        )
        self.assertTrue(check)

