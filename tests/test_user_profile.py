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

from django.utils.crypto import get_random_string

from secure_js_login.models import UserProfile
from secure_js_login.utils import crypt
from secure_js_login import settings as app_settings

from tests.test_utils.base_test_cases import SecureLoginBaseTestCase


class TestUserProfile(SecureLoginBaseTestCase):
    """
    TODO: Test User.set_unusable_password()
    """

    def test_set_password(self):
        old_init_pbkdf2_salt = self.superuser_profile.init_pbkdf2_salt
        old_encrypted_part = self.superuser_profile.encrypted_part

        self.superuser.set_password("New password")

        fresh_user_profile = UserProfile.objects.get_user_profile(self.superuser)
        self.assertNotEqual(old_init_pbkdf2_salt, fresh_user_profile.init_pbkdf2_salt)
        self.assertNotEqual(old_encrypted_part, fresh_user_profile.encrypted_part)

        # Check the created data:
        cnonce = cnonce = get_random_string(
            length=app_settings.CLIENT_NONCE_LENGTH,
            allowed_chars="1234567890abcdef" # cnonce must a "valid" hex value
        )
        server_challenge = crypt.seed_generator(app_settings.RANDOM_CHALLENGE_LENGTH)

        pbkdf2_hash, second_pbkdf2_part = crypt._simulate_client(
            plaintext_password="New password",
            init_pbkdf2_salt=fresh_user_profile.init_pbkdf2_salt,
            cnonce=cnonce,
            server_challenge=server_challenge,
        )
        check = crypt.check_secure_js_login(
            secure_password="$".join([pbkdf2_hash, second_pbkdf2_part, cnonce]),
            encrypted_part=fresh_user_profile.encrypted_part,
            server_challenge=server_challenge,
        )
        self.assertTrue(check)

