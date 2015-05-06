# coding: utf-8

"""
    Secure JavaScript Login
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyleft: 2007-2015 by the secure-js-login team, see AUTHORS for more details.
    :created: by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from __future__ import unicode_literals

import logging
import re

from django import forms
from django.conf import settings
from django.contrib import auth
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import AuthenticationForm
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.utils.translation import ugettext as _
from django.forms.forms import NON_FIELD_ERRORS
from django.contrib.auth import authenticate

from secure_js_login.utils import crypt
from secure_js_login.models import UserProfile, CNONCE_CACHE
from secure_js_login import settings as app_settings


log = logging.getLogger("secure_js_login")


class WrongUserError(ObjectDoesNotExist):
    pass


class UsernameForm(forms.Form):
    username = forms.CharField(max_length=30, label=_('Username'),
        help_text=_('Required. 30 characters or fewer. Alphanumeric characters only (letters, digits and underscores).')
    )

    def __init__(self, *args, **kwargs):
        self.user_cache = None
        super(UsernameForm, self).__init__(*args, **kwargs)

    def get_user(self):
        if not self.user_cache:
            username = self.cleaned_data["username"]
            try:
                self.user_cache = get_user_model().objects.get(username=username)
            except ObjectDoesNotExist as err:
                raise WrongUserError("User %r doesn't exists!" % username)

            if not self.user_cache.is_active:
                raise WrongUserError("User %r is not active!" % self.user_cache)

        return self.user_cache

    def get_user_and_profile(self):
        user = self.get_user()
        assert isinstance(user, get_user_model())
        user_profile = UserProfile.objects.get_user_profile(user)
        return user, user_profile


# PBKDF2_BYTE_LENGTH*2 + "$" + PBKDF2_BYTE_LENGTH + "$" + CLIENT_NONCE_LENGTH
# or:
# PBKDF2_HEX_LENGTH + "$" + PBKDF2_HALF_HEX_LENGTH + "$" + CLIENT_NONCE_LENGTH
CLIENT_DATA_LEN = crypt.PBKDF2_HEX_LENGTH + crypt.PBKDF2_HALF_HEX_LENGTH + app_settings.CLIENT_NONCE_LENGTH + 2


class HashValidator(object):
    def __init__(self, length):
        self.length = length
        self.regexp = re.compile(r"^[a-f0-9]{%i}$" % length)

    def validate(self, value):
        if len(value)!=self.length:
            raise ValidationError("length error")

        if not self.regexp.match(value):
            raise ValidationError("regexp error")

PBKDF2_HEX_Validator = HashValidator(length=crypt.PBKDF2_HEX_LENGTH)
PBKDF2_HALF_HEX_Validator = HashValidator(length=crypt.PBKDF2_HALF_HEX_LENGTH)
CLIENT_NONCE_HEX_Validator = HashValidator(length=app_settings.CLIENT_NONCE_LENGTH)


class SecureLoginForm(UsernameForm, AuthenticationForm):
    """
    data from the client as password:
        send pbkdf2_hash1, second-pbkdf2-part and cnonce to the server
    """
    password=forms.CharField(
        min_length=CLIENT_DATA_LEN,
        max_length=CLIENT_DATA_LEN,
        widget=forms.PasswordInput
    )

    def _raise_validate_error(self, msg):
        # log.debug(msg)
        if not settings.DEBUG:
            msg = self.error_messages['invalid_login']
        raise forms.ValidationError(msg)

    def clean(self):
        # log.debug("Form cleaned data: %r", self.cleaned_data)

        server_challenge = self.request.old_server_challenge
        if not server_challenge:
            self._raise_validate_error("request.old_server_challenge not set.")
        # log.debug("Challenge from session: %r", server_challenge)

        username = self.cleaned_data.get('username')
        if not username:
            self._raise_validate_error("No Username?!?")

        try:
            pbkdf2_hash, second_pbkdf2_part, cnonce = self.cleaned_data.get('password')
        except TypeError as err:
            self._raise_validate_error("Wrong password data: %s" % err)

        self.cleaned_data["password"] = ""

        # Simple check if 'nonce' from client used in the past.
        # Limitations:
        #  - Works only when run in a long-term server process, so not in CGI ;)
        #  - dict vary if more than one server process runs (one dict in one process)
        if cnonce in CNONCE_CACHE:
            self._raise_validate_error("Client-nonce %r used in the past!" % cnonce)

        CNONCE_CACHE[cnonce] = None

        try:
            user, user_profile = self.get_user_and_profile()
        except ObjectDoesNotExist as err:
            self._raise_validate_error("Can't get user+profile: %s" % err)

        user.previous_login = user.last_login # Save for: secure_js_login.views.display_login_info()

        # crypt._simulate_client(
        #     plaintext_password="12345678",
        #     init_pbkdf2_salt=user_profile.init_pbkdf2_salt,
        #     cnonce=cnonce,
        #     server_challenge=server_challenge
        # )

        kwargs = {
            "username":username,
            "user": user,
            "encrypted_part": user_profile.encrypted_part,
            "server_challenge":server_challenge,
            "pbkdf2_hash":pbkdf2_hash,
            "second_pbkdf2_part":second_pbkdf2_part,
            "cnonce":cnonce,
        }
        # log.info("Call authenticate with: %s", repr(kwargs))

        try:
            user = authenticate(**kwargs)
        except crypt.CryptError as err:
            self._raise_validate_error("crypt.check_secure_js_login error: %s" % err)

        if not user:
            self._raise_validate_error("crypt.check_secure_js_login failed!")

        self.confirm_login_allowed(user)
        return user


    def clean_password(self):
        password = self.cleaned_data["password"]
        if password.count("$") != 2:
            self._raise_validate_error(
                "No two $ (found: %i) in password found in: %r" % (
                    password.count("$"),password
                )
            )

        pbkdf2_hash, second_pbkdf2_part, cnonce = password.split("$")

        PBKDF2_HEX_Validator.validate(pbkdf2_hash)
        PBKDF2_HALF_HEX_Validator.validate(second_pbkdf2_part)
        CLIENT_NONCE_HEX_Validator.validate(cnonce)

        # log.debug("Password data is valid.")
        return (pbkdf2_hash, second_pbkdf2_part, cnonce)


# class JSPasswordChangeForm(Sha1BaseForm):
#     """
#     Form for changing the password with Client side JS encryption.
#
#     inherited form Sha1BaseForm() this form fields:
#         pbkdf2_hash
#         second_pbkdf2_part
#         cnonce
#     for pre-verification with old password "JS-SHA1" values
#     """
#     # new password as salted SHA1 hash:
#     salt = forms.CharField(min_length=crypt.SALT_LEN, max_length=crypt.SALT_LEN) # length see: hashers.SHA1PasswordHasher() and django.utils.crypto.get_random_string()
#     sha1hash = forms.CharField(min_length=crypt.CLIENT_DATA_LEN, max_length=crypt.CLIENT_DATA_LEN)
#     def clean_salt(self):
#         return self._validate_filled_sha1_by_key("salt")
#     def clean_sha1(self):
#         return self._validate_sha1_by_key("sha1hash")

