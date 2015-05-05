# coding: utf-8

"""
    PyLucid JS-SHA-Login forms
    ~~~~~~~~~~~~~~~~~~~~~~~~~~

    A secure JavaScript SHA-1 AJAX Login.

    :copyleft: 2007-2015 by the PyLucid team, see AUTHORS for more details.
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

import logging
import re

from django import forms
from django.conf import settings
from django.contrib import auth
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import AuthenticationForm
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext as _
from django.forms.forms import NON_FIELD_ERRORS
from django.contrib.auth import authenticate

from secure_js_login.utils import crypt
from secure_js_login.models import UserProfile, CNONCE_CACHE
from secure_js_login import settings as app_settings


log = logging.getLogger("secure_js_login")


class WrongUserError(Exception):
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
                user = get_user_model().objects.get(username=username)
            except get_user_model().DoesNotExist as err:
                raise WrongUserError("User %r doesn't exists!" % username)

            if not user.is_active:
                raise WrongUserError("User %r is not active!" % user)

            log.debug("User %r: %r", username, user)

        return self.user_cache

    def get_user_and_profile(self):
        user = self.get_user()
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


class SecureLoginForm(AuthenticationForm, UsernameForm):
    """
    data from the client as password:
        send pbkdf2_hash1, second-pbkdf2-part and cnonce to the server
    """
    password=forms.CharField(
        min_length=CLIENT_DATA_LEN,
        max_length=CLIENT_DATA_LEN,
    )

    def _raise_validate_error(self, msg):
        log.debug(msg)
        if not settings.DEBUG:
            msg = self.error_messages['invalid_login']

        raise forms.ValidationError(msg)

    def clean(self):
        log.debug("Form cleaned data: %r", self.cleaned_data)

        username = self.cleaned_data.get('username')
        if not username:
            log.error("No Username?!?")
            return

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
            server_challenge = self.request.session.pop("server_challenge")
        except KeyError as err:
            self._raise_validate_error("Can't get 'server_challenge' from session: %s" % err)
        else:
            log.debug("Challenge from session: %r", server_challenge)

        user = self.get_user()
        if not user:
            log.error("No User?!?")
            return

        user_profile = UserProfile.objects.get_user_profile(user)

        kwargs = {
            "username":username,
            "encrypted_part": user_profile.encrypted_part,
            "server_challenge":server_challenge,
            "pbkdf2_hash":pbkdf2_hash,
            "second_pbkdf2_part":second_pbkdf2_part,
            "cnonce":cnonce,
        }
        log.info("Call authenticate with: %s", repr(kwargs))
        self.user_cache = authenticate(**kwargs)
        if self.user_cache is None:
            raise forms.ValidationError(
                self.error_messages['invalid_login'],
                code='invalid_login',
                params={'username': self.username_field.verbose_name},
            )
        else:
            self.confirm_login_allowed(self.user_cache)

    def clean_password(self):
        log.debug("clean password")
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

        log.debug("Password data is valid.")
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

