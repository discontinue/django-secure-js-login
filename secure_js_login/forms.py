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
    username = forms.CharField(
        min_length=1,
        max_length=30, label=_('Username'),
        help_text=_('Required. 30 characters or fewer. Alphanumeric characters only (letters, digits and underscores).')
    )

    def __init__(self, *args, **kwargs):
        self.user = None
        self.user_profile = None
        super(UsernameForm, self).__init__(*args, **kwargs)

    def _raise_validate_error(self, msg):
        # log.debug(msg)
        if not settings.DEBUG:
            msg = self.error_messages['invalid_login']
        raise forms.ValidationError(msg)

    def clean_username(self):
        username = self.cleaned_data['username']

        try:
            user = get_user_model().objects.get(username=username)
        except ObjectDoesNotExist as err:
            raise self._raise_validate_error("User %r doesn't exists!" % username)

        if not user.is_active:
            raise self._raise_validate_error("User %r is not active!" % user)
        else:
            self.user = user

        try:
            self.user_profile = UserProfile.objects.get_user_profile(self.user)
        except ObjectDoesNotExist as err:
            raise self._raise_validate_error(
                "Profile for user %r doesn't exists!" % self.user.username
            )
        return username


# PBKDF2_BYTE_LENGTH*2 + "$" + PBKDF2_BYTE_LENGTH + "$" + CLIENT_NONCE_LENGTH
# or:
# PBKDF2_HEX_LENGTH + "$" + PBKDF2_HALF_HEX_LENGTH + "$" + CLIENT_NONCE_LENGTH
CLIENT_DATA_LEN = crypt.PBKDF2_HEX_LENGTH + crypt.PBKDF2_HALF_HEX_LENGTH + app_settings.CLIENT_NONCE_LENGTH + 2


class HashValidator(object):
    def __init__(self, name, length):
        self.name = name
        self.length = length
        self.regexp = re.compile(r"^[a-f0-9]{%i}$" % length)

    def validate(self, value):
        if len(value)!=self.length:
            raise ValidationError("%s length error" % self.name)

        if not self.regexp.match(value):
            raise ValidationError("%s regexp error" % self.name)

PBKDF2_HASH_Validator = HashValidator(name="pbkdf2_hash", length=crypt.PBKDF2_HEX_LENGTH)
SECOND_PBKDF2_PART_Validator = HashValidator(name="second_pbkdf2_part", length=crypt.PBKDF2_HALF_HEX_LENGTH)
CLIENT_NONCE_HEX_Validator = HashValidator(name="cnonce", length=app_settings.CLIENT_NONCE_LENGTH)


class SecureLoginForm(AuthenticationForm, UsernameForm):
    """
    data from the client as password:
        send pbkdf2_hash1, second-pbkdf2-part and cnonce to the server
    """
    password=forms.CharField(
        min_length=CLIENT_DATA_LEN,
        max_length=CLIENT_DATA_LEN,
        widget=forms.PasswordInput
    )

    def clean(self):
        try:
            username = self.cleaned_data['username']
        except KeyError as err:
            # e.g.: username field validator has cleaned the value
            # log.debug("No 'username' - Form errors: %r", self.errors)
            return

        assert isinstance(self.user, get_user_model())

        try:
            pbkdf2_hash, second_pbkdf2_part, cnonce = self.cleaned_data['password']
        except KeyError as err:
            # e.g.: password field validator has cleaned the value
            log.debug("No 'password' - Form errors: %r", self.errors)
            return
        except TypeError as err:
            self._raise_validate_error("Wrong password data: %s" % err)

        self.cleaned_data["password"] = "" # Don't send password back

        server_challenge = self.request.old_server_challenge
        if not server_challenge:
            self._raise_validate_error("request.old_server_challenge not set.")
        # log.debug("Challenge from session: %r", server_challenge)

        # Simple check if 'nonce' from client used in the past.
        # Limitations:
        #  - Works only when run in a long-term server process, so not in CGI ;)
        #  - dict vary if more than one server process runs (one dict in one process)
        if cnonce in CNONCE_CACHE:
            self._raise_validate_error("Client-nonce %r used in the past!" % cnonce)

        CNONCE_CACHE[cnonce] = None

        self.user.previous_login = self.user.last_login # Save for: secure_js_login.views.display_login_info()

        kwargs = {
            "username":username,
            "user": self.user,
            "encrypted_part": self.user_profile.encrypted_part,
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

        PBKDF2_HASH_Validator.validate(pbkdf2_hash)
        SECOND_PBKDF2_PART_Validator.validate(second_pbkdf2_part)
        CLIENT_NONCE_HEX_Validator.validate(cnonce)

        # log.debug("Password data is valid.")
        return (pbkdf2_hash, second_pbkdf2_part, cnonce)

    def get_user(self):
        # for django.auth.views.login
        return self.user

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

