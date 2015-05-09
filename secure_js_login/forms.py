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
from django.contrib.auth.forms import AuthenticationForm

from django import forms
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.utils.translation import ugettext as _
from django.contrib.auth import authenticate
from django.utils.text import capfirst

from secure_js_login.utils import crypt
from secure_js_login.models import UserProfile, CNONCE_CACHE
from secure_js_login import settings as app_settings


log = logging.getLogger("secure_js_login")


class WrongUserError(ObjectDoesNotExist):
    pass


# Use the same error message from auth.forms.AuthenticationForm
ERROR_MESSAGE = AuthenticationForm.error_messages["invalid_login"]


class UsernameForm(forms.Form):
    """
    similar to django.contrib.auth.forms.AuthenticationForm
    """
    username = forms.CharField(min_length=1, max_length=254)

    def __init__(self, request=None, *args, **kwargs):
        """
        'request' parameter like auth.forms.AuthenticationForm
        """
        self.request = request
        self.user = None
        self.user_profile = None

        super(UsernameForm, self).__init__(*args, **kwargs)

        # Set the label for the "username" field.
        UserModel = get_user_model()
        self.username_field = UserModel._meta.get_field(UserModel.USERNAME_FIELD)
        if self.fields['username'].label is None:
            self.fields['username'].label = capfirst(self.username_field.verbose_name)

    def _raise_validate_error(self, msg):
        # log.debug("%s error: %s", self.__class__.__name__, msg)
        if not settings.DEBUG:
            msg = ERROR_MESSAGE % {'username': self.username_field.verbose_name}

        raise forms.ValidationError(
            msg,
            code='invalid_login',
            params={'username': self.username_field.verbose_name},
        )

    def clean(self):
        # log.debug("%s.clean()", self.__class__.__name__)
        username = self.cleaned_data.get('username')

    def clean_username(self):
        # log.debug("%s.clean_username()", self.__class__.__name__)
        username = self.cleaned_data['username']
        try:
            self.user = get_user_model().objects.get(username=username)
        except ObjectDoesNotExist as err:
            raise self._raise_validate_error("User %r doesn't exists!" % username)

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


class SecureLoginForm(UsernameForm):
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

        # self.user set in UsernameForm.clean_username()
        assert isinstance(self.user, get_user_model())

        if not self.user.is_active==True:
            raise self._raise_validate_error("User %r is not active!" % self.user)

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

        return user

    def clean_password(self):
        password = self.cleaned_data["password"]
        if password.count("$") != 2:
            log.error(
                "No two $ (found: %i) in password found in: %r" % (
                    password.count("$"),password
                )
            )
            return

        pbkdf2_hash, second_pbkdf2_part, cnonce = password.split("$")

        try:
            PBKDF2_HASH_Validator.validate(pbkdf2_hash)
            SECOND_PBKDF2_PART_Validator.validate(second_pbkdf2_part)
            CLIENT_NONCE_HEX_Validator.validate(cnonce)
        except ValidationError as err:
            log.error("password value error: %s" % err)
            return

        # log.debug("Password data is valid.")
        return (pbkdf2_hash, second_pbkdf2_part, cnonce)

    def get_user(self):
        # API for auth.views.login()
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

