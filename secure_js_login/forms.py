# coding: utf-8

"""
    PyLucid JS-SHA-Login forms
    ~~~~~~~~~~~~~~~~~~~~~~~~~~

    A secure JavaScript SHA-1 AJAX Login.

    :copyleft: 2007-2015 by the PyLucid team, see AUTHORS for more details.
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

import logging

from django import forms
from django.conf import settings
from django.contrib import auth
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import AuthenticationForm
from django.utils.translation import ugettext as _
from django.forms.forms import NON_FIELD_ERRORS
from django.contrib.auth import authenticate

from secure_js_login.utils import crypt
from secure_js_login.models import UserProfile, CNONCE_CACHE


log = logging.getLogger("secure_js_login")


class WrongUserError(Exception):
    pass


class UsernameForm(forms.Form):
    username = forms.CharField(max_length=30, label=_('Username'),
        help_text=_('Required. 30 characters or fewer. Alphanumeric characters only (letters, digits and underscores).')
    )

    def get_user(self):
        username = self.cleaned_data["username"]
        try:
            user = get_user_model().objects.get(username=username)
        except get_user_model().DoesNotExist as err:
            raise WrongUserError("User %r doesn't exists!" % username)

        if not user.is_active:
            raise WrongUserError("User %r is not active!" % user)

        log.debug("User %r: %r", username, user)
        return user


    def get_user_and_profile(self):
        user = self.get_user()
        user_profile = self.get_user_profile(user)
        return user, user_profile


class Sha1BaseForm(forms.Form):
    sha_a = forms.CharField(min_length=crypt.HASH_LEN, max_length=crypt.HASH_LEN)
    sha_b = forms.CharField(min_length=crypt.HASH_LEN / 2, max_length=crypt.HASH_LEN / 2)
    cnonce = forms.CharField(min_length=crypt.HASH_LEN, max_length=crypt.HASH_LEN)

    def _validate_sha1(self, sha_value, key):
        if crypt.validate_sha_value(sha_value) != True:
            raise forms.ValidationError(u"%s is not valid SHA value." % key)
        return sha_value

    def _validate_sha1_by_key(self, key):
        sha_value = self.cleaned_data[key]
        return self._validate_sha1(sha_value, key)

    def _validate_filled_sha1_by_key(self, key):
        value = self.cleaned_data[key]
        # Fill with null, to match the full SHA1 hexdigest length.
        temp_value = value.ljust(crypt.HASH_LEN, "0")
        self._validate_sha1(temp_value, key)
        return value

    def clean_sha_a(self):
        return self._validate_sha1_by_key("sha_a")
    def clean_cnonce(self):
        return self._validate_sha1_by_key("cnonce")

    def clean_sha_b(self):
        """
        The sha_b value is only a part of a SHA1 hexdigest. So we need to add
        some characers to use the crypt.validate_sha_value() method.
        """
        return self._validate_filled_sha1_by_key("sha_b")


class ShaLoginForm(Sha1BaseForm, UsernameForm):
    """
    Form for the SHA1-JavaScript-Login.

    inherited form Sha1BaseForm() this form fields:
        sha_a
        sha_b
        cnonce
    inherited form UsernameForm() this form fields:
        username
    """
    pass


HASH_LEN = (crypt.HASH_LEN * 2) + crypt.HALF_HASH_LEN + 2 # sha_a + "$" + sha_b +"$" + cnonce

class SecureLoginForm(AuthenticationForm):
    password=forms.CharField(
        min_length=HASH_LEN,
        max_length=HASH_LEN
    )

    def _validate_sha1(self, sha_value, key):
        if crypt.validate_sha_value(sha_value) != True:
            self._raise_validate_error("%s is not valid SHA value." % key)
        return sha_value

    def _raise_validate_error(self, msg):
        log.debug(msg)
        if not settings.DEBUG:
            msg = self.error_messages['invalid_login']

        raise forms.ValidationError(msg)

    def clean(self):
        log.debug("Form cleaned data: %r", self.cleaned_data)

        username = self.cleaned_data.get('username')
        if not username:
            return

        try:
            sha_a, sha_b, cnonce = self.cleaned_data.get('password')
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
            challenge = self.request.session.pop("challenge")
        except KeyError as err:
            self._raise_validate_error("Can't get 'challenge' from session: %s" % err)
        else:
            log.debug("Challenge from session: %r", challenge)

        kwargs = {
            "username":username,
            "challenge":challenge,
            "sha_a":sha_a,
            "sha_b":sha_b,
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

        sha_a, sha_b, cnonce = password.split("$")
        self._validate_sha1(sha_a, "sha_a")

        # Fill with null, to match the full SHA1 hexdigest length:
        self._validate_sha1(sha_b.ljust(crypt.HASH_LEN, "0"), "sha_b")

        self._validate_sha1(cnonce, "cnonce")

        log.debug("Password data is valid.")
        return (sha_a, sha_b, cnonce)


class JSPasswordChangeForm(Sha1BaseForm):
    """
    Form for changing the password with Client side JS encryption.

    inherited form Sha1BaseForm() this form fields:
        sha_a
        sha_b
        cnonce
    for pre-verification with old password "JS-SHA1" values
    """
    # new password as salted SHA1 hash:
    salt = forms.CharField(min_length=crypt.SALT_LEN, max_length=crypt.SALT_LEN) # length see: hashers.SHA1PasswordHasher() and django.utils.crypto.get_random_string()
    sha1hash = forms.CharField(min_length=crypt.HASH_LEN, max_length=crypt.HASH_LEN)
    def clean_salt(self):
        return self._validate_filled_sha1_by_key("salt")
    def clean_sha1(self):
        return self._validate_sha1_by_key("sha1hash")

