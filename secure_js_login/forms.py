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
from django.contrib import auth
from django.contrib.auth import get_user_model
from django.utils.translation import ugettext as _
from django.forms.forms import NON_FIELD_ERRORS

from secure_js_login.utils import crypt
from secure_js_login.models import UserProfile


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

    def get_user_profile(self, user=None):
        if user is None:
            user = self.get_user()
            
        try:
            userprofile = UserProfile.objects.get(user=user)
        except UserProfile.DoesNotExist as err:
            raise WrongUserError("Can't get user profile: %r" % err)
        log.debug("User profile: %r for user %r" % (userprofile, user))
        return userprofile

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

class SecureLoginForm(UsernameForm):
    password=forms.CharField(
        min_length=HASH_LEN,
        max_length=HASH_LEN
    )

    def _validate_sha1(self, sha_value, key):
        if crypt.validate_sha_value(sha_value) != True:
            raise forms.ValidationError(u"%s is not valid SHA value." % key)
        return sha_value

    def clean_password(self):
        raw_password = self.cleaned_data["password"]
        if raw_password.count("$") != 3:
            forms.ValidationError(_("No three $ found!"))

        sha_a, sha_b, cnonce = raw_password.split("$")
        self._validate_sha1(sha_a, "sha_a")

        # Fill with null, to match the full SHA1 hexdigest length:
        self._validate_sha1(sha_b.ljust(crypt.HASH_LEN, "0"), "sha_b")

        self._validate_sha1(cnonce, "cnonce")

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

