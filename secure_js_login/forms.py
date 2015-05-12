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
from secure_js_login.signals import secure_js_login_failed

from secure_js_login.utils import crypt
from secure_js_login.models import UserProfile, CNONCE_CACHE
from secure_js_login import settings as app_settings


log = logging.getLogger("secure_js_login")


class WrongUserError(ObjectDoesNotExist):
    pass


# Use the same error message from auth.forms.AuthenticationForm
ERROR_MESSAGE = AuthenticationForm.error_messages["invalid_login"]


class UsernameForm(AuthenticationForm):
    """
    Used to get the salt from UserProfile
    """
    password = forms.CharField(required=False)

    def __init__(self, request=None, *args, **kwargs):
        super(UsernameForm, self).__init__(request, *args, **kwargs)
        self.user_profile = None

    def _raise_validate_error(self, msg):
        # log.debug("%s error: %s", self.__class__.__name__, msg)
        if not settings.DEBUG:
            msg = ERROR_MESSAGE

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
            self.user_cache = get_user_model().objects.get(username=username)
        except ObjectDoesNotExist as err:
            raise self._raise_validate_error("User %r doesn't exists!" % username)

        try:
            self.user_profile = UserProfile.objects.get_user_profile(self.user_cache)
        except ObjectDoesNotExist as err:
            raise self._raise_validate_error(
                "Profile for user %r doesn't exists!" % self.user_cache.username
            )
        return username

    def is_valid(self):
        valid=super(UsernameForm, self).is_valid()
        if not valid:
            # FIXME: How to made this simpler?!?
            form_errors = self.errors.as_data()
            errors=[]
            for field_name, field_errors in sorted(form_errors.items()):
                field_errors = ",".join([",".join(field_error.messages) for field_error in field_errors])
                errors.append("%r:%s" % (field_name, field_errors))
            errors=", ".join(errors)

            reason = "%s error: %s" % (self.__class__.__name__, errors)
            secure_js_login_failed.send(sender=SecureLoginForm, reason=reason)
            # log.error("POST: %r form errors: %s" % (repr(self.request.POST), reason))

        return valid


class SecureLoginForm(UsernameForm):
    """
    data from the client as password:
        send pbkdf2_hash1, second-pbkdf2-part and cnonce to the server
    """
    password=forms.CharField(
        min_length=crypt.CLIENT_DATA_LEN,
        max_length=crypt.CLIENT_DATA_LEN,
        widget=forms.PasswordInput
    )

    def clean(self):
        username = self.cleaned_data.get('username')
        secure_password = self.cleaned_data.get('password')

        assert self.request is not None
        try:
            server_challenge = self.request.server_challenge
        except AttributeError as err:
            self._raise_validate_error("request.server_challenge not set: %s" % err)
        # log.debug("Challenge from session: %r", server_challenge)

        if username and secure_password:
            self.user_cache = authenticate(
                username=username,
                secure_password=secure_password,
                server_challenge=server_challenge
            )
            # log.debug("Get %r back from authenticate()", self.user_cache)
            if self.user_cache is None:
                self._raise_validate_error("authenticate() check failed.")
            else:
                # log.debug("confirm_login_allowed()")
                self.confirm_login_allowed(self.user_cache)
                # log.debug("confirm_login_allowed() - OK")

        return self.cleaned_data


