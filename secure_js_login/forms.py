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

import django_otp

from secure_js_login.exceptions import SecureJSLoginError
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
        self.error_message = ERROR_MESSAGE % {'username': self.username_field.verbose_name}

    def clean(self):
        # log.debug("%s.clean()", self.__class__.__name__)
        username = self.cleaned_data.get('username')

    def clean_username(self):
        # log.debug("%s.clean_username()", self.__class__.__name__)

        username = self.cleaned_data['username']
        try:
            self.user_cache = get_user_model().objects.get(username=username)
        except ObjectDoesNotExist as err:
            raise forms.ValidationError("User '%s' doesn't exists!" % username)

        if not self.user_cache.is_active:
            raise forms.ValidationError("User '%s' is not active!" % username)

        try:
            self.user_profile = UserProfile.objects.get_user_profile(self.user_cache)
        except ObjectDoesNotExist as err:
            raise forms.ValidationError(
                "Profile for user '%s' doesn't exists!" % self.user_cache.username
            )
        return username

    def is_valid(self):
        valid=super(UsernameForm, self).is_valid()
        if not valid:
            # Send signal with the "real" form error information
            # FIXME: How to made this simpler?!?
            form_errors = self.errors.as_data()
            errors=[]
            for field_name, field_errors in sorted(form_errors.items()):
                field_errors = ",".join([
                    ",".join(field_error.messages)
                    for field_error in field_errors
                ])
                errors.append("%s:%s" % (field_name, field_errors))
            errors=", ".join(errors)

            reason = "%s error: %s" % (self.__class__.__name__, errors)
            secure_js_login_failed.send(sender=self.__class__.__name__, reason=reason)
            # log.error("POST: '%s' form errors: %s" % (repr(self.request.POST), reason))

            if not settings.DEBUG:
                # Remove "real" form errors with common message
                self.errors.clear()
                self.add_error(field="__all__", error=self.error_message)

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
    otp_token = forms.IntegerField(
        min_value=1, max_value=99999999,
        label=_("OTP Token"),
        help_text=_("Two-way verification with Time-based One-time Password (TOTP)"),
    )

    def __init__(self, *args, **kwargs):
        super(SecureLoginForm, self).__init__(*args, **kwargs)
        # Not needed for django >= v1.8 !
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = "required"
            visible.field.widget.attrs["required"] = True

        if app_settings.TOTP_NEEDED:
            self.fields["otp_token"].widget.attrs["autocomplete"] = "off"
        else:
            # remove token field:
            del(self.fields["otp_token"])

    def _secure_js_login_failed_signal_handler(self, sender, reason, **kwargs):
        if settings.DEBUG:
            self.add_error(field="__all__", error=reason)

    def clean(self):
        username = self.cleaned_data.get('username')
        secure_password = self.cleaned_data.get('password')

        assert self.request is not None
        try:
            server_challenge = self.request.server_challenge
        except AttributeError as err:
            raise forms.ValidationError("request.server_challenge not set: %s" % err)
        # log.debug("Challenge from session: '%s'", server_challenge)

        if username and secure_password:
            if settings.DEBUG:
                secure_js_login_failed.connect(self._secure_js_login_failed_signal_handler)

            if app_settings.TOTP_NEEDED:
                otp_token = self.cleaned_data.get("otp_token")
                devices = tuple(django_otp.devices_for_user(self.user_cache))
                if len(devices)!=1:
                    raise forms.ValidationError("OTP devices count is not one, it's: %i" % len(devices))
                device = devices[0]
                if device.verify_token(otp_token) != True:
                    raise forms.ValidationError("OTP token wrong!")

            self.user_cache = authenticate(
                user=self.user_cache,
                user_profile=self.user_profile,
                secure_password=secure_password,
                server_challenge=server_challenge
            )
            if settings.DEBUG:
                secure_js_login_failed.disconnect(self._secure_js_login_failed_signal_handler)

            # log.debug("Get '%s' back from authenticate()", self.user_cache)
            if self.user_cache is None:
                raise forms.ValidationError(
                    "authenticate() check failed.",
                    code='invalid_login',
                )

        return self.cleaned_data


