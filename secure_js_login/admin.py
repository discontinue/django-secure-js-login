# coding: utf-8

"""
    Secure JavaScript Login
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyleft: 2007-2015 by the secure-js-login team, see AUTHORS for more details.
    :created: by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from __future__ import unicode_literals

import base64

from django.conf import settings
from django.contrib import admin
from django.contrib.sites.models import get_current_site
from django.core.exceptions import ObjectDoesNotExist
from django.utils import six
from django.utils.http import urlquote
from django.utils.translation import ugettext_lazy as _
from django.template.loader import render_to_string

from django_otp.oath import TOTP
from django_otp.plugins.otp_totp.admin import TOTPDeviceAdmin
from django_otp.plugins.otp_totp.models import TOTPDevice

from secure_js_login.models import UserProfile


class UserProfileAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "createtime", "lastupdatetime")
    list_display_links = ("id", "user")
    list_filter = ("user",)
    date_hierarchy = 'lastupdatetime'
    search_fields = ("username",)

admin.site.register(UserProfile, UserProfileAdmin)


class TOTPDeviceAdmin2(TOTPDeviceAdmin):
    """
    Add QR-Code in google Key-Uri-Format
    https://github.com/google/google-authenticator/wiki/Key-Uri-Format
    """
    readonly_fields = ("qr_code","tokens")

    def get_form(self, request, *args, **kwargs):
        self.request = request # FIXME
        return super(TOTPDeviceAdmin2, self).get_form(request, *args, **kwargs)

    def _qr_code(self, instance):
        request = self.request # FIXME
        try:
            user = instance.user
        except ObjectDoesNotExist:
            return "Please save first!"

        current_site = get_current_site(request)
        username = user.username
        secret = six.text_type(base64.b32encode(instance.bin_key), encoding="ASCII")

        key_uri = (
            "otpauth://totp/secure-login:%(site_name)s-%(username)s?secret=%(secret)s&issuer=%(issuer)s"
        ) % {
            "site_name": urlquote(current_site.name),
            "username": urlquote(username),
            "secret": secret,
            "issuer": urlquote(username),
        }
        context = {
            "key_uri": key_uri,
        }
        return render_to_string("secure_js_login/qr_info.html", context)

    def qr_code(self, instance):
        try:
            return self._qr_code(instance)
        except Exception as err:
            if settings.DEBUG:
                import traceback
                return "<pre>%s</pre>" % traceback.format_exc()
    qr_code.short_description = _("Key")
    qr_code.allow_tags = True

    def tokens(self, instance):
        if not instance.pk:
            # e.g.: Use will create a new TOTP entry
            return "-"

        totp = TOTP(instance.bin_key, instance.step, instance.t0, instance.digits)

        tokens = []
        for offset in range(-instance.tolerance, instance.tolerance + 1):
            totp.drift = instance.drift + offset
            tokens.append(totp.token())

        return " ".join(["%s" % token for token in tokens])

    fieldsets = TOTPDeviceAdmin.fieldsets
    fieldsets.insert(1,
        ('Tokens', {'fields': ['tokens']})
    )
    fieldsets.insert(2,
        ('QR-Code', {'fields': ['qr_code']})
    )


admin.site.unregister(TOTPDevice)
admin.site.register(TOTPDevice, TOTPDeviceAdmin2)

