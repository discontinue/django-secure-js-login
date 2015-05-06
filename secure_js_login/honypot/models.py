# coding: utf-8

"""
    Secure JavaScript Login
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyleft: 2007-2015 by the secure-js-login team, see AUTHORS for more details.
    :created: by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from __future__ import unicode_literals

from django.db import models
from django.utils.translation import ugettext_lazy as _
from django.utils.encoding import python_2_unicode_compatible
from secure_js_login.utils.base_models import UpdateTimeBaseModel


class CountManager(models.Manager):
    def __init__(self, attr_name, *args, **kwargs):
        self.attr_name = attr_name
        super(CountManager, self).__init__(*args, **kwargs)

    def increase_or_add(self, value):
        kwargs = {
            "%s__exact" % self.attr_name: value,
            "defaults": {self.attr_name: value}
        }
        obj, created = self.get_or_create(**kwargs)
        if not created:
            obj.count += 1
            obj.save()
        return obj


@python_2_unicode_compatible
class HonypotUsername(models.Model):
    username = models.CharField(db_index=True, max_length=30)
    count = models.PositiveIntegerField(default=1,
        help_text=_("Number of use of this username.")
    )
    objects = CountManager("username")
    def __str__(self):
        return u"%s (count: %i)" % (self.username, self.count)
    class Meta:
        ordering = ('-count',)


@python_2_unicode_compatible
class HonypotPassword(models.Model):
    password = models.CharField(db_index=True, max_length=128)
    count = models.PositiveIntegerField(default=1,
        help_text=_("Number of use of this password.")
    )
    objects = CountManager("password")
    def __str__(self):
        return u"%s (count: %i)" % (self.password, self.count)
    class Meta:
        ordering = ('-count',)


@python_2_unicode_compatible
class HonypotIP(models.Model):
    ip_address = models.IPAddressField(db_index=True)
    count = models.PositiveIntegerField(default=1,
        help_text=_("Number of logins from this remote IP address.")
    )
    objects = CountManager("ip_address")
    def __str__(self):
        return u"%s (count: %i)" % (self.ip_address, self.count)
    class Meta:
        ordering = ('-count',)


class HonypotAuthManager(models.Manager):
    def add(self, request, username, password):
        ip_address = request.META["REMOTE_ADDR"]
        ip_address_obj = HonypotIP.objects.increase_or_add(ip_address)
        username_obj = HonypotUsername.objects.increase_or_add(username)
        password_obj = HonypotPassword.objects.increase_or_add(password)

        obj, created = self.get_or_create(
            username__exact=username_obj,
            password__exact=password_obj,
            ip_address__exact=ip_address_obj,
            defaults={
                "username":username_obj,
                "password":password_obj,
                "ip_address":ip_address_obj,
            }
        )
        if not created:
            obj.count += 1
            obj.save()
        return obj


@python_2_unicode_compatible
class HonypotAuth(UpdateTimeBaseModel):
    """
    inherited attributes from UpdateTimeBaseModel:
        createtime     -> datetime of creation
        lastupdatetime -> datetime of the last change
    """
    objects = HonypotAuthManager()

    username = models.ForeignKey(HonypotUsername)
    password = models.ForeignKey(HonypotPassword)
    ip_address = models.ForeignKey(HonypotIP)
    count = models.PositiveIntegerField(default=1,
        help_text=_("Number of usage this username/password from the same remote IP address.")
    )

    def __str__(self):
        return u"honypot login from %s [%s/%s] (count: %i)" % (
            self.ip_address, self.username, self.password, self.count
        )

    class Meta:
        ordering = ('-lastupdatetime',)
