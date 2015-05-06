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
try:
    from django.utils.timezone import now
except ImportError:
    from datetime import datetime
    now = datetime.now

from django_tools.middlewares import ThreadLocal


class UpdateTimeBaseModel(models.Model):
    """
    Base model to automatically set:
     * createtime
     * lastupdatetime

    We doesn't used auto_now_add and auto_now here, because they have the odd side effect
    see also:
    https://github.com/jezdez/django-dbtemplates/commit/2f27327bebe7f2e7b33e5cfb0db517f53a1b9701#commitcomment-1396126
    """
    createtime = models.DateTimeField(default=now, editable=False, help_text="Create time")
    lastupdatetime = models.DateTimeField(default=now, editable=False, help_text="Time of the last change.")

    def save(self, *args, **kwargs):
        self.lastupdatetime = now()
        return super(UpdateTimeBaseModel, self).save(*args, **kwargs)

    class Meta:
        abstract = True