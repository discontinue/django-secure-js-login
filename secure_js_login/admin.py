# coding: utf-8

"""
    Secure JavaScript Login
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyleft: 2007-2015 by the secure-js-login team, see AUTHORS for more details.
    :created: by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from __future__ import unicode_literals

from django.contrib import admin
from secure_js_login.models import UserProfile


class UserProfileAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "createtime", "lastupdatetime")
    list_display_links = ("id", "user")
    list_filter = ("user",)
    date_hierarchy = 'lastupdatetime'
    search_fields = ("username",)

admin.site.register(UserProfile, UserProfileAdmin)



