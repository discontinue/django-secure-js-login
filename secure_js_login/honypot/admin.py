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

from secure_js_login.honypot.models import HonypotAuth,\
    HonypotUsername, HonypotPassword, HonypotIP


class HonypotAuthAdmin(admin.ModelAdmin):   
    list_display = ("id", "username", "password", "ip_address", "count", "lastupdatetime")
    list_display_links = ("username", "password", "ip_address")
    list_filter = ("ip_address",)
    date_hierarchy = 'lastupdatetime'
    search_fields = ("username", "password")
admin.site.register(HonypotAuth, HonypotAuthAdmin)


class HonypotUsernameAdmin(admin.ModelAdmin):   
    list_display = ("id", "username", "count")
    list_display_links = ("username",)
    search_fields = ("username",)
admin.site.register(HonypotUsername, HonypotUsernameAdmin)


class HonypotPasswordAdmin(admin.ModelAdmin):   
    list_display = ("id", "password", "count")
    list_display_links = ("password",)
    search_fields = ("password",)
admin.site.register(HonypotPassword, HonypotPasswordAdmin)


class HonypotIPAdmin(admin.ModelAdmin):   
    list_display = ("id", "ip_address", "count")
    list_display_links = ("ip_address",)
    search_fields = ("ip_address",)
admin.site.register(HonypotIP, HonypotIPAdmin)

