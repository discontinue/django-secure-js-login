# coding: utf-8

from django.contrib import admin
from secure_js_login.models import UserProfile


class UserProfileAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "createtime", "lastupdatetime", "createby", "lastupdateby")
    list_display_links = ("id", "user")
    list_filter = ("user", "createby", "lastupdateby")
    date_hierarchy = 'lastupdatetime'
    search_fields = ("username",)

admin.site.register(UserProfile, UserProfileAdmin)



