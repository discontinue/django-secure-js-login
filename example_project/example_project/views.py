# coding: utf-8

"""
    Secure JavaScript Login
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyleft: 2007-2015 by the secure-js-login team, see AUTHORS for more details.
    :created: by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from __future__ import unicode_literals
from django.contrib import messages

from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.conf import settings

def index(request):
    return render(request, "example_project/index.html", {
        # New in django 1.8: To see the "user-tools" bar with logout link
        "has_permission": request.user.is_active
    })

def debug_on(request):
    messages.info(request, "Set: settings.DEBUG=True")
    settings._wrapped.DEBUG=True
    return HttpResponseRedirect("/")

def debug_off(request):
    messages.info(request, "Set: settings.DEBUG=False")
    settings._wrapped.DEBUG=False
    return HttpResponseRedirect("/")

# def create_test_user(request):
#     create_superuser()