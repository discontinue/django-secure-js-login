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
from django.template import RequestContext
from django.utils.translation import ugettext as _
from django.shortcuts import render_to_response
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import get_user_model

from secure_js_login.honypot.forms import HoneypotForm
from secure_js_login.honypot.models import HonypotAuth



@csrf_exempt
def login_honeypot(request):
    """
    A login honypot.
    """
    status_code = None
    if request.method == 'POST':
        form = HoneypotForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data["username"]
            password = form.cleaned_data["password"]

            # Don't store password from existing users:
            if request.user.is_authenticated(): # Logged in user used the honypot?!?
                password="***"
            else:
                user_model = get_user_model()
                existing_user = user_model.objects.filter(username=username).exists()
                if existing_user:
                    password="***"

            HonypotAuth.objects.add(request, username, password)

            # Send a "errored" form back, that looks like the normal form
            form = HoneypotForm(request.POST, raise_error=True)
            status_code = 401 # Unauthorized
    else:
        form = HoneypotForm()
    context = {
        "form": form,
        "form_url": request.path,
    }

    response = render_to_response(
        "admin/login.html",
        context, context_instance=RequestContext(request)
    )
    if status_code is not None:
        response.status_code = status_code
    return response
