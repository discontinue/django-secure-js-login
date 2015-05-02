# coding: utf-8


"""
    PyLucid JS-SHA-Login
    ~~~~~~~~~~~~~~~~~~~~

    secure JavaScript SHA-1 AJAX Login
    more info:
        http://www.pylucid.org/permalink/42/secure-login-without-https

    :copyleft: 2007-2015 by the PyLucid team, see AUTHORS for more details.
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from django.contrib import auth, messages
from django.template import RequestContext
from django.utils.translation import ugettext as _
from django.shortcuts import render_to_response
from django.views.decorators.csrf import csrf_protect, csrf_exempt

from honypot_login.forms import HoneypotForm
from honypot_login.models import HonypotAuth


@csrf_exempt
def login_honeypot(request):
    """
    A login honypot.
    """
    faked_login_error = False
    if request.method == 'POST':
        form = HoneypotForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data["username"]
            password = form.cleaned_data["password"]
            HonypotAuth.objects.add(request, username, password)
            messages.error(request, _("username/password wrong."))
            form = HoneypotForm(initial={"username": username})
            faked_login_error = True
    else:
        form = HoneypotForm()
    context = {
        "form": form,
        "form_url": request.path,
        "page_robots": "noindex,nofollow",
    }

    response = render_to_response("auth/login_honeypot.html", context, context_instance=RequestContext(request))
    if faked_login_error:
        response.status_code = 401
    return response
