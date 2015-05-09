# coding: utf-8

"""
    Secure JavaScript Login
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyleft: 2007-2015 by the secure-js-login team, see AUTHORS for more details.
    :created: by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from __future__ import unicode_literals
import functools

import logging
import pprint
import traceback
import sys

from django.conf import settings
from django.contrib import auth, messages
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseBadRequest
from django.template.loader import render_to_string
from django.utils.translation import ugettext as _
from django.views.decorators.csrf import csrf_protect, csrf_exempt, ensure_csrf_cookie
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.views import login
from django.contrib.auth.signals import user_logged_in

# auth own stuff
from secure_js_login.models import CNONCE_CACHE, UserProfile
from secure_js_login.utils import crypt
from secure_js_login.forms import WrongUserError, UsernameForm, SecureLoginForm
from secure_js_login import settings as app_settings


log = logging.getLogger("secure_js_login")

def _get_server_challenge(request):
    """ create a new server_challenge, add it to session and return it"""
    # Create a new random salt value for the password server_challenge:
    server_challenge = crypt.seed_generator(app_settings.RANDOM_CHALLENGE_LENGTH)

    # For later comparing with form data
    request.session["server_challenge"] = server_challenge
    # log.debug("Save new server_challenge %r to session.", server_challenge)

    return server_challenge


def log_view(func):
    """
    Helpful while debugging Selenium unittests.
    e.g.: server response an error in AJAX requests
    """
    @functools.wraps(func)
    def view_logger(*args, **kwargs):
        log.debug("call view %r", func.__name__)
        try:
            response = func(*args, **kwargs)
        except Exception as err:
            log.error("view exception: %s", err)
            traceback.print_exc(file=sys.stderr)
            raise

        log.debug("Response: %s", response)
        return response
    return view_logger


# @log_view
@csrf_protect
def get_salt(request):
    """
    return the user password salt.
    If the user doesn't exist return a pseudo salt.
    """
    try:
        username = request.POST["username"]
    except KeyError:
        # log.error("No 'username' in POST data?!?")
        return HttpResponseBadRequest()

    send_pseudo_salt=True

    form = UsernameForm(data=request.POST)
    if form.is_valid():
        send_pseudo_salt=False

        user_profile = form.user_profile
        init_pbkdf2_salt = user_profile.init_pbkdf2_salt
        if not init_pbkdf2_salt:
            # log.error("No init_pbkdf2_salt set in user profile!")
            send_pseudo_salt=True

        if len(init_pbkdf2_salt)!=app_settings.PBKDF2_SALT_LENGTH:
            # log.error("Salt for user %r has wrong length: %r" % (request.POST["username"], init_pbkdf2_salt))
            send_pseudo_salt=True
    # else:
    #     log.error("Salt Form is not valid: %r", form.errors)

    if send_pseudo_salt:
        # log.debug("\nUse pseudo salt!!!")
        init_pbkdf2_salt = crypt.get_pseudo_salt(app_settings.PBKDF2_SALT_LENGTH, username)

    # log.debug("\nsend init_pbkdf2_salt %r to client.", init_pbkdf2_salt)
    return HttpResponse(init_pbkdf2_salt, content_type="text/plain")


def display_login_info(sender, user, request, **kwargs):
    """
    Create a message, after login.

    Because this signal receiver will be called **after** auth.models.update_last_login(), the
    user.last_login information was updated before!

    As a work-a-round, we add **user.previous_login** in forms.SecureLoginForm.clean()
    """
    if not hasattr(user, "previous_login"):
        # e.g. normal django admin login page was used
        return
    message = render_to_string('secure_js_login/login_info.html', {"last_login":user.previous_login})
    messages.success(request, message)

user_logged_in.connect(display_login_info)


# @log_view
@csrf_protect
def secure_js_login(request):
    """
    FIXME:
        * Don't send a inserted password back, if form is not valid
    """
    try:
        request.old_server_challenge = request.session["server_challenge"]
        # log.debug("Use old server_challenge: %r", request.old_server_challenge)
    except KeyError:
        request.old_server_challenge = None

    # create a new challenge and add it to session
    server_challenge = _get_server_challenge(request)

    return login(request,
        template_name="secure_js_login/secure_js_login.html",
        # redirect_field_name=REDIRECT_FIELD_NAME,
        authentication_form=SecureLoginForm,
        current_app="secure_js_login",
        extra_context={
            "title": "Secure-JS-Login",
            "DEBUG": "true" if settings.DEBUG else "false",
            "challenge": server_challenge,
            "CHALLENGE_LENGTH": app_settings.RANDOM_CHALLENGE_LENGTH,
            "NONCE_LENGTH": app_settings.CLIENT_NONCE_LENGTH,
            "SALT_LENGTH": app_settings.PBKDF2_SALT_LENGTH,
            "PBKDF2_BYTE_LENGTH": app_settings.PBKDF2_BYTE_LENGTH,
            "ITERATIONS1": app_settings.ITERATIONS1,
            "ITERATIONS2": app_settings.ITERATIONS2,
            "CSRF_COOKIE_NAME": settings.CSRF_COOKIE_NAME,
        }
    )






