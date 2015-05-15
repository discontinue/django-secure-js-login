# coding: utf-8

"""
    Secure JavaScript Login
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyleft: 2007-2015 by the secure-js-login team, see AUTHORS for more details.
    :created: by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from __future__ import unicode_literals

import logging

from django.conf import settings
from django.contrib import messages
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseBadRequest
from django.template.loader import render_to_string
from django.utils.translation import ugettext as _
from django.views.decorators.csrf import csrf_protect, csrf_exempt, ensure_csrf_cookie
from django.contrib.auth.views import login
from django.contrib.auth.signals import user_logged_in

# auth own stuff
from secure_js_login.decorators import TimingAttackPreventer
from secure_js_login.signals import secure_js_login_failed
from secure_js_login.utils import crypt
from secure_js_login.forms import UsernameForm, SecureLoginForm
from secure_js_login import settings as app_settings


log = logging.getLogger("secure_js_login")

SERVER_CHALLENGE_KEY = "server_challenge"


# @log_view
@TimingAttackPreventer()
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

    try:
        request.server_challenge = request.session[SERVER_CHALLENGE_KEY]
    except KeyError as err:
        # log.error("Can't get challenge from session: %s", err)
        return HttpResponseBadRequest()
    # log.debug("old challenge: %r", request.server_challenge)

    send_pseudo_salt=True

    form = UsernameForm(request, data=request.POST)
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
        # log.error("Salt Form is not valid: %r", form.errors)

    if send_pseudo_salt:
        # log.debug("\nUse pseudo salt!!!")
        init_pbkdf2_salt = crypt.get_pseudo_salt(app_settings.PBKDF2_SALT_LENGTH, username)

    response = HttpResponse(init_pbkdf2_salt, content_type="text/plain")

    if not send_pseudo_salt:
        response.add_duration=True # collect duration time in @TimingAttackPreventer

    # log.debug("\nsend init_pbkdf2_salt %r to client.", init_pbkdf2_salt)
    return response


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
@TimingAttackPreventer()
@csrf_protect
def secure_js_login(request):

    # Create a new random salt value for the password server_challenge:
    new_server_challenge = crypt.seed_generator(app_settings.RANDOM_CHALLENGE_LENGTH)

    if request.method == "POST":
        # POST -> Compare login data
        try:
            request.server_challenge = request.session.pop(SERVER_CHALLENGE_KEY)
        except KeyError:
            secure_js_login_failed.send(sender=secure_js_login,
                reason="Can't get '%s' from session!" % SERVER_CHALLENGE_KEY)
            return HttpResponseBadRequest()
        # log.debug("old challenge: %r", request.server_challenge)
    else:
        # GET: request login form
        request.session[SERVER_CHALLENGE_KEY] = new_server_challenge
        # log.debug("Save challenge %r for next POST", new_server_challenge)

    try:
        response = login(request,
            template_name="secure_js_login/secure_js_login.html",
            # redirect_field_name=REDIRECT_FIELD_NAME,
            authentication_form=SecureLoginForm,
            current_app="secure_js_login",
            extra_context={
                "title": "Secure-JS-Login",
                "DEBUG": "true" if settings.DEBUG else "false",
                "challenge": new_server_challenge,
                "CHALLENGE_LENGTH": app_settings.RANDOM_CHALLENGE_LENGTH,
                "NONCE_LENGTH": app_settings.CLIENT_NONCE_LENGTH,
                "SALT_LENGTH": app_settings.PBKDF2_SALT_LENGTH,
                "PBKDF2_BYTE_LENGTH": app_settings.PBKDF2_BYTE_LENGTH,
                "ITERATIONS1": app_settings.ITERATIONS1,
                "ITERATIONS2": app_settings.ITERATIONS2,
                "CSRF_COOKIE_NAME": settings.CSRF_COOKIE_NAME,
            }
        )
    except Exception as err:
        log.debug("Error: %s" % err)
        raise

    if request.user.is_authenticated():
        if isinstance(response, HttpResponseRedirect):
            # Successfully logged in
            response.add_duration=True # collect duration time in @TimingAttackPreventer
    elif request.method == "POST":
            # log.debug("Logged in failed: Save new challenge to session")
            request.session[SERVER_CHALLENGE_KEY] = new_server_challenge

    return response






