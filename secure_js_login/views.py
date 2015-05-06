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

from __future__ import unicode_literals
import logging
import pprint

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


# DEBUG is usefull for debugging. It send always the same challenge "12345"
# DEBUG = True
DEBUG = False
# IMPORTANT: Should really only use for debugging!!!
if DEBUG:
    import warnings
    warnings.warn("Debug mode in auth plugin is on! print statements would be used!")


def _get_server_challenge(request):
    """ create a new server_challenge, add it to session and return it"""
    if DEBUG:
        crypt.seed_generator.DEBUG=True # Generate always the same seed for tests

    # Create a new random salt value for the password server_challenge:
    server_challenge = crypt.seed_generator(app_settings.RANDOM_CHALLENGE_LENGTH)

    crypt.seed_generator.DEBUG=False
    if DEBUG:
        log.critical("use DEBUG server_challenge: %r", server_challenge)

    # For later comparing with form data
    request.session["server_challenge"] = server_challenge
    log.debug("Save new server_challenge %r to session.", server_challenge)

    return server_challenge



def _wrong_login(request, user=None):
    """ username or password is wrong. """
    log.error("Login error, username: %r", user.username)

    # create a new challenge and add it to session
    challenge = _get_server_challenge(request)

    error_msg = _("Wrong username/password.")
    response = "%s;%s" % (challenge, error_msg)
    return HttpResponse(response, content_type="text/plain")



@csrf_protect
def secure_auth(request, next="/"):
    """
    login the user with username and sha values.
    """
    log.debug("secure_auth() requested with: %s", repr(request.POST))

    _NORMAL_ERROR_MSG = "_secure_auth() error"

    form = SecureLoginForm(request.POST)
    if not form.is_valid():
        log.debug("ShaLoginForm is not valid: %s", repr(form.errors))
        return HttpResponseBadRequest()
    else:
        sha_a, sha_b, cnonce = form.cleaned_data["password"]
        log.debug("SHA-A: %r", sha_a)
        log.debug("SHA-B: %r", sha_b)
        log.debug("CNONCE: %r", cnonce)

    try:
        challenge = request.session.pop("challenge")
    except KeyError as err:
        log.debug("Can't get 'challenge' from session: %s", err)
        return HttpResponseBadRequest()
    else:
        log.debug("Challenge from session: %r", challenge)

    try:
        user1, user_profile = form.get_user_and_profile()
    except WrongUserError as err:
        log.debug("Can't get user and user profile: %s", err)
        return _wrong_login(request)

    sha_checksum = user_profile.sha_login_checksum

    # Simple check if 'nonce' from client used in the past.
    # Limitations:
    #  - Works only when run in a long-term server process, so not in CGI ;)
    #  - dict vary if more than one server process runs (one dict in one process)
    if cnonce in CNONCE_CACHE:
        log.error("Client-nonce '%s' used in the past!", cnonce)
        return HttpResponseBadRequest()
    CNONCE_CACHE[cnonce] = None

    log.debug("authenticate %r with: challenge: %r, sha_checksum: %r, sha_a: %r, sha_b: %r, cnonce: %r" % (
        user1, challenge, sha_checksum, sha_a, sha_b, cnonce
        )
    )

    try:
        # authenticate with:
        # pylucid.system.auth_backends.SiteSHALoginAuthBackend
        user2 = auth.authenticate(
            user=user1, challenge=challenge,
            sha_a=sha_a, sha_b=sha_b,
            sha_checksum=sha_checksum,
            loop_count=app_settings.LOOP_COUNT, cnonce=cnonce
        )
    except Exception as err: # e.g. low level error from crypt
        log.error("auth.authenticate() failed: %s", err)
        return _wrong_login(request, user1)

    if user2 is None:
        log.error("auth.authenticate() failed. (must be a wrong password)")
        return _wrong_login(request, user1)
    else:
        log.debug("Authentication ok, log in the user")
        # everything is ok -> log the user in and display "last login" page message
        last_login = user2.last_login
        auth.login(request, user2)
        message = render_to_string('secure_js_login/login_info.html', {"last_login":last_login})
        messages.success(request, message)
        return HttpResponse("OK", content_type="text/plain")


@csrf_protect
def get_salt(request):
    """
    return the user password salt.
    If the user doesn't exist return a pseudo salt.
    """
    if not "username" in request.POST:
        log.error("No 'username' in POST data?!?")
        return HttpResponseBadRequest()

    send_pseudo_salt=True

    form = UsernameForm(request.POST)
    if form.is_valid():
        username = form.cleaned_data["username"]
        try:
            user, user_profile = form.get_user_and_profile()
        except ObjectDoesNotExist as err:
            msg = "Error getting user + profile: %s" % err
            log.error(msg)
        else:
            send_pseudo_salt=False
    else:
        username = request.POST["username"]

    if not send_pseudo_salt: # Form not valid or wrong username
        init_pbkdf2_salt = user_profile.init_pbkdf2_salt
        if not init_pbkdf2_salt:
            msg="No init_pbkdf2_salt set in user profile!"
            log.error(msg)
            send_pseudo_salt=True
        elif len(init_pbkdf2_salt)!=app_settings.PBKDF2_SALT_LENGTH:
            msg = "Salt for user %r has wrong length: %r" % (request.POST["username"], init_pbkdf2_salt)
            log.error(msg)
            send_pseudo_salt=True

    if send_pseudo_salt:
        log.debug("Use pseudo salt!!!")
        init_pbkdf2_salt = crypt.get_pseudo_salt(app_settings.PBKDF2_SALT_LENGTH, username)

    # log.debug("send init_pbkdf2_salt %r to client.", init_pbkdf2_salt)
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


def secure_js_login(request):
    """
    FIXME:
        * Don't send a inserted password back, if form is not valid
    """
    try:
        request.old_server_challenge = request.session["server_challenge"]
        log.debug("Use old server_challenge: %r", request.old_server_challenge)
    except KeyError:
        request.old_server_challenge = None

    # create a new challenge and add it to session
    server_challenge = _get_server_challenge(request)

    # if request.method == 'GET':
    #     # create a new challenge and add it to session
    #     server_challenge = _get_server_challenge(request)
    # elif request.method == 'POST':
    #     if not "server_challenge" in request.session:
    #         # Previous login failed and form will send again with error message
    #         server_challenge = _get_server_challenge(request)
    #     else:
    #         server_challenge=None
    #         # server_challenge = request.session["server_challenge"]
    #         # log.debug("Use old server_challenge: %r", server_challenge)
    #
    # #
    # #     # log.debug("secure_js_login() POST data:\n%s", pprint.pformat(request.POST))
    # #     server_challenge = None # Will be get from session in secureLoginForm()
    # else:
    #     return HttpResponseBadRequest("Wrong request.method!")

    return login(request,
        template_name="secure_js_login/sha_form.html",
        # redirect_field_name=REDIRECT_FIELD_NAME,
        authentication_form=SecureLoginForm,
        current_app="secure_js_login",
        extra_context={
            "DEBUG": "true" if settings.DEBUG else "false",
            "challenge": server_challenge,
            "CHALLENGE_LENGTH": app_settings.RANDOM_CHALLENGE_LENGTH,
            "NONCE_LENGTH": app_settings.CLIENT_NONCE_LENGTH,
            "SALT_LENGTH": app_settings.PBKDF2_SALT_LENGTH,
            "PBKDF2_BYTE_LENGTH": app_settings.PBKDF2_BYTE_LENGTH,
            "ITERATIONS": app_settings.ITERATIONS2,
            "CSRF_COOKIE_NAME": settings.CSRF_COOKIE_NAME,
        }
    )


def _logout_view(request):
    """ Logout the current user. """
    auth.logout(request)
    messages.success(request, _("You are logged out!"))
    next_url = request.path
    return HttpResponseRedirect(next_url)





