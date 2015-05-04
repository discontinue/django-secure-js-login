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

from django.conf import settings
from django.contrib import auth, messages
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseBadRequest
from django.template import RequestContext
from django.template.loader import render_to_string
from django.utils.translation import ugettext as _
from django.shortcuts import render_to_response
from django.core import urlresolvers
from django.views.decorators.csrf import csrf_protect, csrf_exempt, ensure_csrf_cookie

# auth own stuff
from secure_js_login.models import CNONCE_CACHE
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


def _get_challenge(request):
    """ create a new challenge, add it to session and return it"""
    if DEBUG:
        challenge = "12345"
        log.critical("use DEBUG challenge: %r", challenge)
    else:
        # Create a new random salt value for the password challenge:
        challenge = crypt.seed_generator()

    # For later comparing with form data
    request.session["challenge"] = challenge
    log.debug("Save new challenge %r to session.", challenge)

    return challenge





def lucidTag(request):
    """
    Create login/logout link
    example: {% lucidTag auth %}
    """
    context = {
        "honypot_url": "#top" # Don't use honypot
    }
    if request.user.is_authenticated():
        template_name = "secure_js_login/logout_link.html"
        if hasattr(request.PYLUCID, "pagetree"):
            # We are on a normal cms page -> Dont's change the url
            url = ""
        else:
            # We are in the django admin panel -> Go to root page
            url = "/"
        url += "?auth=logout"
    else:
        if app_settings.USE_HONYPOT:
            try: # Use the first PluginPage instance
                honypot_url = PluginPage.objects.reverse("auth", 'Auth-login_honeypot')
            except urlresolvers.NoReverseMatch as err:
                if settings.RUN_WITH_DEV_SERVER:
                    print("*** Can't get 'Auth-login_honeypot' url: %s" % err)
            else:
                context["honypot_url"] = honypot_url

        if not app_settings.HTTPS_URLS:
            template_name = "secure_js_login/login_link.html"
            url = ""
        else:
            # Use https for login
            template_name = "secure_js_login/login_link_https.html"
            url = "https://%s%s" % (request.get_host(), request.path)

        url += "?auth=login"

    context["url"] = url

    return render_to_string(template_name, context, context_instance=RequestContext(request))


def _wrong_login(request, user=None):
    """ username or password is wrong. """
    log.error("Login error, username: %r", user.username)

    # create a new challenge and add it to session
    challenge = _get_challenge(request)

    error_msg = _("Wrong username/password.")
    response = "%s;%s" % (challenge, error_msg)
    return HttpResponse(response, content_type="text/plain")



@csrf_protect
def secure_auth(request):
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
    If the user doesn't exist or is not active, return a pseudo salt.
    """
    log.debug("get_salt() requested.")

    user_profile = None
    form = UsernameForm(request.POST)
    if form.is_valid():
        try:
            user_profile = form.get_user_profile()
        except WrongUserError as err:
            msg = "can't get userprofile: %s" % err
            log.error(msg)
            if settings.DEBUG:
                messages.error(request, msg)

    if user_profile is None: # Wrong user?
        username = request.POST["username"]
        msg = "Username %r is wrong: %r" % (username, form.errors)
        log.error(msg)
        if settings.DEBUG:
            messages.error(request, msg)
        salt = crypt.get_pseudo_salt(username)
    else:
        salt = user_profile.sha_login_salt
        if len(salt)!=crypt.SALT_LEN:
            msg = "Salt for user %r has wrong length: %r" % (request.POST["username"], salt)
            if settings.DEBUG:
                raise AssertionError(msg)

            log.error(msg)
            salt = crypt.get_pseudo_salt(username)

    log.debug("send salt %r to client.", salt)

    return HttpResponse(salt, content_type="text/plain")


@csrf_protect
@ensure_csrf_cookie
def secure_js_login(request):
    """
    For better JavaScript debugging: Enable settings.DEBUG and request the page
    via GET with: "...?auth=login"
    """
    if DEBUG:
        print("auth debug mode is on!")

    if request.method != 'GET':
        log.error("request method %r wrong, only GET allowed", request.method)
        return HttpResponseBadRequest()

    next_url = request.GET.get("next_url", request.path)

    if "//" in next_url: # FIXME: How to validate this better?
        # Don't redirect to other pages.
        log.error("next url %r seems to be wrong!", next_url)
        return HttpResponseBadRequest()

    form = SecureLoginForm()

    # create a new challenge and add it to session
    challenge = _get_challenge(request)

    try:
        # url from django-authopenid, only available if the urls.py are included
        reset_link = urlresolvers.reverse("auth_password_reset")
    except urlresolvers.NoReverseMatch:
        reset_link = None
        # try:
        #     # DjangoBB glue plugin adds the urls from django-authopenid
        #     reset_link = PluginPage.objects.reverse("djangobb_plugin", "auth_password_reset")
        # except KeyError:
        #     # plugin is not installed
        #     reset_link = None
        # except urlresolvers.NoReverseMatch:
        #     # plugin is installed, but not in used (no PluginPage created)
        #     reset_link = None

    context = {
        "debug": "true" if settings.DEBUG else "false",
        "challenge": challenge,
        "old_salt_len": crypt.OLD_SALT_LEN,
        "salt_len": crypt.SALT_LEN,
        "hash_len": crypt.HASH_LEN,
        "loop_count": app_settings.LOOP_COUNT,
        "next": next_url,
        "form": form,
        "pass_reset_link": reset_link,
        "csrf_cookie_name": settings.CSRF_COOKIE_NAME,
    }
    return render_to_response('secure_js_login/sha_form.html', context, context_instance=RequestContext(request))



def _logout_view(request):
    """ Logout the current user. """
    auth.logout(request)
    messages.success(request, _("You are logged out!"))
    next_url = request.path
    return HttpResponseRedirect(next_url)





