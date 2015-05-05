# coding: utf-8

"""
    PyLucid auth backends
    ~~~~~~~~~~~~~~~~~~~~~
    
    Limit user access to sites via UserProfile

    SiteAuthBackend:
        for normal username/plaintext password
        
    SiteSHALoginAuthBackend:
        for JS-SHA1-Login

    :copyleft: 2009-2015 by the PyLucid team, see AUTHORS for more details.
    :license: GNU GPL v3 or above, see LICENSE for more details.
"""

import logging

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User
from django.contrib.sites.models import Site
from django.core.exceptions import ObjectDoesNotExist
from django.utils.translation import ugettext as _
from secure_js_login.models import UserProfile

from secure_js_login.utils import crypt
from secure_js_login import settings as app_settings

log = logging.getLogger("secure_js_login")


#LOCAL_DEBUG = True
LOCAL_DEBUG = False

if LOCAL_DEBUG:
    log.critical("Debug mode in auth_backends is on!")



class SecureLoginAuthBackend(ModelBackend):
    """
    Used for PyLucid JS-SHA-Login.
    Check challenge and limit access to sites.
    """
    def authenticate(self, username=None, **kwargs):
        log.debug("authenticate with SecureLoginAuthBackend")

        if username is None:
            log.error("No username given.")
            return

        if tuple(kwargs.keys()) == ("password",):
            log.debug("normal auth, e.g.: normal django admin login pages was used")
            return

        try:
            user, user_profile = UserProfile.objects.get_user_profile(username)
        except ObjectDoesNotExist as err:
            msg = "Error getting user + profile: %s" % err
            log.error(msg)
            if LOCAL_DEBUG:
                raise
            return

        kwargs["sha_checksum"] = user_profile.sha_login_checksum
        kwargs["loop_count"] = app_settings.LOOP_COUNT

        log.debug("Check with: %r" % repr(kwargs))

        try:
            check = crypt.check_js_sha_checksum(**kwargs)
        except crypt.CryptError as err:
            # Wrong password
            log.error("User %r check_js_sha_checksum error: %s" % (user, err))
            if LOCAL_DEBUG:
                raise
            return

        if check != True:
            # Wrong password
            log.error("User %r check_js_sha_checksum failed." % user)
            return

        log.info("User ok!")
        return user