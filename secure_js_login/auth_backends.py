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

        user = kwargs.pop("user")

        log.debug("Check with: %r" % repr(kwargs))
        check = crypt.check_secure_js_login(**kwargs)
        if check == True:
            return user