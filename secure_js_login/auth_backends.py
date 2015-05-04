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
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User
from django.contrib.sites.models import Site
from django.utils.translation import ugettext as _

from secure_js_login.utils import crypt


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
    def authenticate(self, user=None, challenge=None, sha_a=None, sha_b=None, sha_checksum=None, loop_count=None, cnonce=None):
        log.debug("authenticate with SecureLoginAuthBackend")

        if user == None: # Nothing to do: Normal auth?
            return

        try:
            check = crypt.check_js_sha_checksum(challenge, sha_a, sha_b, sha_checksum, loop_count, cnonce)
        except crypt.SaltHashError as err:
            # Wrong password
            log.error("User %r check_js_sha_checksum error: %s" % (user, err))
            if LOCAL_DEBUG:
                raise
            return

        if check != True:
            # Wrong password
            log.error("User %r check_js_sha_checksum failed." % user)
            return

        return user