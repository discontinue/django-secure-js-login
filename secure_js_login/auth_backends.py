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

from django.contrib.auth.backends import ModelBackend

from secure_js_login.utils import crypt


log = logging.getLogger("secure_js_login")


class SecureLoginAuthBackend(ModelBackend):
    """
    Used for PyLucid JS-SHA-Login.
    Check challenge and limit access to sites.
    """
    def authenticate(self, username=None, **kwargs):
        # log.debug("authenticate with SecureLoginAuthBackend")

        if username is None:
            # log.error("No username given.")
            return

        if tuple(kwargs.keys()) == ("password",):
            # log.debug("normal auth, e.g.: normal django admin login pages was used")
            return

        user = kwargs.pop("user")

        # log.debug("Check with: %r" % repr(kwargs))
        check = crypt.check_secure_js_login(**kwargs)
        if check == True:
            return user