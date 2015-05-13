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
from django.contrib.auth import get_user_model

from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import ObjectDoesNotExist
from secure_js_login.models import UserProfile
from secure_js_login.signals import secure_js_login_failed
from secure_js_login.exceptions import SecureJSLoginError
from secure_js_login.utils import crypt


log = logging.getLogger("secure_js_login")


class SecureLoginAuthBackend(ModelBackend):
    """
    Used for PyLucid JS-SHA-Login.
    Check challenge and limit access to sites.
    """
    def authenticate(self, username=None, secure_password=None, server_challenge=None):
        # log.debug("authenticate with SecureLoginAuthBackend")
        # log.debug("Check with: %r" % repr(kwargs))

        UserModel = get_user_model()
        try:
            user = UserModel._default_manager.get_by_natural_key(username)
        except UserModel.DoesNotExist as err:
            secure_js_login_failed.send(
                sender=self.__class__,
                reason="User %r not exists: %s" % (username, err)
            )
            return

        try:
            user_profile = UserProfile.objects.get_user_profile(user)
        except UserProfile.DoesNotExist as err:
            secure_js_login_failed.send(
                sender=self.__class__,
                reason="Profile for user %r doesn't exists: %s" % (user.username, err)
            )
            return

        # log.debug("Call crypt.check_secure_js_login with: %s", repr(locals()))
        try:
            crypt.check_secure_js_login(
                secure_password=secure_password,
                encrypted_part=user_profile.encrypted_part,
                server_challenge=server_challenge,
            )
        except SecureJSLoginError as err:
            secure_js_login_failed.send(sender=self.__class__, reason="%s" % err)
        else:
            # log.debug("Check ok!")
            user.previous_login = user.last_login # Save for: secure_js_login.views.display_login_info()
            return user