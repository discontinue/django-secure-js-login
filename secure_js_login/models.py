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
from django.contrib.auth.models import User
from django.db import models
from django.db.models import signals
from django.contrib.auth import get_user_model
from django.utils.encoding import python_2_unicode_compatible

from secure_js_login.utils import crypt
from secure_js_login import settings as app_settings
from secure_js_login.utils.base_models import UpdateTimeBaseModel


log = logging.getLogger("secure_js_login")


# used in auth views for simple check if client-nonce used in the past
# Exist here in models, because it's accessible in other modules, too.
# This doesn't work if its defined in views.py
CNONCE_CACHE = {}


class UserProfileManager(models.Manager):
    def get_user_profile(self, user):
        assert isinstance(user, get_user_model())
        user_profile = self.get_queryset().get(user=user)
        # log.debug("User profile: %r for user %r" % (user_profile, user))
        return user_profile



@python_2_unicode_compatible
class UserProfile(UpdateTimeBaseModel):
    """
    Stores additional information about PyLucid users
    http://docs.djangoproject.com/en/dev/topics/auth/#storing-additional-information-about-users

    Created via post_save signal, if a new user created.

    inherited attributes from UpdateTimeBaseModel:
        createtime     -> datetime of creation
        lastupdatetime -> datetime of the last change
    """
    objects = UserProfileManager()

    user = models.OneToOneField(settings.AUTH_USER_MODEL)

    init_pbkdf2_salt = models.CharField(max_length=256,
        help_text="initial salt for PBKDF2 password hash"
    )
    encrypted_part = models.CharField(max_length=256,
        help_text="XOR encrypted PBKDF2 salted checksum"
    )

    def set_secure_login_data(self, password):
        """
        Create a XOR encrypted PBKDF2 salted checksum from a plaintext password.
        """
        init_pbkdf2_salt, encrypted_part = crypt.salt_hash_from_plaintext(password)
        # log.debug("set init_pbkdf2_salt=%r and encrypted_part=%r", init_pbkdf2_salt, encrypted_part)
        self.init_pbkdf2_salt = init_pbkdf2_salt
        self.encrypted_part = encrypted_part
        # log.info("Secure login data saved for user '%s'.", self.user)

    # def save(self, *args, **kwargs):
    #     super(UserProfile, self).save(*args, **kwargs)
    #     assert len(self.init_pbkdf2_salt)==app_settings.PBKDF2_SALT_LENGTH
    #     assert len(self.encrypted_part)==crypt.PBKDF2_HALF_HEX_LENGTH

    def __str__(self):
        return "user %r" % self.user.username

    class Meta:
        ordering = ("user",)

#______________________________________________________________________________
# Create user profile via signals
#
# def create_user_profile(sender, **kwargs):
#     """ signal handler: creating user profile, after a new user created. """
#     user = kwargs["instance"]
#     userprofile, created = UserProfile.objects.get_or_create(user=user)
#     if created:
#         # log.info("UserProfile entry for user '%s' created.", user)
#
# signals.post_save.connect(create_user_profile, sender=settings.AUTH_USER_MODEL)


#______________________________________________________________________________



if app_settings.AUTO_CREATE_PASSWORD_HASH:
    """
    We make a Monkey-Patch and change the method set_password() from
    the model class django.contrib.auth.models.User.
    We need the raw plaintext password, this is IMHO not available via signals.

    FIXME:
        * How to not use a Monkey-Patch?!?
        * How to use get_user_model() here?!?
    """
    # Save the original method
    orig_set_password = User.set_password


    def set_password(user, raw_password):
        # log.debug("set plaintext password for user %r", user.username)

        if user.id == None:
            # It is a new user. We must save the django user accound first to get a
            # existing user object with a ID and then the JS-SHA-Login Data can assign to it.
            user.save()

        # Use the original method to set the django User password:
        orig_set_password(user, raw_password)

        userprofile, created = UserProfile.objects.get_or_create(user=user)
        # if created:
            # log.info("UserProfile entry for user '%s' created.", user)

        userprofile.set_secure_login_data(raw_password)
        userprofile.save()


    # log.debug("Activate monkey-patch 'User.set_password'")
    # replace the method
    User.set_password = set_password
