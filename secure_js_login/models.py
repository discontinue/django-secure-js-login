# coding: utf-8

"""
    pylucid.models
    ~~~~~~~~~~~~~~

    :copyleft: 2009-2015 by the PyLucid team, see AUTHORS for more details.
    :license: GNU GPL v3 or above, see LICENSE for more details.
"""

from __future__ import unicode_literals

import logging

from django.conf import settings

from django.db import models
from django.db.models import signals
from django.contrib.auth.models import User

# http://code.google.com/p/django-tools/
from django_tools.models import UpdateInfoBaseModel

from secure_js_login.utils import crypt
from secure_js_login import settings as app_settings


log = logging.getLogger("secure_js_login")


# used in auth views for simple check if client-nonce used in the past
# Exist here in models, because it's accessible in other modules, too.
# This doesn't work if its defined in views.py
CNONCE_CACHE = {}


class UserProfile(UpdateInfoBaseModel):
    """
    Stores additional information about PyLucid users
    http://docs.djangoproject.com/en/dev/topics/auth/#storing-additional-information-about-users

    Created via post_save signal, if a new user created.

    inherited attributes from UpdateInfoBaseModel:
        createtime     -> datetime of creation
        lastupdatetime -> datetime of the last change
        createby       -> ForeignKey to user who creaded this entry
        lastupdateby   -> ForeignKey to user who has edited this entry
    """
    user = models.OneToOneField(settings.AUTH_USER_MODEL)

    sha_login_checksum = models.CharField(max_length=192,
        help_text="Checksum for PyLucid JS-SHA-Login"
    )
    sha_login_salt = models.CharField(max_length=crypt.SALT_LEN,
        help_text="Salt value for PyLucid JS-SHA-Login"
    )

    def set_sha_login_password(self, raw_password):
        """
        create salt+checksum for JS-SHA-Login.
        see also: http://www.pylucid.org/_goto/8/JS-SHA-Login/
        """
        raw_password = str(raw_password)
        salt, sha_checksum = crypt.make_sha_checksum2(raw_password)
        self.sha_login_salt = salt
        self.sha_login_checksum = sha_checksum
        log.info("SHA Login salt+checksum set for user '%s'.", self.user)

    def __unicode__(self):
        sites = self.sites.values_list('name', flat=True)
        return u"UserProfile for user '%s' (on sites: %r)" % (self.user.username, sites)

    class Meta:
        ordering = ("user",)

#______________________________________________________________________________
# Create user profile via signals

def create_user_profile(sender, **kwargs):
    """ signal handler: creating user profile, after a new user created. """
    print(sender)
    print(kwargs)
    user = kwargs["instance"]

    userprofile, created = UserProfile.objects.get_or_create(user=user)
    if created:
        log.info("UserProfile entry for user '%s' created.", user)
#
#        if not user.is_superuser: # Info: superuser can automaticly access all sites
#            site = Site.objects.get_current()
#            userprofile.site.add(site)
#            failsafe_message("Add site '%s' to '%s' UserProfile." % (site.name, user))

signals.post_save.connect(create_user_profile, sender=settings.AUTH_USER_MODEL)


#______________________________________________________________________________



if app_settings.AUTO_CREATE_PASSWORD_HASH:
    """
    We make a Monkey-Patch and change the method set_password() from
    the model class django.contrib.auth.models.User.
    We need the raw plaintext password, this is IMHO not available via signals.
    """
    # Save the original method
    orig_set_password = User.set_password


    def set_password(user, raw_password):
        log.debug("set password %r fro user %r", user, raw_password)

        if user.id == None:
            # It is a new user. We must save the django user accound first to get a
            # existing user object with a ID and then the JS-SHA-Login Data can assign to it.
            user.save()

        # Use the original method to set the django User password:
        orig_set_password(user, raw_password)

        userprofile, created = UserProfile.objects.get_or_create(user=user)
        if created:
            log.info("UserProfile entry for user '%s' created.", user)

        # Save the password for the JS-SHA-Login:
        userprofile.set_sha_login_password(raw_password)
        userprofile.save()


    log.debug("Activate monkey-patch 'User.set_password'")
    # replace the method
    User.set_password = set_password
