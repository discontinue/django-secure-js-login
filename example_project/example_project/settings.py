# coding: utf-8

"""
    Secure JavaScript Login
    ~~~~~~~~~~~~~~~~~~~~~~~

    For more information on this file, see
    https://docs.djangoproject.com/en/1.7/topics/settings/

    For the full list of settings and their values, see
    https://docs.djangoproject.com/en/1.7/ref/settings/

    :copyleft: 2007-2015 by the secure-js-login team, see AUTHORS for more details.
    :created: by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from __future__ import unicode_literals

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
import os
BASE_DIR = os.path.dirname(os.path.dirname(__file__))

TEMPLATE_DIRS = [os.path.join(BASE_DIR, "example_project", "templates")]

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.7/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'change me!'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True
# DEBUG = False

TEMPLATE_DEBUG = DEBUG

ALLOWED_HOSTS = ["*"]

# https://djangosnippets.org/snippets/1380/
from fnmatch import fnmatch
class glob_list(list):
    def __contains__(self, ip):
        for entry in self:
            if fnmatch(ip, entry):
                return True
        return False

INTERNAL_IPS = glob_list([
    '127.0.0.1',
    '::1',
    '192.168.*.*',
    '10.0.*.*',
])

# Application definition

INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    'django_otp',
    'django_otp.plugins.otp_totp',

    "secure_js_login.honypot",
    "secure_js_login",
)



MIDDLEWARE_CLASSES = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
)

ROOT_URLCONF = 'example_project.urls'

WSGI_APPLICATION = 'example_project.wsgi.application'


USE_DJANGO_TOOLBAR = False
# USE_DJANGO_TOOLBAR = True
if USE_DJANGO_TOOLBAR:
    # django-debug-toolbar - https://github.com/django-debug-toolbar/django-debug-toolbar
    try:
        import debug_toolbar
    except ImportError:
        print("\n\n" + "*"*79)
        print("Please install django-debug-toolbar or set settings.USE_DJANGO_TOOLBAR=False!")
        print("\te.g.: $ pip install django-debug-toolbar\n")
        raise
    del(debug_toolbar)
    INSTALLED_APPS += ('debug_toolbar',)
    MIDDLEWARE_CLASSES = (
        'debug_toolbar.middleware.DebugToolbarMiddleware',
    )  + MIDDLEWARE_CLASSES





# Database
# https://docs.djangoproject.com/en/1.7/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'example_project_db.sqlite3'),
    }
}

# Internationalization
# https://docs.djangoproject.com/en/1.7/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.7/howto/static-files/

STATIC_URL = '/static/'



# django-secure-js-login settings:

# use 'User.set_password' monkey-patch in models.py for create password hashes:
AUTO_CREATE_PASSWORD_HASH = True


AUTHENTICATION_BACKENDS=(
    'secure_js_login.auth_backends.SecureLoginAuthBackend',
    'django.contrib.auth.backends.ModelBackend',
)

# Two-way verification with Time-based One-time Password (TOTP):
TOTP_NEEDED = False

LOGIN_REDIRECT_URL="/"
LOGIN_URL="/"
LOGOUT_URL="/"


LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '%(levelname)s %(msecs)d %(module)s.%(funcName)s line %(lineno)d: %(message)s'
        },
        'simple': {
            'format': '%(levelname)s %(message)s'
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            # 'formatter': 'simple'
            'formatter': 'verbose'
        },
    },
    'loggers': {
        "secure_js_login": {
            'handlers': ['console'],
            'level': 'DEBUG',
        },
    },
}