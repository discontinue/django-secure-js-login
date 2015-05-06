# coding: utf-8

"""
    Secure JavaScript Login
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyleft: 2007-2015 by the secure-js-login team, see AUTHORS for more details.
    :created: by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from __future__ import unicode_literals

from django.conf.urls import patterns, url

from secure_js_login.honypot import views


_urlpatterns = patterns('',
    url(r'^', views.login_honeypot, name='login'),
)

# https://docs.djangoproject.com/en/1.7/topics/http/urls/#url-namespaces-and-included-urlconfs
urls = (_urlpatterns, "honypot-login", "secure_js_login.honypot")