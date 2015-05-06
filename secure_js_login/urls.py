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

from secure_js_login import views


_urlpatterns = patterns('',
    url(r'^get_salt/$', views.get_salt, name='get_salt'),
    url(r'^', views.secure_js_login, name='login'),
)

# https://docs.djangoproject.com/en/1.7/topics/http/urls/#url-namespaces-and-included-urlconfs
urls = (_urlpatterns, "secure-js-login", "secure-js-login")
