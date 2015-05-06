# coding: utf-8

"""
    Secure JavaScript Login
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyleft: 2007-2015 by the secure-js-login team, see AUTHORS for more details.
    :created: by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from __future__ import unicode_literals

from django.conf.urls import patterns, include, url
from django.contrib import admin

from secure_js_login.honypot.urls import urls as honypot_urls
from secure_js_login.urls import urls as secure_js_login_urls

from .views import index

urlpatterns = patterns('',
    url(r'^$', index),

    url(r'^jsi18n/(?P<packages>\S+?)/$', 'django.views.i18n.javascript_catalog'),
    url(r'^login/', include(honypot_urls)),
    url(r'^secure_login/', include(secure_js_login_urls)),

    url(r'^admin/', include(admin.site.urls)),
)
