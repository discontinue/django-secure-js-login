# coding: utf-8

"""
    Secure JavaScript Login
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyleft: 2007-2015 by the secure-js-login team, see AUTHORS for more details.
    :created: by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from __future__ import unicode_literals

from django.conf import settings
from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.contrib.staticfiles.urls import staticfiles_urlpatterns

from secure_js_login.honypot.urls import urls as honypot_urls
from secure_js_login.urls import urls as secure_js_login_urls

from . import views


urlpatterns = patterns('',
    url(r'^$', views.index),
                       
    url(r'^debug_on/$', views.debug_on, name='debug_on'),
    url(r'^debug_off/$', views.debug_off, name='debug_off'),                       

    url(r'^totp_on/$', views.totp_on, name='totp_on'),
    url(r'^totp_off/$', views.totp_off, name='totp_off'),

    url(r'^jsi18n/(?P<packages>\S+?)/$', 'django.views.i18n.javascript_catalog'),
    url(r'^login/', include(honypot_urls)),
    url(r'^secure_login/', include(secure_js_login_urls)),

    url(r'^admin/', include(admin.site.urls)),
)


# Explicit include the "grossly inefficient and probably insecure" staticfiles views,
# so that "runserver --insecure" can be used even if the DEBUG setting is False
# Should never be used in production!
urlpatterns += staticfiles_urlpatterns()


if settings.USE_DJANGO_TOOLBAR:
    import debug_toolbar
    urlpatterns = patterns('',
        url(r'^__debug__/', include(debug_toolbar.urls)),
    ) + urlpatterns