from django.conf.urls import patterns, include, url
from django.contrib import admin

from .views import index
from secure_js_login.honypot.urls import urlpatterns as honypot_urlpatterns
from secure_js_login.urls import urlpatterns as secure_js_login_urlpatterns

urlpatterns = patterns('',
    url(r'^$', index),

    url(r'^login/', include(honypot_urlpatterns)),
    url(r'^secure_login/', include(secure_js_login_urlpatterns)),

    url(r'^admin/', include(admin.site.urls)),
)
