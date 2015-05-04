# coding: utf-8


from django.conf.urls import patterns, url

from secure_js_login import views


_urlpatterns = patterns('',
    url(r'^get_salt/$', views.get_salt, name='get_salt'),
    url(r'^secure_auth/$', views.secure_auth, name='secure_auth'),
    url(r'^', views.secure_js_login, name='login'),
)

# https://docs.djangoproject.com/en/1.7/topics/http/urls/#url-namespaces-and-included-urlconfs
urls = (_urlpatterns, "secure-js-login", "secure-js-login")
