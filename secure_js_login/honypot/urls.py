# coding: utf-8


from django.conf.urls import patterns, url

from secure_js_login.honypot import views


_urlpatterns = patterns('',
    url(r'^', views.login_honeypot, name='login'),
)

# https://docs.djangoproject.com/en/1.7/topics/http/urls/#url-namespaces-and-included-urlconfs
urls = (_urlpatterns, "honypot-login", "secure_js_login.honypot")