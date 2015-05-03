# coding: utf-8


from django.conf.urls import patterns, url

from secure_js_login import views


urlpatterns = patterns('',
    url(r'^', views.secure_js_login, name='secure-js-login'),
)
