# coding: utf-8

"""
    Secure JavaScript Login
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyleft: 2007-2015 by the secure-js-login team, see AUTHORS for more details.
    :created: by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from __future__ import unicode_literals

from django import forms
from django.utils.translation import ugettext as _


class WrongUserError(Exception):
    pass


class HoneypotForm(forms.Form):
    username = forms.CharField(max_length=30, label=_('username'))
    password = forms.CharField(max_length=128, label=_('password'),
        widget=forms.PasswordInput
    )

