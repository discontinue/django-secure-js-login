# coding: utf-8

"""
    PyLucid JS-SHA-Login forms
    ~~~~~~~~~~~~~~~~~~~~~~~~~~

    A secure JavaScript SHA-1 AJAX Login.

    :copyleft: 2007-2015 by the PyLucid team, see AUTHORS for more details.
    :license: GNU GPL v3 or above, see LICENSE for more details
"""


from django import forms
from django.utils.translation import ugettext as _


class WrongUserError(Exception):
    pass


class HoneypotForm(forms.Form):
    username = forms.CharField(max_length=30, label=_('username'))
    password = forms.CharField(max_length=128, label=_('password'),
        widget=forms.PasswordInput
    )

