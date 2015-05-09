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

from secure_js_login.forms import ERROR_MESSAGE

ERROR_MESSAGE = ERROR_MESSAGE % {"username": "username"}  # replace string formatting part


class HoneypotForm(forms.Form):
    """
    Special form:
     * We can validate max_length
     * We can raise a form error by view ;)
    """
    username = forms.CharField(max_length=30, label=_('username'))
    password = forms.CharField(max_length=128, label=_('password'),
                               widget=forms.PasswordInput
                               )

    def __init__(self, *args, **kwargs):
        self.raise_error = kwargs.pop("raise_error", False)
        super(HoneypotForm, self).__init__(*args, **kwargs)

    def clean(self):
        if self.raise_error:
            raise forms.ValidationError(ERROR_MESSAGE)
