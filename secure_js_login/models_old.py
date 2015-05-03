# coding: utf-8

from __future__ import unicode_literals

# used in auth views for simple check if client-nonce used in the past
# Exist here in models, because it's accessible in other modules, too.
# This doesn't work if its defined in views.py
CNONCE_CACHE = {}
