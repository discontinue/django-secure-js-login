# coding: utf-8

"""
    Secure JavaScript Login
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyleft: 2007-2015 by the secure-js-login team, see AUTHORS for more details.
    :created: by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from __future__ import unicode_literals

import functools
import logging
import traceback
import sys

from secure_js_login.simple_dos_protect.utils import get_ip
from secure_js_login.utils.cache import AppCache


log = logging.getLogger("secure_js_login.simple_dos_protect")

cache = AppCache(backend="default", key_suffix="simple_dos_protect", timeout=3)


def simple_dos_protect(func):
    log.debug("simple_dos_protect(%r)", func.__name__)
    @functools.wraps(func)
    def protect(request, *args, **kwargs):
        log.debug("call view %r", func.__name__)

        ip = get_ip(request)
        print("\tIP: %r" % ip)
        cache.incr(ip)
        print(cache)

        try:
            response = func(request, *args, **kwargs)
        except Exception as err:
            # log.error("view exception: %s", err)
            traceback.print_exc(file=sys.stderr)
            raise

        # log.debug("Response: %s", response)
        return response
    return protect