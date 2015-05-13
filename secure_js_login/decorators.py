# coding: utf-8

"""
    Secure JavaScript Login
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyleft: 2015 by the secure-js-login team, see AUTHORS for more details.
    :created: by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from __future__ import unicode_literals

import collections
import functools
import logging
import random
import traceback
import sys
import time


log = logging.getLogger("secure_js_login")


def log_view(func):
    """
    Helpful while debugging Selenium unittests.
    e.g.: server response an error in AJAX requests
    """
    @functools.wraps(func)
    def view_logger(*args, **kwargs):
        log.debug("call view %r", func.__name__)
        try:
            response = func(*args, **kwargs)
        except Exception as err:
            log.error("view exception: %s", err)
            traceback.print_exc(file=sys.stderr)
            raise

        log.debug("Response: %s", response)
        return response
    return view_logger



class TimingAttackPreventer(object):
    timings = collections.deque(maxlen=10)

    def __init__(self, func):
        self.func = func

    def __call__(self, *args, **kwargs):
        # log.debug("call view %r", self.func.__name__)
        start_time=time.time()
        try:
            response = self.func(*args, **kwargs)
        except Exception as err:
            # FIXME: also apply time.sleep() ?!?
            log.error("view exception: %s", err)
            traceback.print_exc(file=sys.stderr)
            raise

        duration = time.time()-start_time

        if getattr(response, "add_duration", False)==True:
            self.timings.append(duration)
        elif self.timings:
            time.sleep(random.uniform(min(self.timings), max(self.timings)))

        # log.debug("Response: %s", response)
        return response