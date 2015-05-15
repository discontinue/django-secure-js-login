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
    def __init__(self, deque_maxlen=50):
        self.deque_maxlen=deque_maxlen
        self.reset()

    def reset(self):
        self.successful_timings = collections.deque(maxlen=self.deque_maxlen)
        self.failed_timings = collections.deque(maxlen=self.deque_maxlen)
        # self.sleep_timings = collections.deque(maxlen=self.deque_maxlen)

    def avg(self, deque):
        if deque:
            return sum(deque) / len(deque)
        else:
            return 0

    def __call__(self, func):
        def wrapped_func(*args, **kwargs):
            # log.debug("\ncall view %r with args: %r kwargs: %r",
            # func.__name__, args, kwargs
            # )
            start_time = time.time()
            response = func(*args, **kwargs)

            successful_length = self.avg(self.successful_timings)
            failed_length = self.avg(self.failed_timings)

            diff_compensation = successful_length - failed_length
            no_compensation = 0

            if getattr(response, "add_duration", False):
                # successful request -> collect duration value
                timing_deque = self.successful_timings
                sleep_length = no_compensation
            else:
                # failed request -> 'fill' time with collect durations
                timing_deque = self.failed_timings
                sleep_length = diff_compensation

            if sleep_length < 0:
                sleep_length = 0

            # self.sleep_timings.append(sleep_length)

            timing_deque.append(time.time() - start_time)

            time.sleep(sleep_length)

            # log.debug("Response: %s", response)
            return response

        return wrapped_func


