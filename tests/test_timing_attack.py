# coding: utf-8

"""
    Secure JavaScript Login
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyleft: 2007-2015 by the secure-js-login team, see AUTHORS for more details.
    :created: by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from __future__ import unicode_literals

# set: DJANGO_SETTINGS_MODULE:tests.test_utils.test_settings to run the tests

import time

from django.contrib.auth import SESSION_KEY
from django.test import override_settings

from tests.test_utils.test_cases import SecureLoginClientBaseTestCase


# MEASUREING_LOOPS = 10
MEASUREING_LOOPS = 25
# MEASUREING_LOOPS = 50
# MEASUREING_LOOPS = 100


def average(l):
    try:
        return sum(l) / len(l)
    except ZeroDivisionError:
        return 0


def statistics(l):
    return min(l), average(l), max(l)


class BaseTestTimingAttack(SecureLoginClientBaseTestCase):
    VERBOSE = False

    def _measure_loop(self, callback):
        start_time = time.time()
        durations = [callback() for _ in range(MEASUREING_LOOPS)]
        duration = time.time() - start_time

        quick, avg, long = statistics(durations)
        self.out("min: %f - average: %f - max: %f (takes %.2f sec.)" % (
            quick, avg, long, duration
        ))
        return avg


class TestSecureLoginTimingAttack(BaseTestTimingAttack):
    def measured_successful_secure_js_login(self):
        self._calc_secure_password()
        start_time = time.time()
        self.client.post(
            self.secure_login_url,
            follow=False,
            data={
             "username": self.SUPER_USER_NAME,
             "password": self.secure_password,
            }
        )
        duration = time.time() - start_time
        self.assertIn(SESSION_KEY, self.client.session)
        self._reset_secure_data()
        self.client.logout()
        return duration

    def measured_failed_secure_js_login(self):
        start_time = time.time()
        self.client.post(
            self.secure_login_url,
            follow=False,
            data={
                "username": self.SUPER_USER_NAME,
                "password": "wrong password",
            }
        )
        duration = time.time() - start_time
        self.assertNotIn(SESSION_KEY, self.client.session)
        return duration

    @override_settings(DEBUG=False)
    def test_secure_js_login(self):
        self.out("\nMeasuring successful secure_js_login (%i loops)..." % MEASUREING_LOOPS)
        average1 = self._measure_loop(self.measured_successful_secure_js_login)

        self.out("\nMeasuring failed secure_js_login (%i loops)..." % MEASUREING_LOOPS)
        average2 = self._measure_loop(self.measured_failed_secure_js_login)

        self.out("average secure_js_login diff: %f sec" % (average1 - average2))


class TestDjangoLoginTimingAttack(BaseTestTimingAttack):
    def measured_successful_django_login(self):
        start_time = time.time()
        self.client.post(
            self.django_login_url,
            follow=False,
            data={
                "username": self.SUPER_USER_NAME,
                "password": self.SUPER_USER_PASS,
            }
        )
        duration = time.time() - start_time
        self.assertIn(SESSION_KEY, self.client.session)
        self.client.logout()
        return duration

    def measured_failed_django_login(self):
        start_time = time.time()
        self.client.post(
            self.django_login_url,
            follow=False,
            data={
                "username": self.SUPER_USER_NAME,
                "password": "wrong password",
            }
        )
        duration = time.time() - start_time
        self.assertNotIn(SESSION_KEY, self.client.session)
        return duration

    @override_settings(DEBUG=False)
    def test_django_login(self):
        self.out("\nMeasuring successful django login (%i loops)..." % MEASUREING_LOOPS)
        average1 = self._measure_loop(self.measured_successful_django_login)

        self.out("\nMeasuring failed django login (%i loops)..." % MEASUREING_LOOPS)
        average2 = self._measure_loop(self.measured_failed_django_login)

        self.out("average django diff: %f sec" % (average1 - average2))