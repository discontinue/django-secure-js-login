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
import statistics

from django.contrib.auth import SESSION_KEY
from django.test import override_settings

from tests.test_utils.test_cases import SecureLoginClientBaseTestCase, debug_response


class TestTimingAttack(SecureLoginClientBaseTestCase):
    VERBOSE = False

    def _login(self, username, password=None, succses_login=True):
        if password is None:
            self._calc_secure_password()
            password=self.secure_password

        start_time = time.time()
        response = self.client.post(self.secure_login_url,
            follow=False,
            data = {
                "username": username,
                "password": password,
            }
        )
        duration = time.time()-start_time
        if succses_login:
            self.assertIn(SESSION_KEY, self.client.session)
        else:
            self.assertNotIn(SESSION_KEY, self.client.session)

        self._reset_secure_data()
        self.client.logout()

        return duration

    @override_settings(DEBUG=False)
    def test(self):
        print("\nMeasuring successful logins...")

        start_time = time.time() + 1
        durations = []
        while True:
            duration = self._login(self.SUPER_USER_NAME)
            durations.append(duration)
            if time.time()>start_time:
                break

        print("%i requests made." % len(durations))
        print(durations)
        print("average:", statistics.mean(durations))
        print("median:", statistics.median(durations))

        print("\nMeasuring failed logins...")
        start_time = time.time() + 1
        durations = []
        while True:
            duration = self._login("Not exists", "wrong pass", succses_login=False)
            durations.append(duration)
            if time.time()>start_time:
                break

        print("%i requests made." % len(durations))
        print(durations)
        print("average:", statistics.mean(durations))
        print("median:", statistics.median(durations))