# coding: utf-8

"""
    Secure JavaScript Login
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyleft: 2007-2015 by the secure-js-login team, see AUTHORS for more details.
    :created: by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from __future__ import unicode_literals, print_function

# set: DJANGO_SETTINGS_MODULE:tests.test_utils.test_settings to run the tests

import sys
import time
import unittest

from django.contrib.auth import SESSION_KEY
from django.test import override_settings
from django.utils import six

from secure_js_login.decorators import TimingAttackPreventer
from tests.test_utils.client_test_cases import SecureLoginClientBaseTestCase


# MEASUREING_LOOPS = 10
# MEASUREING_LOOPS = 25
MEASUREING_LOOPS = 50
# MEASUREING_LOOPS = 75
# MEASUREING_LOOPS = 100

MIN_MAX_AVG_PERCENT = 15


def average(l):
    try:
        return sum(l) / len(l)
    except ZeroDivisionError:
        return 0


class NoAddDurationResponseMock(object):
    add_duration = False


class AddDurationResponseMock(object):
    add_duration = True


preventer = TimingAttackPreventer()


def origin_test_func(t, response_mock):
    time.sleep(t)
    return response_mock


origin_test_func.preventer = preventer


@preventer
# @TimingAttackPreventer()
def preventer_func(t, response_mock):
    return origin_test_func(t, response_mock)


preventer_func.preventer = preventer


# @unittest.skip # Only for developting!
class TestTimingAttackPreventer(unittest.TestCase):
    def out(self, *args):
        print(*args, file=sys.stderr)

    def _measure(self, func, t1, t2, loops):
        self.out("\nt1=%s vs t2=%s - %i loops:" % (t1, t2, loops))

        func.preventer.reset()
        duration1 = duration2 = 0

        total_start_time = time.time()

        for _ in range(loops):
            start_time = time.time()
            func(t1, AddDurationResponseMock)
            duration1 += time.time() - start_time

            start_time = time.time()
            func(t2, NoAddDurationResponseMock)
            duration2 += time.time() - start_time

        total_duration = time.time() - total_start_time

        diff = abs(duration1 - duration2)
        percent = 100 / (duration1 + duration2) * diff

        self.out("\t%f vs %f - diff: %.2fms - %.1f%% (total run time: %.1fSec)" % (
            duration1, duration2, diff * 1000, percent, total_duration
        ))
        self.out("\tsuccessful_timings..", list(func.preventer.successful_timings)[-3:])
        self.out("\tfailed_timings......", list(func.preventer.failed_timings)[-3:])
        # self.out("\tsleep_timings.......", list(func.preventer.sleep_timings)[-3:])

        return percent

    def test_without_decorator(self):
        """
        Just to see the variants in same code path
        """
        diff_percent = self._measure(func=origin_test_func, t1=0, t2=0, loops=10000)
        self.assertLess(diff_percent, 2)

        diff_percent = self._measure(func=origin_test_func, t1=0.001, t2=0, loops=50)
        self.assertGreater(diff_percent, 95)

    def test_with_decorator(self):
        """
        Test TimingAttackPreventer
        """
        max_diff_percent = 6
        
        diff_percent = self._measure(func=preventer_func, t1=0.0005, t2=0.0005, loops=500)
        self.assertLess(diff_percent, max_diff_percent)

        diff_percent = self._measure(func=preventer_func, t1=0.005, t2=0.005, loops=100)
        self.assertLess(diff_percent, max_diff_percent)

        diff_percent = self._measure(func=preventer_func, t1=0.002, t2=0.001, loops=250)
        self.assertLess(diff_percent, max_diff_percent)

        diff_percent = self._measure(func=preventer_func, t1=0.004, t2=0.001, loops=100)
        self.assertLess(diff_percent, max_diff_percent)

        diff_percent = self._measure(func=preventer_func, t1=0.008, t2=0.001, loops=75)
        self.assertLess(diff_percent, max_diff_percent)





class BaseTestTimingAttack(SecureLoginClientBaseTestCase):
    VERBOSE = False

    def _measure_loop(self, callback):
        start_time = time.time()
        durations = [callback() for _ in range(MEASUREING_LOOPS)]
        duration = time.time() - start_time

        durations.sort()
        avg = average(durations)
        count = int(round(MEASUREING_LOOPS/100*MIN_MAX_AVG_PERCENT,0))
        if count<1:
            count=1
        self.out("\tMin/max avg with %i items." % count)
        avg_min = average(durations[:count])
        avg_max = average(durations[-count:])

        quick_percent = 100 - (100/avg_min*avg)
        long_percent = 100 - (100/avg_max*avg)
        self.out("\tavg.min: %.1fms (%i%%) - average: %.1fms - avg.max: %.1fms (%i%%) (takes %.2f sec.)" % (
            avg_min*1000, quick_percent,
            avg*1000,
            avg_max*1000, long_percent,
            duration
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

        self.out("Measuring failed secure_js_login (%i loops)..." % MEASUREING_LOOPS)
        average2 = self._measure_loop(self.measured_failed_secure_js_login)

        diff = abs(average1 - average2)
        percent = abs(100 - (100/average1*average2))
        self.out(" *** average secure_js_login diff: %.2fms (%.1f%%)" % (diff*1000, percent))

    def measured_successful_get_salt(self):
        self._request_server_challenge()

        start_time = time.time()
        response = self.client.post(self.get_salt_url,
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
            data={"username": self.SUPER_USER_NAME}
        )
        duration = time.time() - start_time

        self.assertEqual(
            six.text_type(response.content, "ascii"),
            self.superuser_profile.init_pbkdf2_salt
        )
        self._reset_secure_data()
        return duration

    def measured_failed_get_salt(self):
        self._request_server_challenge()

        start_time = time.time()
        response = self.client.post(self.get_salt_url,
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
            data={"username": "NotExists"}
        )
        duration = time.time() - start_time

        self.assertNotEqual(
            six.text_type(response.content, "ascii"),
            self.superuser_profile.init_pbkdf2_salt
        )
        self._reset_secure_data()
        return duration

    @override_settings(DEBUG=False)
    def test_get_salt(self):
        self.out("\nMeasuring successful get_salt view (%i loops)..." % MEASUREING_LOOPS)
        average1 = self._measure_loop(self.measured_successful_get_salt)

        self.out("Measuring failed get_salt view (%i loops)..." % MEASUREING_LOOPS)
        average2 = self._measure_loop(self.measured_failed_get_salt)

        diff = abs(average1 - average2)
        percent = abs(100 - (100/average1*average2))
        self.out(" *** average get_salt diff: %.2fms (%.1f%%)" % (diff*1000, percent))


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

    def measured_wrong_password_django_login(self):
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

    def measured_wrong_username_django_login(self):
        start_time = time.time()
        self.client.post(
            self.django_login_url,
            follow=False,
            data={
                "username": "NotExistingUser",
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

        self.out("Measuring 'wrong password' django login (%i loops)..." % MEASUREING_LOOPS)
        average2 = self._measure_loop(self.measured_wrong_password_django_login)

        self.out("Measuring 'wrong username' django login (%i loops)..." % MEASUREING_LOOPS)
        average3 = self._measure_loop(self.measured_wrong_username_django_login)

        averages = [average1, average2, average3]
        min_avg = min(averages)
        max_avg = max(averages)

        diff = max_avg - min_avg
        percent = 100 - (100/max_avg*min_avg)
        self.out(" *** max.average django diff: %.2fms (%.1f%%)" % (diff*1000, percent))