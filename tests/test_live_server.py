# coding: utf-8

"""
    Secure JavaScript Login
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyleft: 2007-2015 by the secure-js-login team, see AUTHORS for more details.
    :created: by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from __future__ import unicode_literals
import traceback

import unittest

# set: DJANGO_SETTINGS_MODULE:tests.test_utils.test_settings to run the tests
import sys

from django.contrib.staticfiles.testing import StaticLiveServerTestCase

try:
    import selenium
    from selenium import webdriver
    from selenium.common.exceptions import WebDriverException, UnexpectedAlertPresentException
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions
except ImportError as err:
    selenium_import_error = err
else:
    selenium_import_error = None

from tests.test_utils.test_cases import SecureLoginBaseTestCase


class SeleniumVerboseAssert(object):
    def _verbose_assertion_error(self, page_source, err):
        print("\n", flush=True, file=sys.stderr)
        print("*" * 79, file=sys.stderr)
        traceback.print_exc()
        print(" -" * 40, file=sys.stderr)
        page_source = "\n".join([line for line in page_source.splitlines() if line.rstrip()])
        print(page_source, file=sys.stderr)
        print("*" * 79, file=sys.stderr)
        print("\n", flush=True, file=sys.stderr)
        raise

    def assertEqualTitle(self, should):
        try:
            self.assertEqual(self.driver.title, should)
        except AssertionError as err:
            self._verbose_assertion_error(self.driver.page_source, err)

    def assertInPageSource(self, member):
        try:
            self.assertIn(member, self.driver.page_source)
        except AssertionError as err:
            self._verbose_assertion_error(self.driver.page_source, err)

    def assertNotInPageSource(self, member):
        try:
            self.assertNotIn(member, self.driver.page_source)
        except AssertionError as err:
            self._verbose_assertion_error(self.driver.page_source, err)


@unittest.skipUnless(selenium_import_error is None, selenium_import_error)
class SeleniumTests(StaticLiveServerTestCase, SecureLoginBaseTestCase, SeleniumVerboseAssert):
    """
    http://selenium-python.readthedocs.org/
    """

    @classmethod
    def setUpClass(cls):
        super(SeleniumTests, cls).setUpClass()
        cls.driver = webdriver.Firefox()

    @classmethod
    def tearDownClass(cls):
        try:
            cls.driver.quit()
        except:
            pass
        super(SeleniumTests, cls).tearDownClass()

    def setUp(self):
        super(SeleniumTests, self).setUp()
        self.driver.delete_all_cookies()

    def test_example_index_page(self):
        self.driver.get('%s%s' % (self.live_server_url, '/'))
        self.assertEqualTitle(
            "Django secure-js-login example project"
        )
        self.assertEqualTitle("Django secure-js-login example project")

        self.assertInPageSource('<a href="/secure_login/">')
        self.assertInPageSource('<a href="/login/">') # honypot login
        self.assertInPageSource('<a href="/admin/">') # Django Admin login
        self.assertInPageSource('<a href="/admin/">') # Django Admin login
        self.assertNotInPageSource('error')

    def test_django_plaintext_login_success(self):
        self.driver.get('%s%s' % (self.live_server_url, "/admin/"))
        # print(self.firefox.page_source)
        self.assertEqualTitle("Log in | Django site admin")

        self.assertNotInPageSource("Secure-JS-Login")

        username_input = self.driver.find_element_by_name("username")
        username_input.send_keys(self.SUPER_USER_NAME)
        password_input = self.driver.find_element_by_name("password")
        password_input.send_keys(self.SUPER_USER_PASS)
        self.driver.find_element_by_xpath('//input[@value="Log in"]').click()

        self.assertNotInPageSource("Error")
        self.assertNotInPageSource("Please enter the correct username")
        self.assertEqualTitle("Site administration | Django site admin")
        self.assertInPageSource(self.SUPER_USER_NAME)
        self.assertInPageSource("Log out")

    def test_django_plaintext_login_wrong_password(self):
        self.driver.get('%s%s' % (self.live_server_url, "/admin/"))
        # print(self.firefox.page_source)
        self.assertEqualTitle("Log in | Django site admin")

        username_input = self.driver.find_element_by_name("username")
        username_input.send_keys(self.SUPER_USER_NAME)
        password_input = self.driver.find_element_by_name("password")
        password_input.send_keys("wrong password")
        self.driver.find_element_by_xpath('//input[@value="Log in"]').click()
        # print(self.firefox.page_source)

        self.assertEqualTitle("Log in | Django site admin")
        self.assertInPageSource(
            "Please enter the correct username and password for a staff account."
        )

    def _submit_secure_login(self, username, password):
        """
        Request secure-js-login page and submit given username/password
        but didn't wait for reload!
        """
        self.driver.get('%s%s' % (self.live_server_url, '/secure_login/'))
        # print(self.firefox.page_source)

        # self.assertInHTML( # Will failed, because tags are escaped inner noscript, why?
        # '<noscript><p class="errornote">Please enable JavaScript!</p></noscript>',
        #     self.firefox.page_source
        # )
        self.assertInPageSource('<noscript>')
        self.assertInPageSource("Please enable JavaScript!")

        # Test if precheck was ok
        self.assertEqual(
            self.driver.execute_script('return precheck_secure;'),
            True
        )

        # Test if username/password is empty:
        self.assertEqual(
            self.driver.execute_script('return $(ID_USERNAME).val();'),
            ""
        )
        self.assertEqual(
            self.driver.execute_script('return $(ID_PASSWORD).val();'),
            ""
        )

        username_input = self.driver.find_element_by_name("username")
        username_input.send_keys(username)
        password_input = self.driver.find_element_by_name("password")
        password_input.send_keys(password)

        # Check if username/password are "visible" from JavaScript
        self.assertEqual(
            self.driver.execute_script('return $(ID_USERNAME).val();'),
            username
        )
        self.assertEqual(
            self.driver.execute_script('return $(ID_PASSWORD).val();'),
            password
        )

        # self.track_element = self.driver.create_web_element("SELENIUM_PAGE_LOAD_TRACKING_ELEMENT")
        self.body = self.driver.find_element_by_css_selector('body')

        # Submit the Form
        self.driver.find_element_by_xpath('//input[@value="Log in"]').click()

    def _wait_until_reload(self):
        try:
            check = WebDriverWait(self.driver, 10).until(
                # expected_conditions.staleness_of(self.track_element)
                expected_conditions.staleness_of(self.body)
            )
        except UnexpectedAlertPresentException as err:
            print("\n\nPage is reloaded?!? - %s" % err)
            check = True
            import time
            time.sleep(10)
            print(self.driver.page_source)
            raise
        except Exception as err:
            print("\n\nError: %s" % err)
            import time
            time.sleep(10)
            print(self.driver.page_source)
            raise

        self.body = None
        self.track_element = None
        self.assertTrue(check)

    def _secure_login(self, username, password):
        """
        Fill given username/password to secure-js-login page
        return if form is submit
        """
        self._submit_secure_login(username, password)
        self._wait_until_reload()

    def test_secure_login_success(self):
        self._secure_login(
            username=self.SUPER_USER_NAME,
            password=self.SUPER_USER_PASS
        )
        # Check new loaded page content:
        self.assertSecureLoginSuccess(self.driver.page_source)

    def test_secure_login_wrong_password(self):
        self._secure_login(
            username=self.SUPER_USER_NAME,
            password="Wrong Password"
        )
        # Check new loaded page content:
        self.assertSecureLoginFailed(self.driver.page_source)

    def test_secure_login_wrong_username(self):
        self._secure_login(
            username="WrongUsername",
            password="Wrong Password"
        )
        # Check new loaded page content:
        self.assertSecureLoginFailed(self.driver.page_source)

    def test_secure_login_wrong_and_then_right(self):
        self.test_secure_login_wrong_password()
        self.test_secure_login_success()