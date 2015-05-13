# coding: utf-8

"""
    Secure JavaScript Login
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyleft: 2007-2015 by the secure-js-login team, see AUTHORS for more details.
    :created: by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from __future__ import unicode_literals, print_function
import traceback

import unittest

# set: DJANGO_SETTINGS_MODULE:tests.test_utils.test_settings to run the tests
import sys
from selenium.webdriver.common.alert import Alert

from django.contrib.staticfiles.testing import StaticLiveServerTestCase
from django.test import override_settings
from django.utils import six

try:
    import selenium
    from selenium import webdriver
    from selenium.common.exceptions import WebDriverException, UnexpectedAlertPresentException, \
        StaleElementReferenceException
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions
except ImportError as err:
    selenium_import_error = err
else:
    selenium_import_error = None

# selenium_import_error = "Deactivated!"

from tests.test_utils.test_cases import SecureLoginBaseTestCase


class SeleniumVerboseAssert(object):
    def _verbose_assertion_error(self, err):
        print("\n", flush=True, file=sys.stderr)
        print("*" * 79, file=sys.stderr)
        traceback.print_exc()
        print(" -" * 40, file=sys.stderr)
        try:
            page_source = self.driver.page_source
        except Exception as e:
            print("Can't get 'driver.page_source': %s" % e)
        else:
            page_source = "\n".join([line for line in page_source.splitlines() if line.rstrip()])
            print(page_source, file=sys.stderr)

        print("*" * 79, file=sys.stderr)
        print("\n", flush=True, file=sys.stderr)
        raise

    def assertNoJavaScriptAltert(self):
        alert = expected_conditions.alert_is_present()(self.driver)
        if alert != False:
            alert_text = alert.text
            alert.accept() # Confirm a alert dialog, otherwise access to driver.page_source will failed!
            try:
                raise self.failureException("Alert is preset: %s" % alert_text)
            except AssertionError as err:
                self._verbose_assertion_error(err)

    def assertEqualTitle(self, should):
        try:
            self.assertEqual(self.driver.title, should)
        except AssertionError as err:
            self._verbose_assertion_error(err)

    def assertInPageSource(self, member):
        try:
            self.assertIn(member, self.driver.page_source)
        except AssertionError as err:
            self._verbose_assertion_error(err)

    def assertNotInPageSource(self, member):
        try:
            self.assertNotIn(member, self.driver.page_source)
        except AssertionError as err:
            self._verbose_assertion_error(err)


@unittest.skipUnless(selenium_import_error is None, selenium_import_error)
class SeleniumTests(StaticLiveServerTestCase, SecureLoginBaseTestCase, SeleniumVerboseAssert):
    """
    http://selenium-python.readthedocs.org/
    """

    @classmethod
    def setUpClass(cls):
        super(SeleniumTests, cls).setUpClass()
        cls.driver = webdriver.Firefox()
        cls.driver.set_window_size(800,600)
        cls.driver.set_window_position(0,0)

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
        self.assertNotInPageSource("Traceback")

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

        self.body = self.driver.find_element_by_css_selector('body')
        self.assertTrue(self.body.is_enabled())

        # Submit the Form
        self.driver.find_element_by_xpath('//input[@value="Log in"]').click()

    def _wait_until_reload(self):
        #print("\n\n%r\n\n" % self.driver.execute_script('return document.firstChild.innerHTML;'))
        self.assertNoJavaScriptAltert()

        check = WebDriverWait(self.driver, 10).until(
            expected_conditions.staleness_of(self.body)
        )
        self.assertTrue(check)
        self.body = None

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

    @override_settings(DEBUG=True)
    def test_secure_login_wrong_password(self):
        """ Detail error message while DEBUG=True """
        self._secure_login(
            username=self.SUPER_USER_NAME,
            password="Wrong Password"
        )
        # Check new loaded page content:
        self.assertSecureLoginFailed(self.driver.page_source)
        self.assertFailedSignals(
	        "XOR decrypted data: PBKDF2 hash test failed",
            (
                "SecureLoginForm error:"
                " '__all__':XOR decrypted data:"
                " PBKDF2 hash test failed,authenticate() check failed."
            )
        )
        try:
            self.assertIn(
                "XOR decrypted data: PBKDF2 hash test failed",
                self.driver.page_source
            )
        except AssertionError as err:
            self._verbose_assertion_error(self.driver.page_source)

    @override_settings(DEBUG=False)
    def test_secure_login_wrong_username(self):
        """ common error messages while DEBUG=False """
        self._secure_login(
            username="WrongUsername",
            password="Wrong Password"
        )
        # Check new loaded page content:
        self.assertSecureLoginFailed(self.driver.page_source)
        self.assertOnlyCommonFormError(self.driver.page_source)
        self.assertFailedSignals(
            ( # The salt request:
                "UsernameForm error:"
                " 'username':"
                "User 'WrongUsername' doesn't exists!"
            ),
            ( # The login request:
                "SecureLoginForm error:"
                " 'username':"
                "User 'WrongUsername' doesn't exists!"
            )
        )
        try:
            self.assertNotIn("'WrongUsername' doesn't exists", self.driver.page_source)
        except AssertionError as err:
            self._verbose_assertion_error(self.driver.page_source)

    def test_secure_login_wrong_and_then_right(self):
        self.test_secure_login_wrong_password()
        self.reset_signal_storage()
        self.test_secure_login_success()