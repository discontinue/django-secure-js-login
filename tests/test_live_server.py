# coding: utf-8

"""
    Secure JavaScript Login
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyleft: 2007-2015 by the secure-js-login team, see AUTHORS for more details.
    :created: by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from __future__ import unicode_literals

import os

# set: DJANGO_SETTINGS_MODULE:tests.test_utils.test_settings to run the tests
assert os.environ["DJANGO_SETTINGS_MODULE"]=="tests.test_utils.test_settings"

from django.conf import settings
from django.contrib.staticfiles.testing import StaticLiveServerTestCase

from selenium import webdriver
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions

from tests.test_utils.test_cases import UserTestCaseMixin

# https://github.com/jedie/django-tools/
try:
    import django_tools
except ImportError as err:
    msg = (
        "Please install django-tools for unittests"
        " - https://github.com/jedie/django-tools/"
        " - Original error: %s"
    ) % err
    raise ImportError(msg)
from django_tools.unittest_utils.BrowserDebug import debug_response


class SeleniumTests(StaticLiveServerTestCase, UserTestCaseMixin):
    """
    http://selenium-python.readthedocs.org/
    """
    @classmethod
    def setUpClass(cls):
        super(SeleniumTests, cls).setUpClass()
        cls.driver = webdriver.Firefox()

    @classmethod
    def tearDownClass(cls):
        cls.driver.quit()
        super(SeleniumTests, cls).tearDownClass()

    def setUp(self):
        super(SeleniumTests, self).setUp()
        self.driver.delete_all_cookies()
        self.TEST_SUPERUSER = self.create_and_get_superuser()

    def test_example_index_page(self):
        self.driver.get('%s%s' % (self.live_server_url, '/'))
        self.assertEqual(self.driver.title,
            "Django secure-js-login example project"
        )
        page_source = self.driver.page_source
        self.assertIn('<a href="/secure_login/">', page_source)
        self.assertIn('<a href="/login/">', page_source) # honypot login
        self.assertIn('<a href="/admin/">', page_source) # Django Admin login

    def test_django_plaintext_login_success(self):
        self.driver.get('%s%s' % (self.live_server_url, "/admin/"))
        # print(self.firefox.page_source)
        self.assertEqual(self.driver.title, "Log in | Django site admin")

        username_input = self.driver.find_element_by_name("username")
        username_input.send_keys(self.SUPER_USER_NAME)
        password_input = self.driver.find_element_by_name("password")
        password_input.send_keys(self.SUPER_USER_PASS)
        self.driver.find_element_by_xpath('//input[@value="Log in"]').click()

        page_source = self.driver.page_source
        self.assertNotIn("Error", page_source)

        self.assertEqual(self.driver.title, "Site administration | Django site admin")
        self.assertIn(self.SUPER_USER_NAME, page_source)
        self.assertIn("Log out", page_source)

    def test_django_plaintext_login_wrong_password(self):
        self.driver.get('%s%s' % (self.live_server_url, "/admin/"))
        # print(self.firefox.page_source)
        self.assertEqual(self.driver.title, "Log in | Django site admin")

        username_input = self.driver.find_element_by_name("username")
        username_input.send_keys(self.SUPER_USER_NAME)
        password_input = self.driver.find_element_by_name("password")
        password_input.send_keys("wrong password")
        self.driver.find_element_by_xpath('//input[@value="Log in"]').click()
        # print(self.firefox.page_source)

        self.assertEqual(self.driver.title, "Log in | Django site admin")
        self.assertIn(
            "Please enter the correct username and password for a staff account.",
            self.driver.page_source
        )
        
    def _submit_secure_login(self, username, password):
        """
        Request secure-js-login page and submit given username/password
        but didn't wait for reload!
        """
        self.driver.get('%s%s' % (self.live_server_url, '/secure_login/'))
        # print(self.firefox.page_source)

        # self.assertInHTML( # Will failed, because tags are escaped inner noscript, why?
        #     '<noscript><p class="errornote">Please enable JavaScript!</p></noscript>',
        #     self.firefox.page_source
        # )
        self.assertIn('<noscript>', self.driver.page_source)
        self.assertIn("Please enable JavaScript!", self.driver.page_source)

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
        check = WebDriverWait(self.driver, 10).until(
            # expected_conditions.staleness_of(self.track_element)
            expected_conditions.staleness_of(self.body)
        )
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

    def assertSecureLoginSuccess(self, page_source):
        try:
            self.assertIn("You are logged in.", page_source)
            self.assertIn("Last login was:", page_source)
            self.assertIn(self.SUPER_USER_NAME, page_source)
            self.assertIn("Log out", page_source)
            self.assertNotIn("Error", page_source)
        except AssertionError as err:
            # import time
            # time.sleep(10)
            raise

    def assertSecureLoginFailed(self, page_source):
        self.assertNotIn("You are logged in.", page_source)
        self.assertNotIn("Last login was:", page_source)
        self.assertNotIn("Log out", page_source)
        self.assertIn("Error", page_source)

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