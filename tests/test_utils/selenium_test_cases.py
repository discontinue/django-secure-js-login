# coding: utf-8

"""
    Secure JavaScript Login
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyleft: 2012-2015 by the secure-js-login team, see AUTHORS for more details.
    :created: by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details
"""

from __future__ import unicode_literals, print_function

import sys
import traceback
from django.conf import settings
from django.utils.importlib import import_module

try:
    import selenium
    from selenium import webdriver
    from selenium.common.exceptions import WebDriverException, UnexpectedAlertPresentException, \
        StaleElementReferenceException
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions
    from selenium.webdriver.common.alert import Alert
except ImportError as err:
    selenium_import_error = err
else:
    selenium_import_error = None

from django.contrib.staticfiles.testing import StaticLiveServerTestCase
from django.http import HttpResponse, SimpleCookie

from tests.test_utils.base_test_cases import SecureLoginBaseTestCase, FakedHttpResponse


class SeleniumTestCase(StaticLiveServerTestCase, SecureLoginBaseTestCase):
    """
    http://selenium-python.readthedocs.org/
    """
    @classmethod
    def setUpClass(cls):
        super(SeleniumTestCase, cls).setUpClass()
        cls.driver = webdriver.Firefox()
        cls.driver.set_window_size(800,600)
        cls.driver.set_window_position(0,0)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.driver.quit()
        except:
            pass
        super(SeleniumTestCase, cls).tearDownClass()

    def setUp(self):
        super(SeleniumTestCase, self).setUp()
        self.driver.delete_all_cookies()

    def get_faked_response(self):
        """
        Create a similar 'testing-response' [1] here.
        So that some of the django testing assertions [2] can be used
        with selenium tests, too ;)

        Currently not available:
            * response.status_code
            * response.redirect_chain
            * response.templates
            * response.context

        Available:
            * response.content
            * response.cookies
            * response.client.cookies
            * response.session

        [1] https://docs.djangoproject.com/en/1.7/topics/testing/tools/#testing-responses
        [2] https://docs.djangoproject.com/en/1.7/topics/testing/tools/#assertions
        """
        response = FakedHttpResponse(content=self.driver.page_source)
        self.client = self.client_class() # Fresh Client() instance
        response.client = self.client

        # Add 'response.client.cookies':
        # driver.get_cookies() is a simple list of dict items, e.g.:
        # [{'name': 'csrftoken', 'value': 'yXoN3...', ...},...]
        for cookie in self.driver.get_cookies():
            response.set_cookie(
                key=cookie["name"],
                value=cookie["value"],

                max_age=cookie["expiry"],

                path=cookie["path"],
                domain=cookie["domain"],
                secure=cookie["secure"],
            )

        # response.cookies and response.client.cookies
        # are django.http.cookies.SimpleCookie instances
        response.client.cookies.update(response.cookies)

        # Add 'response.session':
        response.session = self.client.session

        return response

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