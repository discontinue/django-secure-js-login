import os

# set: DJANGO_SETTINGS_MODULE:tests.test_settings to run the tests
assert os.environ["DJANGO_SETTINGS_MODULE"]=="tests.test_settings"

from django.conf import settings
from django.contrib.staticfiles.testing import StaticLiveServerTestCase
from selenium import webdriver
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions

from tests.test_utils.test_cases import UserTestCaseMixin


class SeleniumTests(StaticLiveServerTestCase, UserTestCaseMixin):
    @classmethod
    def setUpClass(cls):
        super(SeleniumTests, cls).setUpClass()
        cls.firefox = webdriver.Firefox()
        cls.firefox.implicitly_wait(1)

    @classmethod
    def tearDownClass(cls):
        cls.firefox.quit()
        super(SeleniumTests, cls).tearDownClass()

    def setUp(self):
        super(SeleniumTests, self).setUp()
        self.firefox.delete_all_cookies()
        self.TEST_SUPERUSER = self.create_and_get_superuser()

    def test_example_index_page(self):
        self.firefox.get('%s%s' % (self.live_server_url, '/'))
        self.assertEqual(self.firefox.title,
            "Django secure-js-login example project"
        )
        page_source = self.firefox.page_source
        self.assertIn('<a href="/secure_login/">', page_source)
        self.assertIn('<a href="/login/">', page_source) # honypot login
        self.assertIn('<a href="/admin/">', page_source) # Django Admin login

    def test_django_plaintext_login_succsess(self):
        self.firefox.get('%s%s' % (self.live_server_url, "/admin/"))
        # print(self.firefox.page_source)
        self.assertEqual(self.firefox.title, "Log in | Django site admin")

        username_input = self.firefox.find_element_by_name("username")
        username_input.send_keys(self.SUPER_USER_NAME)
        password_input = self.firefox.find_element_by_name("password")
        password_input.send_keys(self.SUPER_USER_PASS)
        self.firefox.find_element_by_xpath('//input[@value="Log in"]').click()

        page_source = self.firefox.page_source
        self.assertNotIn("Error", page_source)

        self.assertEqual(self.firefox.title, "Site administration | Django site admin")
        self.assertIn(self.SUPER_USER_NAME, page_source)
        self.assertIn("Log out", page_source)

    def test_django_plaintext_login_wrong_password(self):
        self.firefox.get('%s%s' % (self.live_server_url, "/admin/"))
        # print(self.firefox.page_source)
        self.assertEqual(self.firefox.title, "Log in | Django site admin")

        username_input = self.firefox.find_element_by_name("username")
        username_input.send_keys(self.SUPER_USER_NAME)
        password_input = self.firefox.find_element_by_name("password")
        password_input.send_keys("wrong password")
        self.firefox.find_element_by_xpath('//input[@value="Log in"]').click()
        # print(self.firefox.page_source)

        self.assertEqual(self.firefox.title, "Log in | Django site admin")
        self.assertIn(
            "Please enter the correct username and password for a staff account.",
            self.firefox.page_source
        )

    def test_secure_login(self):
        self.firefox.get('%s%s' % (self.live_server_url, '/secure_login/'))
        # print(self.firefox.page_source)

        # self.assertInHTML( # Will failed, because tags are escaped inner noscript, why?
        #     '<noscript><p class="errornote">Please enable JavaScript!</p></noscript>',
        #     self.firefox.page_source
        # )
        self.assertIn('<noscript>', self.firefox.page_source)
        self.assertIn("Please enable JavaScript!", self.firefox.page_source)

        # Test if precheck was ok
        self.assertEqual(
            self.firefox.execute_script('return precheck_secure;'),
            True
        )

        # Test if username/password is empty:
        self.assertEqual(
            self.firefox.execute_script('return $(ID_USERNAME).val();'),
            ""
        )
        self.assertEqual(
            self.firefox.execute_script('return $(ID_PASSWORD).val();'),
            ""
        )

        username_input = self.firefox.find_element_by_name("username")
        username_input.send_keys(self.SUPER_USER_NAME)
        password_input = self.firefox.find_element_by_name("password")
        password_input.send_keys(self.SUPER_USER_PASS)

        # Check if username/password are "visible" from JavaScript
        self.assertEqual(
            self.firefox.execute_script('return $(ID_USERNAME).val();'),
            self.SUPER_USER_NAME
        )
        self.assertEqual(
            self.firefox.execute_script('return $(ID_PASSWORD).val();'),
            self.SUPER_USER_PASS
        )

        # Submit the Form
        self.firefox.find_element_by_xpath('//input[@value="Log in"]').click()

        # Wait until hashes are calculated and new page loaded:
        check = WebDriverWait(self.firefox, 10).until(
            expected_conditions.invisibility_of_element_located(
                (By.NAME, "password")
            )
        )
        self.assertTrue(check)

        # Check new loaded page content:
        self.assertIn("You are logged in.", self.firefox.page_source)
        self.assertIn("Last login was:", self.firefox.page_source)
        self.assertIn(self.SUPER_USER_NAME, self.firefox.page_source)
        self.assertIn("Log out", self.firefox.page_source)
        self.assertNotIn("Error", self.firefox.page_source)
