# coding: utf-8


"""
    PyLucid JS-SHA-Login tests
    ~~~~~~~~~~~~~~~~~~~~~~~~~~
    
    A secure JavaScript SHA-1 Login and a plaintext fallback login.
    
    TODO: Add test for honypot, too.
    
    :copyleft: 2010-2012 by the PyLucid team, see AUTHORS for more details.
    :license: GNU GPL v3 or above, see LICENSE for more details
"""


import os
import sys
import hashlib

if __name__ == "__main__":
    # Run all unittest directly

    tests = __file__
#    tests = "pylucid_plugins.auth.tests.LoginTest.test_login_ajax_form"
#    tests = "pylucid_plugins.auth.tests.LoginTest.test_get_salt_csrf"
#    tests = "pylucid_plugins.auth.tests.LoginTest.test_get_salt_with_wrong_csrf_token"
#    tests = "pylucid_plugins.auth.tests.LoginTest.test_complete_login"

    from pylucid_project.tests import run_test_directly
    run_test_directly(tests,
        verbosity=2,
#        failfast=True,
        failfast=False,
    )
    sys.exit()

from django.core.cache import cache
from django.conf import settings
from django.test.client import Client

from pylucid_project.tests.test_tools import basetest
from pylucid_project.utils import crypt

from preference_forms import AuthPreferencesForm


LOGIN_URL = "/en/welcome/?auth=login"


class LoginTest(basetest.BaseUnittest):
    def setUp(self):
        settings.DEBUG = False
        self.client = Client() # start a new session

    def test_login_link(self):
        response = self.client.get("/en/welcome/")
        self.assertDOM(response,
            must_contain=(
                '''<a href="#top" id="login_link" rel="nofollow" onclick="return get_pylucid_ajax_view('?auth=login');">Log in</a>''',
            )
        )

    def test_admin_login_page(self):
        """ Simple check if login link exist. """
        response = self.client.get("/admin/", HTTP_ACCEPT_LANGUAGE="en")
        self.assertAdminLoginPage(response)

    def test_login_redirect(self):
        """
        Check login redirect
        http://github.com/jedie/PyLucid/issues#issue/6
        """
        response = self.client.get("/pylucid_admin/menu/", HTTP_ACCEPT_LANGUAGE="en")
        self.assertRedirect(response, "http://testserver/admin/?next=/pylucid_admin/menu/")

    def test_non_ajax_request_with_debug(self):
        settings.DEBUG = True
        cache.clear()
        response = self.client.get(LOGIN_URL)
        self.assertResponse(response,
            must_contain=(
                "<!DOCTYPE", "<title>PyLucid CMS", "<body", "<head>", # <- a complete page
                "Enable non AJAX login request, because DEBUG is on.", # debug page messages
                "JS-SHA-LogIn", "username", "var challenge=",
            ),
            must_not_contain=("Traceback", 'Permission denied')
        )

    def test_non_ajax_request_without_debug(self):
        settings.DEBUG = False
        cache.clear()
        response = self.client.get(LOGIN_URL)
        self.assertResponse(response,
            must_contain=(
                "<!DOCTYPE", "<title>PyLucid CMS", "<body", "<head>", # <- a complete page
            ),
            must_not_contain=(
                "Traceback", 'Permission denied',
                '<div class="PyLucidPlugins auth" id="auth_http_get_view">',
                "JS-SHA-LogIn", "username", "var challenge=",
            ),
        )

    def test_login_ajax_form(self):
        """ Check if we get the login form via AJAX
        FIXME: We get no ajax response, if unittests runs all tests, but it works
        if only this test runs, why?
        """
        response = self.client.get(LOGIN_URL, HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        self.assertStatusCode(response, 200)
        self.assertDOM(response,
            must_contain=(
                '<input id="submit_button" type="submit" value="Log in" />',
            )
        )
        self.assertResponse(response,
            must_contain=(
                '<div class="PyLucidPlugins auth" id="auth_http_get_view">',
                "JS-SHA-LogIn", "username",
                # outside from django-compressor section:
                "var challenge=", "var next_url=",
            ),
            must_not_contain=(
                "<!DOCTYPE", "<title>PyLucid CMS", "<body", "<head>", # <- not a complete page
                "Traceback", 'Permission denied'
            ),
        )

    def test_DOS_attack(self):
        settings.DEBUG = True

        client = self.client
        userdata = self._get_userdata("normal")
        username = userdata["username"]
#        self.login("normal")
#        client.logout()

        # Get the login form: The challenge value would be stored into session
        client.get("/en/welcome/?auth=login", HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        self.failUnless("challenge" in client.session)

        pref_form = AuthPreferencesForm()
        preferences = pref_form.get_preferences()
        ban_limit = preferences["ban_limit"]

        # Hold if all events would been received.
        tested_first_login = False
        tested_under_limit = False
        tested_limit_reached = False
        tested_banned = False

        for no in xrange(1, ban_limit + 3):
            # get the salt
            response1 = client.post(
                "/en/welcome/?auth=get_salt", {"username": username}, HTTP_X_REQUESTED_WITH='XMLHttpRequest'
            )

            response2 = client.post(
                "/en/welcome/?auth=sha_auth",
                {
                    "username": username,
                    "sha_a2": "0123456789abcdef0123456789abcdef01234567",
                    "sha_b": "0123456789abcdef0123",
                },
                HTTP_X_REQUESTED_WITH='XMLHttpRequest'
            )

            if no == 1:
                # first request, normal failed
                self.assertStatusCode(response1, 200)
                self.assertStatusCode(response2, 200)
                tested_first_login = True
                self.failUnless(len(response1.content) == 5) # the salt          
                self.assertResponse(response2,
                    must_contain=(
                        'auth.authenticate() failed.',
                        'must be a wrong password)',
                    ),
                    must_not_contain=(
                        "Traceback", "Form errors", "field is required",
                        "<!DOCTYPE", "<body", "</html>",
                    )
                )
            elif no == ban_limit + 1:
                # The limit has been reached
                tested_banned = True
                self.assertResponse(response2, must_contain=('You are now banned.',))
                self.assertStatusCode(response2, 404)
                self.failUnless(len(response1.content) == 5) # the salt
            elif no > ban_limit:
                # IP is on the ban list
                tested_limit_reached = True
                self.assertStatusCode(response1, 403) # get forbidden page
                self.assertStatusCode(response2, 403) # get forbidden page
            else:
                # under ban limit: comment was saved, page should be reloaded
                tested_under_limit = True
                self.assertStatusCode(response1, 200)
                self.assertStatusCode(response2, 200)
                self.failUnless(len(response1.content) == 5) # the salt
                self.assertResponse(response2,
                    must_contain=(
                        'Request too fast!',
                        'IP is blocked by',
                    ),
                    must_not_contain=(
                        "Traceback", "Form errors", "field is required",
                        "<!DOCTYPE", "<body", "</html>",
                    )
                )

        # Check if all events have been received.
        self.failUnless(tested_first_login == True)
        self.failUnless(tested_limit_reached == True)
        self.failUnless(tested_under_limit == True)
        self.failUnless(tested_banned == True)

    def test_get_salt_with_wrong_csrf_token(self):
        settings.DEBUG = True
        user = self._get_user("normal")
        username = user.username
        user_profile = user.get_profile()
        salt = user_profile.sha_login_salt

        csrf_client = Client(enforce_csrf_checks=True)

        # Create session
        response = csrf_client.get(LOGIN_URL,
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
        )
        self.assertStatusCode(response, 200)
        sessionid = response.cookies["sessionid"]

        # send POST with sessionid but with wrong csrf token
        response = csrf_client.post(
            "/en/welcome/?auth=get_salt",
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
            HTTP_COOKIE=(
                "%s=1234567890abcdef1234567890abcdef;"
                "sessionid=%s"
            ) % (settings.CSRF_COOKIE_NAME, sessionid),
            data={
                "username": username,
            }
        )
        self.assertResponse(response,
            must_contain=(
                'Forbidden', 'CSRF verification failed.',
                'CSRF token missing or incorrect.',
            ),
            must_not_contain=(
                salt,
                "Traceback", "Form errors", "field is required",
            )
        )

    def test_get_salt_csrf(self):
        """
        https://github.com/jedie/PyLucid/issues/61
        """
        settings.DEBUG = True

        user = self._get_user("normal")
        username = user.username
        user_profile = user.get_profile()
        salt = user_profile.sha_login_salt

        csrf_client = Client(enforce_csrf_checks=True)

        response = csrf_client.get("/en/welcome/") # Put page into cache
        self.assertStatusCode(response, 200)

        # Get the CSRF token
        response = csrf_client.get(LOGIN_URL,
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
        )
        self.assertStatusCode(response, 200)
        csrf_cookie = response.cookies[settings.CSRF_COOKIE_NAME]
        csrf_token = csrf_cookie.value

        self.assertResponse(response,
            must_contain=(
                '<p id="load_info">loading...</p>',
            ),
            must_not_contain=(
                "Traceback", "Form errors", "field is required",
                csrf_token,
                "<!DOCTYPE", "<title>PyLucid CMS", "<body", "<head>", # <- not a complete page
            )
        )

        # Check if we get the salt, instead of a CSRF error
        response = csrf_client.post(
            "/en/welcome/?auth=get_salt",
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
            HTTP_X_CSRFTOKEN=csrf_token,
            data={
                "username": username,
            }
        )
        if response.content != salt:
            self.raise_browser_traceback(response,
                "Response content is not salt %r - content: %r" % (salt, response.content)
            )

        # remove client cookie and check if csrf protection works
        del(csrf_client.cookies[settings.CSRF_COOKIE_NAME])
        response = csrf_client.post(
            "/en/welcome/?auth=get_salt",
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
            data={
                "username": username,
            }
        )
        self.assertResponse(response,
            must_contain=(
                'Forbidden', 'CSRF verification failed.',
                'CSRF cookie not set.',
            ),
            must_not_contain=(
                salt, csrf_token,
                "Traceback", "Form errors", "field is required",
            )
        )

    def test_complete_login(self):
        cache.clear()

        test_userdata = self._get_userdata("normal")
        userpass = test_userdata["password"]

        user = self._get_user("normal")
        username = user.username


        csrf_client = Client(enforce_csrf_checks=True)

        response = csrf_client.get("/en/welcome/") # Put page into cache
        self.assertStatusCode(response, 200)

        # Get the CSRF token
        response = csrf_client.get(LOGIN_URL, HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        csrf_cookie = response.cookies[settings.CSRF_COOKIE_NAME]
        csrf_token = csrf_cookie.value

        challenge = csrf_client.session["challenge"]
        self.assertResponse(response,
            must_contain=('var challenge="%s";' % challenge),
            must_not_contain=("Traceback", 'Permission denied'),
        )
        self.assertEqual(len(challenge), crypt.HASH_LEN)

        # Get the salt via AJAX
        response = csrf_client.post("/en/welcome/?auth=get_salt",
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
            HTTP_X_CSRFTOKEN=csrf_token,
            data={"username": username}
        )
        salt = response.content
        self.assertEqual(len(salt), crypt.SALT_LEN)

        # Build the response:
        shapass = hashlib.sha1(salt + userpass).hexdigest()
        sha_a = shapass[:20]
        sha_a2 = hashlib.sha1(challenge + sha_a).hexdigest()
        sha_b = shapass[20:]

        # Login with calculated sha pass
        response = csrf_client.post("/en/welcome/?auth=sha_auth",
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
            HTTP_X_CSRFTOKEN=csrf_token,
            data={
                "username": username,
                "sha_a2": sha_a2,
                "sha_b": sha_b,
            }
        )
        self.assertStatusCode(response, 200)
        self.assertResponse(response,
            must_contain=('OK',), must_not_contain=("Traceback", "error")
        )
        self.assertEqual(response.content, "OK")

        # Check if we are really login:
        response = csrf_client.get("/en/welcome/")
        self.assertResponse(response,
            must_contain=(
                "You are logged in. Last login was:",
                '<a href="?auth=logout">Log out [%s]</a>' % username
            ),
            must_not_contain=(
                'Forbidden', 'CSRF verification failed.',
                'CSRF cookie not set.',
                "Traceback", "Form errors", "field is required",
            )
        )


