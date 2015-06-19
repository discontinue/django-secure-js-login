#!/usr/bin/env python
# coding: utf-8

"""
    secure_js_login distutils setup
    ~~~~~~~~~~~~~~~~~~~~~~~
    
    Links
    ~~~~~
    
    http://www.python-forum.de/viewtopic.php?f=21&t=26895 (de)

    :copyleft: 2009-2015 by the secure_js_login team, see AUTHORS for more details.
    :license: GNU GPL v3 or above, see LICENSE for more details.
"""

from __future__ import absolute_import, division, print_function


import os
import sys

from setuptools import setup, find_packages

from secure_js_login import __version__


if "publish" in sys.argv:
    try:
        # Test if wheel is installed, otherwise the user will only see:
        #   error: invalid command 'bdist_wheel'
        import wheel
    except ImportError as err:
        print("\nError: %s" % err)
        print("\nMaybe https://pypi.python.org/pypi/wheel is not installed or virtualenv not activated?!?")
        print("e.g.:")
        print("    ~/your/env/$ source bin/activate")
        print("    ~/your/env/$ pip install wheel")
        sys.exit(-1)

    if "dev" in __version__:
        print("\nERROR: Version contains 'dev': v%s\n" % __version__)
        sys.exit(-1)

    import subprocess

    def verbose_check_output(*args):
        print("\nCall: %r\n" %  " ".join(args))
        try:
            return subprocess.check_output(args, universal_newlines=True)
        except subprocess.CalledProcessError as err:
            print("\n***ERROR:")
            print(err.output)
            raise

    def verbose_check_call(*args):
        print("\nCall: %r\n" %  " ".join(args))
        subprocess.check_call(args, universal_newlines=True)

    # Check if we are on 'master' branch:
    output = verbose_check_output("git", "branch", "--no-color")
    if "* master" in output:
        print("OK")
    else:
        print("\nNOTE: It seems you are not on 'master':")
        print(output)
        if input("\nPublish anyhow? (Y/N)").lower() not in ("y", "j"):
            print("Bye.")
            sys.exit(-1)

    # publish only if git repro is clean:
    output = verbose_check_output("git", "status", "--porcelain")
    if output == "":
        print("OK")
    else:
        print("\n***ERROR: git repro not clean:")
        print(output)
        sys.exit(-1)

    # tag first (will raise a error of tag already exists)
    verbose_check_call("git", "tag", "v%s" % __version__)

    # build and upload to PyPi:
    verbose_check_call(sys.executable or "python", "setup.py", "sdist", "bdist_wheel", "upload")

    # push
    verbose_check_call("git", "push")
    verbose_check_call("git", "push", "--tags")

    sys.exit(0)


PACKAGE_ROOT = os.path.dirname(os.path.abspath(__file__))


# convert creole to ReSt on-the-fly, see also:
# https://code.google.com/p/python-creole/wiki/UseInSetup
try:
    from creole.setup_utils import get_long_description
except ImportError as err:
    if "check" in sys.argv or "register" in sys.argv or "sdist" in sys.argv or "--long-description" in sys.argv:
        raise ImportError("%s - Please install python-creole >= v0.8 - e.g.: pip install python-creole" % err)
    long_description = None
else:
    long_description = get_long_description(PACKAGE_ROOT)


def get_authors():
    try:
        with open(os.path.join(PACKAGE_ROOT, "AUTHORS"), "r") as f:
            authors = [l.strip(" *\r\n") for l in f if l.strip().startswith("*")]
    except Exception as err:
        authors = "[Error: %s]" % err
    return authors


setup(
    name='django-secure-js-login',
    version=__version__,
    description='JavaScript Challenge-handshake authentication django app',
    long_description=long_description,
    author=get_authors(),
    maintainer="Jens Diemer",
    url='https://github.com/jedie/django-secure-js-login',
    packages=find_packages(),
    include_package_data=True, # include package data under version control
    # test_suite = "runtests.run_tests",
    zip_safe=False,
    install_requires=[
        "Django>=1.7,<1.9",
        "django-otp>=0.3.1,<0.4",
    ],
    tests_require=[
        "selenium", # https://pypi.python.org/pypi/selenium
        "django-tools",  # https://github.com/jedie/django-tools/
    ],
    classifiers=[
       # 'Development Status :: 1 - Planning',
       # 'Development Status :: 2 - Pre-Alpha',
       # 'Development Status :: 3 - Alpha',
       "Development Status :: 4 - Beta",
       #  "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License (GPL)",
        "Programming Language :: Python",
        "Programming Language :: JavaScript",
        'Framework :: Django',
        "Topic :: Database :: Front-Ends",
        "Topic :: Documentation",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Internet :: WWW/HTTP :: Site Management",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Application",
        "Operating System :: OS Independent",
    ],
    test_suite="runtests.cli_run",
)
