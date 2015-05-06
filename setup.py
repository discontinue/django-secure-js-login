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

from secure_js_login import VERSION_STRING


if "publish" in sys.argv:
    import subprocess
    args = [sys.executable or "python", "setup.py", "sdist", "bdist_wheel", "upload"]
    print("\nCall: %r\n" %  " ".join(args))
    subprocess.call(args)

    print("\nDon't forget to tag this version, e.g.:")
    print("\tgit tag v%s" % VERSION_STRING)
    print("\tgit push --tags")
    sys.exit()


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



setup_info = dict(
    name='django-secure-js-login',
    version=VERSION_STRING,
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
    test_suite="runtests.run_tests",
)
setup(**setup_info)
