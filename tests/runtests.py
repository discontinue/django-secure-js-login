#!/usr/bin/env python
# coding: utf-8

"""
    run unittests
    ~~~~~~~~~~~~~

    run all tests:

    ./runtests.py

    run only some tests, e.g.:

    ./runtests.py tests.test_file
    ./runtests.py tests.test_file.test_class
    ./runtests.py tests.test_file.test_class.test_method

    :copyleft: 2015 by the django-reversion-compare team, see AUTHORS for more details.
    :created: 2015 by JensDiemer.de
    :license: GNU GPL v3 or above, see LICENSE for more details.
"""

from __future__ import absolute_import, print_function

import os
os.environ['DJANGO_SETTINGS_MODULE'] = os.environ.get('DJANGO_SETTINGS_MODULE', 'tests.test_utils.test_settings')

import doctest
import sys
import time

import django
from django.conf import settings
from django.test.utils import get_runner

import secure_js_login


SKIP_DIRS = (".settings", ".git", "dist", "python_creole.egg-info")
SKIP_FILES = ("setup.py", "test.py")


def run_all_doctests(verbosity, base_path):
    """
    run all existing DocTests
    """
    start_time = time.time()

    if verbosity >= 2:
        print("")
        print("_" * 79)
        print("Running %r DocTests:\n" % base_path)

    total_files = 0
    total_doctests = 0
    total_attempted = 0
    total_failed = 0
    for root, dirs, filelist in os.walk(base_path, followlinks=True):
        for skip_dir in SKIP_DIRS:
            if skip_dir in dirs:
                dirs.remove(skip_dir) # don't visit this directories

        for filename in filelist:
            if not filename.endswith(".py"):
                continue
            if filename in SKIP_FILES:
                continue

            total_files += 1

            sys.path.insert(0, root)
            try:
                m = __import__(filename[:-3])
            except ImportError as err:
                if verbosity >= 2:
                    print("***DocTest import %s error*** %s" % (filename, err))
            except Exception as err:
                if verbosity >= 2:
                    print("***DocTest %s error*** %s" % (filename, err))
            else:
                failed, attempted = doctest.testmod(m)
                total_attempted += attempted
                total_failed += failed
                if attempted or failed:
                    total_doctests += 1

                if attempted and not failed:
                    filepath = os.path.join(root, filename)
                    if verbosity <= 1:
                        sys.stdout.write(".")
                    elif verbosity >= 2:
                        print("DocTest in %s OK (failed=%i, attempted=%i)" % (
                            filepath, failed, attempted
                        ))
            finally:
                del sys.path[0]

    duration = time.time() - start_time
    print("")
    print("-" * 70)
    print(" *** Ran %i DocTests from %i files in %.3fs: failed=%i, attempted=%i\n\n" % (
        total_doctests, total_files, duration, total_failed, total_attempted
    ))


def run_unittests(test_labels=None):
    django.setup()

    TestRunner = get_runner(settings)
    test_runner = TestRunner(
        verbosity=2,
        failfast=True,
    )

    if test_labels is None or test_labels == ["test"]:
        test_labels = ['tests']
    failures = test_runner.run_tests(test_labels)

    sys.exit(bool(failures))


def cli_run():
    if "-v" in sys.argv or "--verbosity" in sys.argv:
        verbosity = 2
    elif "-q" in sys.argv or "--quite" in sys.argv:
        verbosity = 0
    else:
        verbosity = 1

    if verbosity:
        print("DJANGO_SETTINGS_MODULE=%r" % os.environ['DJANGO_SETTINGS_MODULE'])

    base_path = os.path.abspath(os.path.dirname(secure_js_login.__file__))

    # verbosity=3
    run_all_doctests(verbosity, base_path)
    run_unittests(test_labels=sys.argv[1:])


if __name__ == "__main__":
    cli_run()


