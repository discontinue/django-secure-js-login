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


PACKAGE_ROOT = os.path.dirname(os.path.abspath(__file__))


# convert README.creole on-the-fly to ReSt, see also:
# https://github.com/jedie/python-creole/wiki/Use-In-Setup/
check_readme="publish" in sys.argv or "check" in sys.argv or "register" in sys.argv or "sdist" in sys.argv or "--long-description" in sys.argv
try:
    from creole.setup_utils import get_long_description
except ImportError as err:
    if check_readme:
        raise ImportError("%s - Please install python-creole >= v0.8 -  e.g.: pip install python-creole" % err)
    long_description = None
else:
    if check_readme:
        print("\nCheck creole2ReSt:")
    long_description = get_long_description(PACKAGE_ROOT)
    if check_readme:
        print("OK")


if "publish" in sys.argv:
    """
    Build and upload to PyPi, if...
        ... __version__ doesn't contains "dev"
        ... we are on git 'master' branch
        ... git repository is 'clean' (no changed files)

    Upload with "twine", git tag the current version and git push --tag

    The cli arguments will be pass to 'twine'. So this is possible:
     * Display 'twine' help page...: ./setup.py publish --help
     * use testpypi................: ./setup.py publish --repository=test

    TODO: Look at: https://github.com/zestsoftware/zest.releaser
    """
    # Imports here, so it's easier to copy&paste this complete code block ;)
    import subprocess
    import shutil

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

    try:
        import twine
    except ImportError as err:
        print("\nError: %s" % err)
        print("\nMaybe https://pypi.python.org/pypi/twine is not installed or virtualenv not activated?!?")
        print("e.g.:")
        print("    ~/your/env/$ source bin/activate")
        print("    ~/your/env/$ pip install twine")
        sys.exit(-1)

    def verbose_check_output(*args):
        """ 'verbose' version of subprocess.check_output() """
        call_info = "Call: %r" % " ".join(args)
        try:
            output = subprocess.check_output(args, universal_newlines=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as err:
            print("\n***ERROR:")
            print(err.output)
            raise
        return call_info, output

    def verbose_check_call(*args):
        """ 'verbose' version of subprocess.check_call() """
        print("\tCall: %r\n" % " ".join(args))
        subprocess.check_call(args, universal_newlines=True)

    if "dev" in __version__:
        print("\nERROR: Version contains 'dev': v%s\n" % __version__)
        sys.exit(-1)

    print("\nCheck if we are on 'master' branch:")
    call_info, output = verbose_check_output("git", "branch", "--no-color")
    print("\t%s" % call_info)
    if "* master" in output:
        print("OK")
    else:
        print("\nNOTE: It seems you are not on 'master':")
        print(output)
        if input("\nPublish anyhow? (Y/N)").lower() not in ("y", "j"):
            print("Bye.")
            sys.exit(-1)

    print("\ncheck if if git repro is clean:")
    call_info, output = verbose_check_output("git", "status", "--porcelain")
    print("\t%s" % call_info)
    if output == "":
        print("OK")
    else:
        print("\n *** ERROR: git repro not clean:")
        print(output)
        sys.exit(-1)

    print("\ncheck if pull is needed")
    verbose_check_call("git", "fetch", "--all")
    call_info, output = verbose_check_output("git", "log", "HEAD..origin/master", "--oneline")
    print("\t%s" % call_info)
    if output == "":
        print("OK")
    else:
        print("\n *** ERROR: git repro is not up-to-date:")
        print(output)
        sys.exit(-1)
    verbose_check_call("git", "push")

    print("\nCleanup old builds:")
    def rmtree(path):
        path = os.path.abspath(path)
        if os.path.isdir(path):
            print("\tremove tree:", path)
            shutil.rmtree(path)
    rmtree("./dist")
    rmtree("./build")

    print("\nbuild but don't upload...")
    log_filename="build.log"
    with open(log_filename, "a") as log:
        call_info, output = verbose_check_output(
            sys.executable or "python",
            "setup.py", "sdist", "bdist_wheel", "bdist_egg"
        )
        print("\t%s" % call_info)
        log.write(call_info)
        log.write(output)
    print("Build output is in log file: %r" % log_filename)

    print("\ngit tag version (will raise a error of tag already exists)")
    verbose_check_call("git", "tag", "v%s" % __version__)

    print("\nUpload with twine:")
    twine_args = sys.argv[1:]
    twine_args.remove("publish")
    twine_args.insert(1, "dist/*")
    print("\ttwine upload command args: %r" % " ".join(twine_args))
    from twine.commands.upload import main as twine_upload
    twine_upload(twine_args)

    print("\ngit push tag to server")
    verbose_check_call("git", "push", "--tags")

    sys.exit(0)


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
        "django-tools>=0.29.2",  # https://github.com/jedie/django-tools/
    ],
    classifiers=[
       # 'Development Status :: 1 - Planning',
       # 'Development Status :: 2 - Pre-Alpha',
       'Development Status :: 3 - Alpha',
       # "Development Status :: 4 - Beta",
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
