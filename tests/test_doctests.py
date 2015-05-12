import os
import unittest
import doctest
import sys

from django.utils import six

import secure_js_login


SKIP_DIRS = (".settings", ".git", "dist", ".egg-info")
SKIP_FILES = ("setup.py", "test.py")


def get_all_doctests(base_path, verbose=False):
    suites = []
    for root, dirs, filelist in os.walk(base_path, followlinks=True):
        for skip_dir in SKIP_DIRS:
            if skip_dir in dirs:
                dirs.remove(skip_dir) # don't visit this directories

        for filename in filelist:
            if not filename.endswith(".py"):
                continue
            if filename in SKIP_FILES:
                continue

            sys.path.insert(0, root)
            try:
                module = __import__(filename[:-3])
            except ImportError as err:
                if verbose:
                    print(
                        "\tDocTest import %s error %s" % (filename, err),
                        file=sys.stderr
                    )
            except Exception as err:
                if verbose:
                    print(
                        "\tDocTest %s error %s" % (filename, err),
                        file=sys.stderr
                    )
            else:
                try:
                    suite = doctest.DocTestSuite(module)
                except ValueError: # has no docstrings
                    continue

                test_count = suite.countTestCases()
                if test_count<1:
                    if verbose:
                        print(
                            "\tNo DocTests in %r" % module.__name__,
                            file=sys.stderr
                        )
                    continue

                if verbose:
                    file_info = module.__file__
                else:
                    file_info = module.__name__
                print(
                    "\t%i DocTests in %r" % (test_count,file_info),
                    file=sys.stderr
                )
                suites.append((module,suite))
            finally:
                del sys.path[0]

    return suites


class TestDoctests(unittest.TestCase):
    def run_doctest(self, module, suite):
        module_name = module.__name__
        print("Run DocTests in %r..." % module_name, file=sys.stderr)

        result = self.defaultTestResult()

        old_stdout = sys.stdout
        sys.stdout = sys.stderr
        try:
            suite.run(result)
        finally:
            sys.stdout = old_stdout

        msg = "Doctest %r results: run=%i errors=%i failures=%i" % (
            module_name, result.testsRun, len(result.errors), len(result.failures)
        )
        self.assertEqual(len(result.errors), 0, msg)
        self.assertEqual(len(result.failures), 0, msg)
        print(msg, file=sys.stderr)

    @unittest.skipIf(six.PY2, "DocTests are for Python 3")
    def test_doctests(self):
        print("\ncollect DocTests:", file=sys.stderr)
        path = os.path.abspath(os.path.dirname(secure_js_login.__file__))
        suites = get_all_doctests(
            base_path=path,
            # verbose=True
        )
        for module, suite in suites:
            self.run_doctest(module, suite)