#!/usr/bin/env python
# coding: utf-8

from __future__ import absolute_import, print_function

import os
import string

os.environ['DJANGO_SETTINGS_MODULE'] = 'tests.test_utils.test_settings'

from django.contrib.auth.hashers import PBKDF2PasswordHasher

hasher = PBKDF2PasswordHasher()
foo_text = "foo"
source_text = string.printable * 10


def hash_foo():
    hasher.encode(password=foo_text, salt="123")

def hash_source_text():
    hasher.encode(password=source_text, salt="123")


def compare(source_text, timeit_number):
    print("\nPBKDF2('foo')........\t", end="", flush=True)
    duration1 = timeit.timeit(
        "hash_foo()", setup="from __main__ import hash_foo", number=timeit_number
    )
    print("takes: %.2fs (timeit loops: %i)" % (duration1, timeit_number))

    print("PBKDF2(%.2f KB text)..\t" % (len(source_text)/1024), end="", flush=True)
    duration2 = timeit.timeit(
        "hash_source_text()", setup="from __main__ import hash_source_text", number=timeit_number
    )
    print("takes: %.2fs (timeit loops: %i)" % (duration2, timeit_number))


if __name__ == '__main__':
    import timeit

    # compare(source_text=string.printable * 10, timeit_number=50)
    # compare(source_text=string.printable * 100, timeit_number=50)
    # compare(source_text=string.printable * 1000, timeit_number=20)
    # compare(source_text=string.printable * 10000, timeit_number=10)
    # compare(source_text=string.printable * 100000, timeit_number=100)
    compare(source_text=string.printable * 10000000, timeit_number=10)




