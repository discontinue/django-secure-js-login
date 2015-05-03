# coding: utf-8

from django.conf import settings


# Numbers login log messages after IP would be banned.
BAN_LIMIT = getattr(settings, "BAN_LIMIT", 6)

# Minimum pause in seconds between two login log messages from the same user. (Used 'REMOTE_ADDR')
MIN_PAUSE = getattr(settings, "MIN_PAUSE", 5)

# Enable login honypot?
USE_HONYPOT = getattr(settings, "USE_HONYPOT", False)

# Number of loops in the JS-SHA1-Process for repeatedly apply
# the client-nonce for hash based key stretching.
# (Note: Higher count increase the security, but causes more CPU load on client and server.)
LOOP_COUNT = getattr(settings, "LOOP_COUNT", 15)

# Use https (secure http) for login forms?
HTTPS_URLS = getattr(settings, "HTTPS_URLS", False)


