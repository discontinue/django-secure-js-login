# coding: utf-8

from django.conf import settings


# Numbers login log messages after IP would be banned.
BAN_LIMIT = getattr(settings, "BAN_LIMIT", 6)

# Minimum pause in seconds between two login log messages from the same user. (Used 'REMOTE_ADDR')
MIN_PAUSE = getattr(settings, "MIN_PAUSE", 5)

# Enable login honypot?
USE_HONYPOT = getattr(settings, "USE_HONYPOT", False)

# Number of loops in PBKDF2 for hash based key stretching.
# Higher count increase the security, but causes more CPU load on client and server.
# The compute time of together 2000 iterations on a Raspberry Pi 1 and firefox are acceptable.
# django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher() used currently iterations = 24000
# Note:
#   * **ITERATIONS1** should be not changed if passwords already stored in database!
#   * **ITERATIONS2** can be changed very time!
ITERATIONS1 = getattr(settings, "ITERATIONS1", 24000) # for storing a part of the password in the database
ITERATIONS2 = getattr(settings, "ITERATIONS2", 24000) # for generate on-the-fly the server challenge

# Length of the generated PBKDF2 hash in bytes:
PBKDF2_BYTE_LENGTH = getattr(settings, "PBKDF2_BYTE_LENGTH", 32) # max length: 256 by model field!

# Length of random string values:
PBKDF2_SALT_LENGTH = getattr(settings, "PBKDF2_SALT_LENGTH", 12) # max length: 256 by model field!
RANDOM_CHALLENGE_LENGTH = getattr(settings, "RANDOM_CHALLENGE_LENGTH", 24)

# generated with SHA1 (Hex representation), so max length is: 40
CLIENT_NONCE_LENGTH = getattr(settings, "CLIENT_NONCE_LENGTH", 24)

# Use https (secure http) for login forms?
HTTPS_URLS = getattr(settings, "HTTPS_URLS", False)

# use 'User.set_password' monkey-patch in models.py for create password hashes
AUTO_CREATE_PASSWORD_HASH = getattr(settings, "AUTO_CREATE_PASSWORD_HASH", False)

# Used cache backend for:
#  * used cnonce
CACHE_NAME = getattr(settings, "CACHE_NAME", "default")

# Time-based One-time Password Algorithm (TOTP) needed for login?
# https://tools.ietf.org/html/rfc6238#section-4
TOTP_NEEDED = getattr(settings, "TOTP_NEEDED", False)