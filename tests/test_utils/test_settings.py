
from example_project.example_project.settings import *

DEBUG=False

ROOT_URLCONF = 'example_project.example_project.urls'

# For faster unittests:
ITERATIONS1 = 5
ITERATIONS2 = 10

PBKDF2_BYTE_LENGTH = 12

PBKDF2_SALT_LENGTH = 5
RANDOM_CHALLENGE_LENGTH = 6
CLIENT_NONCE_LENGTH = 8

# Two-way verification with Time-based One-time Password (TOTP):
TOTP_NEEDED = False