from django.dispatch import Signal

secure_js_login_failed = Signal(providing_args=["reason"])


