
from django.core.cache import get_cache

class AppCache(object):
    KEY_PREFIX="secure-js-login"
    def __init__(self, backend, key_suffix, timeout):
        self.cache = get_cache(backend)
        self.key_prefix = "%s_%s_" % (self.KEY_PREFIX, key_suffix)
        self.timeout = timeout

    def exists_or_add(self, key):
        if self.cache.get(self.key_prefix + key) is None:
            self.cache.set(self.key_prefix + key, True, self.timeout)
            return False
        return True