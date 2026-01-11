"""Simple in-memory caching for frequently accessed data"""

from typing import Any, Optional, Dict
from datetime import datetime, timedelta
from functools import wraps
import hashlib
import json
from config import get_settings

settings = get_settings()


class SimpleCache:
    def __init__(self):
        self._cache: Dict[str, Dict[str, Any]] = {}
        self.enabled = settings.CACHE_ENABLED
        self.default_ttl = settings.CACHE_TTL_SECONDS
    
    def _make_key(self, *args, **kwargs) -> str:
        """Create cache key from function arguments"""
        key_data = str(args) + str(sorted(kwargs.items()))
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        if not self.enabled:
            return None
        
        if key in self._cache:
            entry = self._cache[key]
            if datetime.utcnow() < entry['expires']:
                return entry['value']
            else:
                del self._cache[key]
        return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set value in cache with TTL"""
        if not self.enabled:
            return
        
        ttl = ttl or self.default_ttl
        self._cache[key] = {
            'value': value,
            'expires': datetime.utcnow() + timedelta(seconds=ttl),
            'created': datetime.utcnow()
        }
    
    def delete(self, key: str):
        """Delete specific cache entry"""
        if key in self._cache:
            del self._cache[key]
    
    def clear(self):
        """Clear all cache entries"""
        self._cache.clear()
    
    def clean_expired(self):
        """Remove expired entries"""
        now = datetime.utcnow()
        expired_keys = [k for k, v in self._cache.items() if now >= v['expires']]
        for key in expired_keys:
            del self._cache[key]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        self.clean_expired()
        return {
            'enabled': self.enabled,
            'entries': len(self._cache),
            'ttl_seconds': self.default_ttl
        }


cache = SimpleCache()


def cached(ttl: Optional[int] = None, key_prefix: str = ""):
    """Decorator for caching function results"""
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            if not cache.enabled:
                return await func(*args, **kwargs)
            
            cache_key = f"{key_prefix}:{func.__name__}:{cache._make_key(*args, **kwargs)}"
            
            cached_value = cache.get(cache_key)
            if cached_value is not None:
                return cached_value
            
            result = await func(*args, **kwargs)
            cache.set(cache_key, result, ttl)
            return result
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            if not cache.enabled:
                return func(*args, **kwargs)
            
            cache_key = f"{key_prefix}:{func.__name__}:{cache._make_key(*args, **kwargs)}"
            
            cached_value = cache.get(cache_key)
            if cached_value is not None:
                return cached_value
            
            result = func(*args, **kwargs)
            cache.set(cache_key, result, ttl)
            return result
        
        import inspect
        if inspect.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator
