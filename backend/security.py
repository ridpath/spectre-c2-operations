from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from typing import Callable
import re
from config import get_settings

settings = get_settings()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        
        if settings.ENVIRONMENT == "production":
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        
        return response


class HTTPSRedirectMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if settings.ENVIRONMENT == "production":
            if request.url.scheme != "https" and not request.url.path.startswith("/health"):
                forwarded_proto = request.headers.get("X-Forwarded-Proto")
                if forwarded_proto != "https":
                    url = request.url.replace(scheme="https")
                    return Response(
                        status_code=307,
                        headers={"Location": str(url)}
                    )
        
        return await call_next(request)


class SQLInjectionProtectionMiddleware(BaseHTTPMiddleware):
    SQL_INJECTION_PATTERNS = [
        r"(\bunion\b.*\bselect\b)",
        r"(\bselect\b.*\bfrom\b)",
        r"(\binsert\b.*\binto\b)",
        r"(\bupdate\b.*\bset\b)",
        r"(\bdelete\b.*\bfrom\b)",
        r"(\bdrop\b.*\btable\b)",
        r"(--)",
        r"(;.*--)",
        r"(\bor\b.*=.*)",
        r"(\band\b.*=.*)",
        r"('.*or.*'.*=.*')",
    ]
    
    def __init__(self, app):
        super().__init__(app)
        self.patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.SQL_INJECTION_PATTERNS]
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        query_string = str(request.url.query)
        
        for pattern in self.patterns:
            if pattern.search(query_string):
                raise HTTPException(
                    status_code=400,
                    detail="Invalid request detected"
                )
        
        if request.method in ["POST", "PUT", "PATCH"]:
            content_type = request.headers.get("content-type", "")
            if "application/json" in content_type:
                try:
                    body = await request.body()
                    body_str = body.decode("utf-8", errors="ignore")
                    
                    for pattern in self.patterns:
                        if pattern.search(body_str):
                            raise HTTPException(
                                status_code=400,
                                detail="Invalid request detected"
                            )
                except Exception:
                    pass
        
        return await call_next(request)


class IPWhitelistMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, whitelist: list = None):
        super().__init__(app)
        self.whitelist = whitelist or []
        self.enabled = len(self.whitelist) > 0
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not self.enabled:
            return await call_next(request)
        
        client_ip = self.get_client_ip(request)
        
        if client_ip not in self.whitelist and not any(
            self.ip_in_range(client_ip, allowed) for allowed in self.whitelist
        ):
            raise HTTPException(
                status_code=403,
                detail="Access denied from your IP address"
            )
        
        return await call_next(request)
    
    def get_client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"
    
    def ip_in_range(self, ip: str, cidr: str) -> bool:
        if "/" not in cidr:
            return ip == cidr
        
        try:
            import ipaddress
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
        except (ValueError, ImportError):
            return False


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_size: int = 1024 * 1024 * 1024):
        super().__init__(app)
        self.max_size = max_size
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        content_length = request.headers.get("content-length")
        
        if content_length and int(content_length) > self.max_size:
            raise HTTPException(
                status_code=413,
                detail=f"Request body too large. Maximum size: {self.max_size} bytes"
            )
        
        return await call_next(request)


def validate_environment():
    errors = []
    
    if settings.ENVIRONMENT == "production":
        if settings.JWT_SECRET_KEY == "CHANGE_THIS_IN_PRODUCTION_USE_STRONG_SECRET_KEY":
            errors.append("JWT_SECRET_KEY must be changed in production")
        
        if len(settings.JWT_SECRET_KEY) < 32:
            errors.append("JWT_SECRET_KEY must be at least 32 characters long")
        
        if "localhost" in settings.ALLOWED_HOSTS or "127.0.0.1" in settings.ALLOWED_HOSTS:
            errors.append("ALLOWED_HOSTS should not contain localhost in production")
        
        if not settings.DATABASE_URL.startswith("postgresql://"):
            errors.append("Production database must use PostgreSQL")
    
    if errors:
        error_msg = "\n".join([f"  - {error}" for error in errors])
        raise RuntimeError(
            f"\n\nProduction Security Configuration Errors:\n{error_msg}\n\n"
            "Please fix these issues before running in production mode.\n"
        )
    
    return True
