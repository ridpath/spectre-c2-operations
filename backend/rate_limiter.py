from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Dict, Tuple
import asyncio


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, requests_per_minute: int = 60, requests_per_hour: int = 1000):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.requests_per_hour = requests_per_hour
        self.minute_buckets: Dict[str, list] = defaultdict(list)
        self.hour_buckets: Dict[str, list] = defaultdict(list)
        self.lock = asyncio.Lock()
        self.cleanup_task = None
    
    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/health"):
            return await call_next(request)
        
        client_ip = self.get_client_ip(request)
        
        current_time = datetime.now(timezone.utc)
        
        async with self.lock:
            await self.check_rate_limit(client_ip, current_time)
        
        response = await call_next(request)
        return response
    
    def get_client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"
    
    async def check_rate_limit(self, client_ip: str, current_time: datetime):
        one_minute_ago = current_time - timedelta(minutes=1)
        one_hour_ago = current_time - timedelta(hours=1)
        
        self.minute_buckets[client_ip] = [
            ts for ts in self.minute_buckets[client_ip]
            if ts > one_minute_ago
        ]
        self.hour_buckets[client_ip] = [
            ts for ts in self.hour_buckets[client_ip]
            if ts > one_hour_ago
        ]
        
        minute_count = len(self.minute_buckets[client_ip])
        hour_count = len(self.hour_buckets[client_ip])
        
        if minute_count >= self.requests_per_minute:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded: {self.requests_per_minute} requests per minute. Try again later."
            )
        
        if hour_count >= self.requests_per_hour:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded: {self.requests_per_hour} requests per hour. Try again later."
            )
        
        self.minute_buckets[client_ip].append(current_time)
        self.hour_buckets[client_ip].append(current_time)
    
    async def cleanup_old_buckets(self):
        while True:
            await asyncio.sleep(300)
            
            async with self.lock:
                current_time = datetime.now(timezone.utc)
                one_hour_ago = current_time - timedelta(hours=1)
                
                ips_to_remove = []
                for ip in list(self.hour_buckets.keys()):
                    self.hour_buckets[ip] = [
                        ts for ts in self.hour_buckets[ip]
                        if ts > one_hour_ago
                    ]
                    
                    if not self.hour_buckets[ip]:
                        ips_to_remove.append(ip)
                
                for ip in ips_to_remove:
                    del self.hour_buckets[ip]
                    if ip in self.minute_buckets:
                        del self.minute_buckets[ip]


class EndpointRateLimiter:
    def __init__(self):
        self.limits: Dict[str, Tuple[int, int]] = {}
        self.buckets: Dict[str, Dict[str, list]] = defaultdict(lambda: defaultdict(list))
    
    def add_limit(self, endpoint: str, requests: int, window_seconds: int):
        self.limits[endpoint] = (requests, window_seconds)
    
    async def check_limit(self, endpoint: str, client_ip: str) -> bool:
        if endpoint not in self.limits:
            return True
        
        requests, window_seconds = self.limits[endpoint]
        current_time = datetime.now(timezone.utc)
        window_start = current_time - timedelta(seconds=window_seconds)
        
        self.buckets[endpoint][client_ip] = [
            ts for ts in self.buckets[endpoint][client_ip]
            if ts > window_start
        ]
        
        if len(self.buckets[endpoint][client_ip]) >= requests:
            return False
        
        self.buckets[endpoint][client_ip].append(current_time)
        return True


endpoint_limiter = EndpointRateLimiter()

endpoint_limiter.add_limit("/api/v1/auth/login", 5, 60)
endpoint_limiter.add_limit("/api/v1/auth/register", 3, 300)
endpoint_limiter.add_limit("/api/v1/vulnerabilities/scan", 10, 60)
endpoint_limiter.add_limit("/api/v1/evidence/upload", 20, 60)
endpoint_limiter.add_limit("/api/v1/iq/upload", 10, 60)


async def check_endpoint_rate_limit(request: Request):
    client_ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown")
    if client_ip and "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()
    
    endpoint = request.url.path
    
    if not await endpoint_limiter.check_limit(endpoint, client_ip):
        raise HTTPException(
            status_code=429,
            detail=f"Too many requests to {endpoint}. Please slow down."
        )
