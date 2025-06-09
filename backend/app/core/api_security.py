# Comprehensive API security middleware and endpoint protection

import time
import json
import logging
from typing import Dict, Any, Optional, List, Callable
from datetime import datetime, timedelta
from functools import wraps

from fastapi import Request, Response, HTTPException, status, Depends
from fastapi.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import RequestResponseEndpoint
import httpx

from ..core.security_enhanced import security_manager, rate_limit_check
from ..core.authorization import (
    auth_manager, 
    Permission, 
    require_permission,
    auth_auditor,
    audit_access
)

logger = logging.getLogger(__name__)

class APISecurityMiddleware(BaseHTTPMiddleware):
    """Comprehensive API security middleware."""
    
    def __init__(self, app, config: Optional[Dict[str, Any]] = None):
        super().__init__(app)
        self.config = config or {}
        self.blocked_ips = set()
        self.suspicious_patterns = [
            'union select',
            'drop table',
            'insert into',
            'delete from',
            '<script',
            'javascript:',
            'eval(',
            'exec(',
            '../',
            '..\\',
        ]
        
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Process request through security checks."""
        start_time = time.time()
        
        try:
            # Security checks
            await self._check_ip_security(request)
            await self._check_request_security(request)
            await self._check_rate_limiting(request)
            
            # Process request
            response = await call_next(request)
            
            # Add security headers
            self._add_security_headers(response)
            
            # Log request
            await self._log_request(request, response, start_time)
            
            return response
            
        except HTTPException as e:
            # Log security violation
            await self._log_security_violation(request, e)
            return JSONResponse(
                status_code=e.status_code,
                content={"detail": e.detail}
            )
        except Exception as e:
            logger.error(f"Security middleware error: {e}")
            return JSONResponse(
                status_code=500,
                content={"detail": "Internal server error"}
            )
    
    async def _check_ip_security(self, request: Request):
        """Check IP-based security."""
        client_ip = security_manager._get_client_ip(request)
        
        # Check if IP is blocked
        if client_ip in self.blocked_ips:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="IP address is blocked"
            )
        
        # Check for suspicious IP patterns
        if self._is_suspicious_ip(client_ip):
            await security_manager._log_security_event(
                'suspicious_ip_access',
                None,
                client_ip,
                request.headers.get('user-agent', ''),
                {'path': str(request.url.path)},
                'high'
            )
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP is suspicious."""
        # Add your IP reputation checks here
        # For now, just check for private ranges accessing public endpoints
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            
            # Allow localhost and private networks for development
            if ip_obj.is_private or ip_obj.is_loopback:
                return False
            
            # Add more sophisticated IP reputation checks here
            return False
        except ValueError:
            return True  # Invalid IP format is suspicious
    
    async def _check_request_security(self, request: Request):
        """Check request for security threats."""
        # Check URL for suspicious patterns
        url_path = str(request.url.path).lower()
        query_string = str(request.url.query).lower()
        
        for pattern in self.suspicious_patterns:
            if pattern in url_path or pattern in query_string:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Suspicious request pattern detected"
                )
        
        # Check headers for suspicious content
        user_agent = request.headers.get('user-agent', '').lower()
        if any(bot in user_agent for bot in ['sqlmap', 'nikto', 'nmap', 'masscan']):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Suspicious user agent detected"
            )
        
        # Check request size
        content_length = request.headers.get('content-length')
        if content_length and int(content_length) > 10 * 1024 * 1024:  # 10MB limit
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="Request too large"
            )
        
        # Check for potential XSS in headers
        for header_name, header_value in request.headers.items():
            if any(pattern in header_value.lower() for pattern in ['<script', 'javascript:', 'eval(']):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Suspicious header content detected"
                )
    
    async def _check_rate_limiting(self, request: Request):
        """Apply rate limiting."""
        if not await security_manager.check_rate_limit(request):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded"
            )
    
    def _add_security_headers(self, response: Response):
        """Add security headers to response."""
        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
        }
        
        for header, value in security_headers.items():
            response.headers[header] = value
    
    async def _log_request(self, request: Request, response: Response, start_time: float):
        """Log request details."""
        duration = time.time() - start_time
        
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'method': request.method,
            'path': str(request.url.path),
            'query': str(request.url.query),
            'status_code': response.status_code,
            'duration': round(duration, 3),
            'ip': security_manager._get_client_ip(request),
            'user_agent': request.headers.get('user-agent', ''),
            'content_length': response.headers.get('content-length', '0'),
        }
        
        # Log based on status code
        if response.status_code >= 500:
            logger.error(f"Server error: {json.dumps(log_data)}")
        elif response.status_code >= 400:
            logger.warning(f"Client error: {json.dumps(log_data)}")
        else:
            logger.info(f"Request: {json.dumps(log_data)}")
    
    async def _log_security_violation(self, request: Request, exception: HTTPException):
        """Log security violations."""
        await security_manager._log_security_event(
            'security_violation',
            None,
            security_manager._get_client_ip(request),
            request.headers.get('user-agent', ''),
            {
                'path': str(request.url.path),
                'method': request.method,
                'status_code': exception.status_code,
                'detail': exception.detail
            },
            'high'
        )

# Endpoint protection decorators
def secure_endpoint(
    permissions: Optional[List[Permission]] = None,
    rate_limit: bool = True,
    audit: bool = True,
    resource: Optional[str] = None,
    action: Optional[str] = None
):
    """Decorator to secure API endpoints."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Apply rate limiting if enabled
            if rate_limit:
                request = kwargs.get('request')
                if request and not await security_manager.check_rate_limit(request):
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail="Rate limit exceeded"
                    )
            
            # Check permissions if specified
            if permissions:
                current_user = kwargs.get('current_user')
                if not current_user:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Authentication required"
                    )
                
                for permission in permissions:
                    if not auth_manager.has_permission(current_user, permission):
                        if audit:
                            auth_auditor.log_access_attempt(
                                current_user,
                                resource or func.__name__,
                                action or 'access',
                                False,
                                f"Missing permission: {permission.value}"
                            )
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"Permission required: {permission.value}"
                        )
            
            # Execute function
            try:
                result = await func(*args, **kwargs)
                
                # Log successful access if auditing enabled
                if audit and permissions:
                    current_user = kwargs.get('current_user')
                    if current_user:
                        auth_auditor.log_access_attempt(
                            current_user,
                            resource or func.__name__,
                            action or 'access',
                            True,
                            "Access granted"
                        )
                
                return result
                
            except Exception as e:
                # Log failed access if auditing enabled
                if audit and permissions:
                    current_user = kwargs.get('current_user')
                    if current_user:
                        auth_auditor.log_access_attempt(
                            current_user,
                            resource or func.__name__,
                            action or 'access',
                            False,
                            f"Error: {str(e)}"
                        )
                raise
        
        return wrapper
    return decorator

# Input validation and sanitization
class InputValidator:
    """Input validation and sanitization utilities."""
    
    @staticmethod
    def sanitize_string(value: str, max_length: int = 1000) -> str:
        """Sanitize string input."""
        if not isinstance(value, str):
            raise ValueError("Value must be a string")
        
        # Remove null bytes
        value = value.replace('\x00', '')
        
        # Limit length
        if len(value) > max_length:
            raise ValueError(f"String too long (max {max_length} characters)")
        
        # Remove potentially dangerous characters
        dangerous_chars = ['<', '>', '"', "'", '&', '\r', '\n']
        for char in dangerous_chars:
            value = value.replace(char, '')
        
        return value.strip()
    
    @staticmethod
    def validate_email(email: str) -> str:
        """Validate email format."""
        import re
        
        email = InputValidator.sanitize_string(email, 254)
        
        # Basic email regex
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            raise ValueError("Invalid email format")
        
        return email.lower()
    
    @staticmethod
    def validate_username(username: str) -> str:
        """Validate username format."""
        username = InputValidator.sanitize_string(username, 50)
        
        if len(username) < 3:
            raise ValueError("Username must be at least 3 characters")
        
        if not username.replace('_', '').replace('-', '').isalnum():
            raise ValueError("Username can only contain letters, numbers, hyphens, and underscores")
        
        return username.lower()
    
    @staticmethod
    def validate_ip_address(ip: str) -> str:
        """Validate IP address format."""
        import ipaddress
        
        try:
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            raise ValueError("Invalid IP address format")
    
    @staticmethod
    def validate_json(data: str, max_size: int = 1024 * 1024) -> dict:
        """Validate and parse JSON data."""
        if len(data) > max_size:
            raise ValueError(f"JSON data too large (max {max_size} bytes)")
        
        try:
            return json.loads(data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}")

# API endpoint security configurations
ENDPOINT_SECURITY_CONFIG = {
    # Authentication endpoints
    '/auth/login': {
        'rate_limit': True,
        'max_requests': 5,
        'window': 300,  # 5 minutes
        'audit': True,
    },
    '/auth/register': {
        'rate_limit': True,
        'max_requests': 3,
        'window': 3600,  # 1 hour
        'audit': True,
    },
    '/auth/logout': {
        'rate_limit': False,
        'audit': True,
    },
    
    # User management endpoints
    '/users': {
        'permissions': [Permission.USER_READ],
        'rate_limit': True,
        'audit': True,
    },
    '/users/{user_id}': {
        'permissions': [Permission.USER_READ],
        'rate_limit': True,
        'audit': True,
    },
    
    # System endpoints
    '/system/status': {
        'permissions': [Permission.SYSTEM_READ],
        'rate_limit': True,
        'audit': False,
    },
    '/system/settings': {
        'permissions': [Permission.SETTINGS_READ],
        'rate_limit': True,
        'audit': True,
    },
    
    # Threat detection endpoints
    '/threats': {
        'permissions': [Permission.THREAT_READ],
        'rate_limit': True,
        'audit': True,
    },
    '/threats/analyze': {
        'permissions': [Permission.THREAT_WRITE],
        'rate_limit': True,
        'max_requests': 10,
        'window': 60,
        'audit': True,
    },
    
    # Network monitoring endpoints
    '/network/status': {
        'permissions': [Permission.NETWORK_READ],
        'rate_limit': True,
        'audit': False,
    },
    '/network/scan': {
        'permissions': [Permission.NETWORK_WRITE],
        'rate_limit': True,
        'max_requests': 5,
        'window': 300,
        'audit': True,
    },
    
    # Security endpoints
    '/security/logs': {
        'permissions': [Permission.SECURITY_READ],
        'rate_limit': True,
        'audit': True,
    },
    '/security/settings': {
        'permissions': [Permission.SECURITY_ADMIN],
        'rate_limit': True,
        'audit': True,
    },
}

# CORS security configuration
CORS_CONFIG = {
    'allow_origins': [
        'http://localhost:3000',
        'http://localhost:4000',
        'https://ecyber.app',
    ],
    'allow_credentials': True,
    'allow_methods': ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    'allow_headers': [
        'Authorization',
        'Content-Type',
        'X-Requested-With',
        'X-CSRF-Token',
    ],
    'expose_headers': [
        'X-Total-Count',
        'X-Page-Count',
    ],
    'max_age': 86400,  # 24 hours
}

# Security monitoring
class SecurityMonitor:
    """Monitor security events and threats."""
    
    def __init__(self):
        self.threat_indicators = []
        self.blocked_requests = 0
        self.suspicious_activities = 0
    
    def record_threat_indicator(self, indicator_type: str, value: str, severity: str):
        """Record a threat indicator."""
        self.threat_indicators.append({
            'timestamp': datetime.utcnow().isoformat(),
            'type': indicator_type,
            'value': value,
            'severity': severity,
        })
        
        # Keep only recent indicators
        cutoff = datetime.utcnow() - timedelta(hours=24)
        self.threat_indicators = [
            indicator for indicator in self.threat_indicators
            if datetime.fromisoformat(indicator['timestamp']) > cutoff
        ]
    
    def get_security_metrics(self) -> Dict[str, Any]:
        """Get security metrics."""
        now = datetime.utcnow()
        last_hour = now - timedelta(hours=1)
        last_24h = now - timedelta(hours=24)
        
        recent_indicators = [
            indicator for indicator in self.threat_indicators
            if datetime.fromisoformat(indicator['timestamp']) > last_hour
        ]
        
        daily_indicators = [
            indicator for indicator in self.threat_indicators
            if datetime.fromisoformat(indicator['timestamp']) > last_24h
        ]
        
        return {
            'blocked_requests_total': self.blocked_requests,
            'suspicious_activities_total': self.suspicious_activities,
            'threat_indicators_last_hour': len(recent_indicators),
            'threat_indicators_last_24h': len(daily_indicators),
            'high_severity_indicators': len([
                i for i in daily_indicators if i['severity'] == 'high'
            ]),
            'security_stats': security_manager.get_security_stats(),
        }

# Global security monitor
security_monitor = SecurityMonitor()

# Export security components
__all__ = [
    'APISecurityMiddleware',
    'secure_endpoint',
    'InputValidator',
    'ENDPOINT_SECURITY_CONFIG',
    'CORS_CONFIG',
    'SecurityMonitor',
    'security_monitor'
]

