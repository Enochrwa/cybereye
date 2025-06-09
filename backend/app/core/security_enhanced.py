# Enhanced security middleware for authentication and authorization

import time
import hashlib
import secrets
import logging
from typing import Dict, List, Optional, Set, Callable, Any
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict, deque
import asyncio
import ipaddress
from dataclasses import dataclass, field

from fastapi import HTTPException, Request, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete
import jwt
from passlib.context import CryptContext
import pyotp
import qrcode
from io import BytesIO
import base64

from ..core.config import settings
from ..database import get_db
from ..models.user import User
from ..models.security import SecurityLog, LoginAttempt, Session

logger = logging.getLogger(__name__)

# Security configuration
SECURITY_CONFIG = {
    'max_login_attempts': 5,
    'lockout_duration': 900,  # 15 minutes
    'session_timeout': 3600,  # 1 hour
    'max_sessions_per_user': 5,
    'password_min_length': 12,
    'password_require_special': True,
    'password_require_numbers': True,
    'password_require_uppercase': True,
    'password_require_lowercase': True,
    'rate_limit_requests': 100,
    'rate_limit_window': 60,  # 1 minute
    'suspicious_activity_threshold': 10,
    'max_2fa_attempts': 3,
    '2fa_window': 30,  # seconds
}

@dataclass
class RateLimitInfo:
    requests: deque = field(default_factory=deque)
    blocked_until: Optional[datetime] = None
    violation_count: int = 0

@dataclass
class SecurityEvent:
    event_type: str
    user_id: Optional[int]
    ip_address: str
    user_agent: str
    timestamp: datetime
    details: Dict[str, Any]
    severity: str  # 'low', 'medium', 'high', 'critical'

class SecurityManager:
    """Comprehensive security manager for authentication and authorization."""
    
    def __init__(self):
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        self.security_bearer = HTTPBearer(auto_error=False)
        
        # Rate limiting storage
        self.rate_limits: Dict[str, RateLimitInfo] = defaultdict(RateLimitInfo)
        self.blocked_ips: Set[str] = set()
        self.suspicious_ips: Dict[str, int] = defaultdict(int)
        
        # Session management
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.user_sessions: Dict[int, Set[str]] = defaultdict(set)
        
        # Security events
        self.security_events: deque = deque(maxlen=10000)
        
        # Cleanup task
        self._cleanup_task = None
        self._start_cleanup_task()
    
    def _start_cleanup_task(self):
        """Start background cleanup task."""
        async def cleanup_loop():
            while True:
                try:
                    await self._cleanup_expired_data()
                    await asyncio.sleep(300)  # Cleanup every 5 minutes
                except Exception as e:
                    logger.error(f"Cleanup task error: {e}")
                    await asyncio.sleep(60)
        
        self._cleanup_task = asyncio.create_task(cleanup_loop())
    
    async def _cleanup_expired_data(self):
        """Clean up expired rate limits, sessions, and other data."""
        now = datetime.utcnow()
        
        # Clean up rate limits
        expired_ips = []
        for ip, info in self.rate_limits.items():
            # Remove old requests
            while info.requests and info.requests[0] < now - timedelta(seconds=SECURITY_CONFIG['rate_limit_window']):
                info.requests.popleft()
            
            # Remove expired blocks
            if info.blocked_until and info.blocked_until < now:
                info.blocked_until = None
                info.violation_count = 0
            
            # Remove empty entries
            if not info.requests and not info.blocked_until:
                expired_ips.append(ip)
        
        for ip in expired_ips:
            del self.rate_limits[ip]
        
        # Clean up expired sessions
        expired_sessions = []
        for session_id, session_data in self.active_sessions.items():
            if session_data['expires_at'] < now:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            await self._remove_session(session_id)
    
    def hash_password(self, password: str) -> str:
        """Hash a password using bcrypt."""
        return self.pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        return self.pwd_context.verify(plain_password, hashed_password)
    
    def validate_password_strength(self, password: str) -> Dict[str, Any]:
        """Validate password strength according to security policy."""
        issues = []
        score = 0
        
        if len(password) < SECURITY_CONFIG['password_min_length']:
            issues.append(f"Password must be at least {SECURITY_CONFIG['password_min_length']} characters long")
        else:
            score += 1
        
        if SECURITY_CONFIG['password_require_lowercase'] and not any(c.islower() for c in password):
            issues.append("Password must contain at least one lowercase letter")
        else:
            score += 1
        
        if SECURITY_CONFIG['password_require_uppercase'] and not any(c.isupper() for c in password):
            issues.append("Password must contain at least one uppercase letter")
        else:
            score += 1
        
        if SECURITY_CONFIG['password_require_numbers'] and not any(c.isdigit() for c in password):
            issues.append("Password must contain at least one number")
        else:
            score += 1
        
        if SECURITY_CONFIG['password_require_special'] and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            issues.append("Password must contain at least one special character")
        else:
            score += 1
        
        # Additional checks
        if password.lower() in ['password', '123456', 'qwerty', 'admin', 'letmein']:
            issues.append("Password is too common")
            score = 0
        
        strength = 'weak'
        if score >= 4:
            strength = 'strong'
        elif score >= 3:
            strength = 'medium'
        
        return {
            'is_valid': len(issues) == 0,
            'issues': issues,
            'strength': strength,
            'score': score
        }
    
    async def check_rate_limit(self, request: Request) -> bool:
        """Check if request is within rate limits."""
        client_ip = self._get_client_ip(request)
        now = datetime.utcnow()
        
        # Check if IP is blocked
        if client_ip in self.blocked_ips:
            await self._log_security_event(
                'rate_limit_blocked',
                None,
                client_ip,
                request.headers.get('user-agent', ''),
                {'reason': 'IP blocked due to repeated violations'}
            )
            return False
        
        rate_info = self.rate_limits[client_ip]
        
        # Check if currently blocked
        if rate_info.blocked_until and rate_info.blocked_until > now:
            return False
        
        # Remove old requests
        while rate_info.requests and rate_info.requests[0] < now - timedelta(seconds=SECURITY_CONFIG['rate_limit_window']):
            rate_info.requests.popleft()
        
        # Check current rate
        if len(rate_info.requests) >= SECURITY_CONFIG['rate_limit_requests']:
            # Rate limit exceeded
            rate_info.violation_count += 1
            block_duration = min(300 * (2 ** rate_info.violation_count), 3600)  # Exponential backoff, max 1 hour
            rate_info.blocked_until = now + timedelta(seconds=block_duration)
            
            await self._log_security_event(
                'rate_limit_exceeded',
                None,
                client_ip,
                request.headers.get('user-agent', ''),
                {
                    'requests_in_window': len(rate_info.requests),
                    'violation_count': rate_info.violation_count,
                    'blocked_until': rate_info.blocked_until.isoformat()
                }
            )
            
            # Block IP if too many violations
            if rate_info.violation_count >= 5:
                self.blocked_ips.add(client_ip)
                await self._log_security_event(
                    'ip_blocked',
                    None,
                    client_ip,
                    request.headers.get('user-agent', ''),
                    {'reason': 'Repeated rate limit violations'}
                )
            
            return False
        
        # Add current request
        rate_info.requests.append(now)
        return True
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address from request."""
        # Check for forwarded headers
        forwarded_for = request.headers.get('x-forwarded-for')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.headers.get('x-real-ip')
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else '127.0.0.1'
    
    async def create_access_token(self, user: User, session_id: str) -> str:
        """Create JWT access token."""
        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60)
        
        payload = {
            'sub': str(user.id),
            'username': user.username,
            'email': user.email,
            'is_superuser': user.is_superuser,
            'session_id': session_id,
            'iat': now.timestamp(),
            'exp': expires_at.timestamp(),
            'type': 'access'
        }
        
        return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    
    async def create_session(self, user: User, request: Request) -> str:
        """Create a new user session."""
        session_id = secrets.token_urlsafe(32)
        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=SECURITY_CONFIG['session_timeout'])
        
        # Check session limit
        user_session_count = len(self.user_sessions[user.id])
        if user_session_count >= SECURITY_CONFIG['max_sessions_per_user']:
            # Remove oldest session
            oldest_session = min(
                (sid for sid in self.user_sessions[user.id] if sid in self.active_sessions),
                key=lambda sid: self.active_sessions[sid]['created_at'],
                default=None
            )
            if oldest_session:
                await self._remove_session(oldest_session)
        
        session_data = {
            'user_id': user.id,
            'username': user.username,
            'created_at': now,
            'expires_at': expires_at,
            'last_activity': now,
            'ip_address': self._get_client_ip(request),
            'user_agent': request.headers.get('user-agent', ''),
            'is_active': True
        }
        
        self.active_sessions[session_id] = session_data
        self.user_sessions[user.id].add(session_id)
        
        await self._log_security_event(
            'session_created',
            user.id,
            session_data['ip_address'],
            session_data['user_agent'],
            {'session_id': session_id}
        )
        
        return session_id
    
    async def _remove_session(self, session_id: str):
        """Remove a session."""
        if session_id in self.active_sessions:
            session_data = self.active_sessions[session_id]
            user_id = session_data['user_id']
            
            del self.active_sessions[session_id]
            self.user_sessions[user_id].discard(session_id)
            
            await self._log_security_event(
                'session_removed',
                user_id,
                session_data['ip_address'],
                session_data['user_agent'],
                {'session_id': session_id}
            )
    
    async def validate_session(self, session_id: str, request: Request) -> Optional[Dict[str, Any]]:
        """Validate and update session."""
        if session_id not in self.active_sessions:
            return None
        
        session_data = self.active_sessions[session_id]
        now = datetime.utcnow()
        
        # Check expiration
        if session_data['expires_at'] < now:
            await self._remove_session(session_id)
            return None
        
        # Update last activity
        session_data['last_activity'] = now
        session_data['expires_at'] = now + timedelta(seconds=SECURITY_CONFIG['session_timeout'])
        
        # Validate IP consistency (optional security check)
        current_ip = self._get_client_ip(request)
        if session_data['ip_address'] != current_ip:
            await self._log_security_event(
                'session_ip_change',
                session_data['user_id'],
                current_ip,
                request.headers.get('user-agent', ''),
                {
                    'session_id': session_id,
                    'original_ip': session_data['ip_address'],
                    'new_ip': current_ip
                }
            )
            # Could invalidate session here for high security
        
        return session_data
    
    async def verify_token(self, token: str, request: Request) -> Optional[Dict[str, Any]]:
        """Verify JWT token and return payload."""
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            
            # Validate session
            session_id = payload.get('session_id')
            if session_id:
                session_data = await self.validate_session(session_id, request)
                if not session_data:
                    return None
                
                # Add session data to payload
                payload['session_data'] = session_data
            
            return payload
        except jwt.ExpiredSignatureError:
            await self._log_security_event(
                'token_expired',
                None,
                self._get_client_ip(request),
                request.headers.get('user-agent', ''),
                {}
            )
            return None
        except jwt.JWTError as e:
            await self._log_security_event(
                'token_invalid',
                None,
                self._get_client_ip(request),
                request.headers.get('user-agent', ''),
                {'error': str(e)}
            )
            return None
    
    def generate_2fa_secret(self, user: User) -> Dict[str, str]:
        """Generate 2FA secret and QR code."""
        secret = pyotp.random_base32()
        
        # Create TOTP URI
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user.email,
            issuer_name="eCyber Security Platform"
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        qr_code_data = base64.b64encode(buffer.getvalue()).decode()
        
        return {
            'secret': secret,
            'qr_code_uri': totp_uri,
            'qr_code_data': f"data:image/png;base64,{qr_code_data}"
        }
    
    def verify_2fa_token(self, secret: str, token: str) -> bool:
        """Verify 2FA token."""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=SECURITY_CONFIG['2fa_window'])
    
    async def _log_security_event(
        self,
        event_type: str,
        user_id: Optional[int],
        ip_address: str,
        user_agent: str,
        details: Dict[str, Any],
        severity: str = 'medium'
    ):
        """Log security event."""
        event = SecurityEvent(
            event_type=event_type,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            timestamp=datetime.utcnow(),
            details=details,
            severity=severity
        )
        
        self.security_events.append(event)
        
        # Log to file
        logger.warning(
            f"Security Event: {event_type} | User: {user_id} | IP: {ip_address} | Details: {details}"
        )
        
        # Check for suspicious activity
        await self._check_suspicious_activity(ip_address, event_type)
    
    async def _check_suspicious_activity(self, ip_address: str, event_type: str):
        """Check for suspicious activity patterns."""
        suspicious_events = [
            'login_failed', 'token_invalid', 'rate_limit_exceeded',
            'session_ip_change', '2fa_failed'
        ]
        
        if event_type in suspicious_events:
            self.suspicious_ips[ip_address] += 1
            
            if self.suspicious_ips[ip_address] >= SECURITY_CONFIG['suspicious_activity_threshold']:
                self.blocked_ips.add(ip_address)
                await self._log_security_event(
                    'ip_blocked_suspicious',
                    None,
                    ip_address,
                    '',
                    {'suspicious_events': self.suspicious_ips[ip_address]},
                    'high'
                )
    
    def get_security_stats(self) -> Dict[str, Any]:
        """Get security statistics."""
        now = datetime.utcnow()
        recent_events = [
            event for event in self.security_events
            if event.timestamp > now - timedelta(hours=24)
        ]
        
        return {
            'active_sessions': len(self.active_sessions),
            'blocked_ips': len(self.blocked_ips),
            'suspicious_ips': len(self.suspicious_ips),
            'recent_events': len(recent_events),
            'events_by_type': {
                event_type: len([e for e in recent_events if e.event_type == event_type])
                for event_type in set(e.event_type for e in recent_events)
            },
            'events_by_severity': {
                severity: len([e for e in recent_events if e.severity == severity])
                for severity in ['low', 'medium', 'high', 'critical']
            }
        }

# Global security manager instance
security_manager = SecurityManager()

# Dependency functions
async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_manager.security_bearer),
    db: AsyncSession = Depends(get_db)
) -> User:
    """Get current authenticated user."""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Verify token
    payload = await security_manager.verify_token(credentials.credentials, request)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Get user from database
    user_id = int(payload['sub'])
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    
    return user

def require_permissions(*required_permissions: str):
    """Decorator to require specific permissions."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get current user from kwargs or args
            current_user = kwargs.get('current_user')
            if not current_user:
                for arg in args:
                    if isinstance(arg, User):
                        current_user = arg
                        break
            
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            # Check permissions
            if not current_user.is_superuser:
                # For now, only superusers have all permissions
                # In a full implementation, you'd check user roles/permissions
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions"
                )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator

def require_superuser(current_user: User = Depends(get_current_user)) -> User:
    """Require superuser privileges."""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superuser privileges required"
        )
    return current_user

async def rate_limit_check(request: Request):
    """Rate limiting dependency."""
    if not await security_manager.check_rate_limit(request):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded"
        )

# Export security manager and dependencies
__all__ = [
    'security_manager',
    'get_current_user',
    'require_permissions',
    'require_superuser',
    'rate_limit_check',
    'SECURITY_CONFIG'
]

