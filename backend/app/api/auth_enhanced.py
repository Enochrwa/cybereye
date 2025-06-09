# Enhanced authentication routes with comprehensive security

from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from pydantic import BaseModel, EmailStr, validator

from ..database import get_db
from ..models.user import User
from ..core.security_enhanced import (
    security_manager, 
    get_current_user, 
    require_superuser,
    rate_limit_check,
    SECURITY_CONFIG
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["authentication"])

# Pydantic models
class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: Optional[str] = None
    
    @validator('username')
    def validate_username(cls, v):
        if len(v) < 3:
            raise ValueError('Username must be at least 3 characters long')
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError('Username can only contain letters, numbers, hyphens, and underscores')
        return v.lower()
    
    @validator('password')
    def validate_password(cls, v):
        validation = security_manager.validate_password_strength(v)
        if not validation['is_valid']:
            raise ValueError(f"Password validation failed: {', '.join(validation['issues'])}")
        return v

class UserLogin(BaseModel):
    username: str
    password: str
    remember_me: bool = False

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: Dict[str, Any]
    requires_2fa: bool = False

class TwoFactorSetup(BaseModel):
    secret: str
    qr_code_uri: str
    qr_code_data: str

class TwoFactorVerify(BaseModel):
    code: str

class PasswordChange(BaseModel):
    current_password: str
    new_password: str
    
    @validator('new_password')
    def validate_new_password(cls, v):
        validation = security_manager.validate_password_strength(v)
        if not validation['is_valid']:
            raise ValueError(f"Password validation failed: {', '.join(validation['issues'])}")
        return v

class PasswordReset(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str
    
    @validator('new_password')
    def validate_new_password(cls, v):
        validation = security_manager.validate_password_strength(v)
        if not validation['is_valid']:
            raise ValueError(f"Password validation failed: {', '.join(validation['issues'])}")
        return v

# Helper functions
async def authenticate_user(db: AsyncSession, username: str, password: str) -> Optional[User]:
    """Authenticate user with username/email and password."""
    # Try username first, then email
    result = await db.execute(
        select(User).where(
            (User.username == username.lower()) | (User.email == username.lower())
        )
    )
    user = result.scalar_one_or_none()
    
    if not user or not security_manager.verify_password(password, user.hashed_password):
        return None
    
    return user

async def log_login_attempt(
    db: AsyncSession,
    username: str,
    ip_address: str,
    user_agent: str,
    success: bool,
    user_id: Optional[int] = None,
    failure_reason: Optional[str] = None
):
    """Log login attempt to database."""
    try:
        # This would insert into a login_attempts table
        # For now, just log to security manager
        await security_manager._log_security_event(
            'login_success' if success else 'login_failed',
            user_id,
            ip_address,
            user_agent,
            {
                'username': username,
                'failure_reason': failure_reason
            },
            'low' if success else 'medium'
        )
    except Exception as e:
        logger.error(f"Failed to log login attempt: {e}")

# Authentication endpoints
@router.post("/register", response_model=Dict[str, str])
async def register(
    user_data: UserRegister,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_check)
):
    """Register a new user."""
    # Check if username or email already exists
    result = await db.execute(
        select(User).where(
            (User.username == user_data.username.lower()) | 
            (User.email == user_data.email.lower())
        )
    )
    existing_user = result.scalar_one_or_none()
    
    if existing_user:
        if existing_user.username == user_data.username.lower():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already registered"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
    
    # Create new user
    hashed_password = security_manager.hash_password(user_data.password)
    new_user = User(
        username=user_data.username.lower(),
        email=user_data.email.lower(),
        full_name=user_data.full_name,
        hashed_password=hashed_password,
        is_active=True,
        is_superuser=False,
        is_two_factor_enabled=False,
        created_at=datetime.utcnow()
    )
    
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    
    # Log registration
    await security_manager._log_security_event(
        'user_registered',
        new_user.id,
        security_manager._get_client_ip(request),
        request.headers.get('user-agent', ''),
        {'username': new_user.username, 'email': new_user.email}
    )
    
    logger.info(f"New user registered: {new_user.username}")
    
    return {"message": "User registered successfully"}

@router.post("/login", response_model=TokenResponse)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    request: Request = None,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_check)
):
    """Authenticate user and return access token."""
    ip_address = security_manager._get_client_ip(request)
    user_agent = request.headers.get('user-agent', '')
    
    # Authenticate user
    user = await authenticate_user(db, form_data.username, form_data.password)
    
    if not user:
        await log_login_attempt(
            db, form_data.username, ip_address, user_agent, 
            False, failure_reason="Invalid credentials"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        await log_login_attempt(
            db, form_data.username, ip_address, user_agent,
            False, user.id, "Account disabled"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is disabled"
        )
    
    # Check if 2FA is required
    if user.is_two_factor_enabled:
        # Create temporary session for 2FA
        temp_session_id = await security_manager.create_session(user, request)
        temp_token = await security_manager.create_access_token(user, temp_session_id)
        
        await log_login_attempt(
            db, form_data.username, ip_address, user_agent,
            True, user.id
        )
        
        return TokenResponse(
            access_token=temp_token,
            expires_in=300,  # 5 minutes for 2FA
            user={
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "full_name": user.full_name,
                "is_superuser": user.is_superuser,
                "is_two_factor_enabled": user.is_two_factor_enabled
            },
            requires_2fa=True
        )
    
    # Create session and token
    session_id = await security_manager.create_session(user, request)
    access_token = await security_manager.create_access_token(user, session_id)
    
    # Update last login
    await db.execute(
        update(User)
        .where(User.id == user.id)
        .values(last_login=datetime.utcnow())
    )
    await db.commit()
    
    await log_login_attempt(
        db, form_data.username, ip_address, user_agent,
        True, user.id
    )
    
    logger.info(f"User logged in: {user.username}")
    
    return TokenResponse(
        access_token=access_token,
        expires_in=SECURITY_CONFIG['session_timeout'],
        user={
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "is_superuser": user.is_superuser,
            "is_two_factor_enabled": user.is_two_factor_enabled
        }
    )

@router.post("/verify-2fa", response_model=TokenResponse)
async def verify_2fa(
    verify_data: TwoFactorVerify,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Verify 2FA code and complete login."""
    if not current_user.is_two_factor_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is not enabled for this user"
        )
    
    # Verify 2FA code
    if not security_manager.verify_2fa_token(current_user.two_factor_secret, verify_data.code):
        await security_manager._log_security_event(
            '2fa_failed',
            current_user.id,
            security_manager._get_client_ip(request),
            request.headers.get('user-agent', ''),
            {'code_provided': verify_data.code[:2] + '****'}  # Partial code for logging
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid 2FA code"
        )
    
    # Create new session and token
    session_id = await security_manager.create_session(current_user, request)
    access_token = await security_manager.create_access_token(current_user, session_id)
    
    # Update last login
    await db.execute(
        update(User)
        .where(User.id == current_user.id)
        .values(last_login=datetime.utcnow())
    )
    await db.commit()
    
    await security_manager._log_security_event(
        '2fa_success',
        current_user.id,
        security_manager._get_client_ip(request),
        request.headers.get('user-agent', ''),
        {}
    )
    
    logger.info(f"2FA verification successful: {current_user.username}")
    
    return TokenResponse(
        access_token=access_token,
        expires_in=SECURITY_CONFIG['session_timeout'],
        user={
            "id": current_user.id,
            "username": current_user.username,
            "email": current_user.email,
            "full_name": current_user.full_name,
            "is_superuser": current_user.is_superuser,
            "is_two_factor_enabled": current_user.is_two_factor_enabled
        }
    )

@router.post("/logout")
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """Logout user and invalidate session."""
    # Get session ID from token
    credentials = await security_manager.security_bearer(request)
    if credentials:
        payload = await security_manager.verify_token(credentials.credentials, request)
        if payload and 'session_id' in payload:
            await security_manager._remove_session(payload['session_id'])
    
    await security_manager._log_security_event(
        'user_logout',
        current_user.id,
        security_manager._get_client_ip(request),
        request.headers.get('user-agent', ''),
        {}
    )
    
    logger.info(f"User logged out: {current_user.username}")
    
    return {"message": "Successfully logged out"}

@router.get("/me")
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information."""
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "is_active": current_user.is_active,
        "is_superuser": current_user.is_superuser,
        "is_two_factor_enabled": current_user.is_two_factor_enabled,
        "created_at": current_user.created_at,
        "last_login": current_user.last_login
    }

# 2FA Management
@router.post("/2fa/generate-secret", response_model=TwoFactorSetup)
async def generate_2fa_secret(current_user: User = Depends(get_current_user)):
    """Generate 2FA secret for user."""
    if current_user.is_two_factor_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is already enabled"
        )
    
    setup_data = security_manager.generate_2fa_secret(current_user)
    
    logger.info(f"2FA secret generated for user: {current_user.username}")
    
    return TwoFactorSetup(**setup_data)

@router.post("/2fa/enable")
async def enable_2fa(
    verify_data: TwoFactorVerify,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Enable 2FA for user."""
    if current_user.is_two_factor_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is already enabled"
        )
    
    # Get the secret from the request (should be stored temporarily)
    # For this example, we'll assume the secret is passed in the request
    # In a real implementation, you'd store it temporarily during setup
    setup_data = security_manager.generate_2fa_secret(current_user)
    secret = setup_data['secret']
    
    # Verify the code
    if not security_manager.verify_2fa_token(secret, verify_data.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid 2FA code"
        )
    
    # Enable 2FA
    await db.execute(
        update(User)
        .where(User.id == current_user.id)
        .values(
            is_two_factor_enabled=True,
            two_factor_secret=secret
        )
    )
    await db.commit()
    
    await security_manager._log_security_event(
        '2fa_enabled',
        current_user.id,
        security_manager._get_client_ip(request),
        request.headers.get('user-agent', ''),
        {}
    )
    
    logger.info(f"2FA enabled for user: {current_user.username}")
    
    return {"message": "2FA enabled successfully"}

@router.post("/2fa/disable")
async def disable_2fa(
    verify_data: TwoFactorVerify,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Disable 2FA for user."""
    if not current_user.is_two_factor_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is not enabled"
        )
    
    # Verify current 2FA code
    if not security_manager.verify_2fa_token(current_user.two_factor_secret, verify_data.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid 2FA code"
        )
    
    # Disable 2FA
    await db.execute(
        update(User)
        .where(User.id == current_user.id)
        .values(
            is_two_factor_enabled=False,
            two_factor_secret=None
        )
    )
    await db.commit()
    
    await security_manager._log_security_event(
        '2fa_disabled',
        current_user.id,
        security_manager._get_client_ip(request),
        request.headers.get('user-agent', ''),
        {}
    )
    
    logger.info(f"2FA disabled for user: {current_user.username}")
    
    return {"message": "2FA disabled successfully"}

# Password management
@router.post("/change-password")
async def change_password(
    password_data: PasswordChange,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Change user password."""
    # Verify current password
    if not security_manager.verify_password(password_data.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    # Hash new password
    new_hashed_password = security_manager.hash_password(password_data.new_password)
    
    # Update password
    await db.execute(
        update(User)
        .where(User.id == current_user.id)
        .values(hashed_password=new_hashed_password)
    )
    await db.commit()
    
    await security_manager._log_security_event(
        'password_changed',
        current_user.id,
        security_manager._get_client_ip(request),
        request.headers.get('user-agent', ''),
        {}
    )
    
    logger.info(f"Password changed for user: {current_user.username}")
    
    return {"message": "Password changed successfully"}

# Security information
@router.get("/security/stats")
async def get_security_stats(current_user: User = Depends(require_superuser)):
    """Get security statistics (superuser only)."""
    return security_manager.get_security_stats()

@router.get("/security/sessions")
async def get_active_sessions(current_user: User = Depends(get_current_user)):
    """Get user's active sessions."""
    user_sessions = [
        {
            'session_id': session_id[:8] + '...',  # Truncated for security
            'created_at': session_data['created_at'].isoformat(),
            'last_activity': session_data['last_activity'].isoformat(),
            'ip_address': session_data['ip_address'],
            'user_agent': session_data['user_agent'][:100],  # Truncated
            'is_current': session_data.get('is_current', False)
        }
        for session_id, session_data in security_manager.active_sessions.items()
        if session_data['user_id'] == current_user.id
    ]
    
    return {"sessions": user_sessions}

@router.delete("/security/sessions/{session_id}")
async def revoke_session(
    session_id: str,
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """Revoke a specific session."""
    if session_id in security_manager.active_sessions:
        session_data = security_manager.active_sessions[session_id]
        
        # Check if user owns this session
        if session_data['user_id'] != current_user.id and not current_user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot revoke another user's session"
            )
        
        await security_manager._remove_session(session_id)
        
        await security_manager._log_security_event(
            'session_revoked',
            current_user.id,
            security_manager._get_client_ip(request),
            request.headers.get('user-agent', ''),
            {'revoked_session_id': session_id}
        )
        
        return {"message": "Session revoked successfully"}
    
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Session not found"
    )

