# Role-based access control and authorization system

from enum import Enum
from typing import List, Set, Dict, Any, Optional
from datetime import datetime
from dataclasses import dataclass
import logging

from fastapi import HTTPException, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from sqlalchemy.orm import relationship

from ..database import get_db
from ..models.user import User
from ..core.security_enhanced import get_current_user

logger = logging.getLogger(__name__)

# Permission system
class Permission(str, Enum):
    # User management
    USER_READ = "user:read"
    USER_WRITE = "user:write"
    USER_DELETE = "user:delete"
    USER_ADMIN = "user:admin"
    
    # System management
    SYSTEM_READ = "system:read"
    SYSTEM_WRITE = "system:write"
    SYSTEM_ADMIN = "system:admin"
    
    # Threat management
    THREAT_READ = "threat:read"
    THREAT_WRITE = "threat:write"
    THREAT_ADMIN = "threat:admin"
    
    # Network management
    NETWORK_READ = "network:read"
    NETWORK_WRITE = "network:write"
    NETWORK_ADMIN = "network:admin"
    
    # Log management
    LOG_READ = "log:read"
    LOG_WRITE = "log:write"
    LOG_DELETE = "log:delete"
    LOG_ADMIN = "log:admin"
    
    # Model management
    MODEL_READ = "model:read"
    MODEL_WRITE = "model:write"
    MODEL_TRAIN = "model:train"
    MODEL_ADMIN = "model:admin"
    
    # Settings management
    SETTINGS_READ = "settings:read"
    SETTINGS_WRITE = "settings:write"
    SETTINGS_ADMIN = "settings:admin"
    
    # Security management
    SECURITY_READ = "security:read"
    SECURITY_WRITE = "security:write"
    SECURITY_ADMIN = "security:admin"
    
    # Audit and compliance
    AUDIT_READ = "audit:read"
    AUDIT_WRITE = "audit:write"
    AUDIT_ADMIN = "audit:admin"

class Role(str, Enum):
    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    NETWORK_ANALYST = "network_analyst"
    THREAT_ANALYST = "threat_analyst"
    VIEWER = "viewer"
    GUEST = "guest"

# Role permissions mapping
ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.SUPER_ADMIN: set(Permission),  # All permissions
    
    Role.ADMIN: {
        Permission.USER_READ, Permission.USER_WRITE, Permission.USER_DELETE,
        Permission.SYSTEM_READ, Permission.SYSTEM_WRITE,
        Permission.THREAT_READ, Permission.THREAT_WRITE,
        Permission.NETWORK_READ, Permission.NETWORK_WRITE,
        Permission.LOG_READ, Permission.LOG_WRITE, Permission.LOG_DELETE,
        Permission.MODEL_READ, Permission.MODEL_WRITE, Permission.MODEL_TRAIN,
        Permission.SETTINGS_READ, Permission.SETTINGS_WRITE,
        Permission.SECURITY_READ, Permission.SECURITY_WRITE,
        Permission.AUDIT_READ, Permission.AUDIT_WRITE,
    },
    
    Role.SECURITY_ANALYST: {
        Permission.USER_READ,
        Permission.SYSTEM_READ,
        Permission.THREAT_READ, Permission.THREAT_WRITE,
        Permission.NETWORK_READ,
        Permission.LOG_READ, Permission.LOG_WRITE,
        Permission.MODEL_READ,
        Permission.SETTINGS_READ,
        Permission.SECURITY_READ, Permission.SECURITY_WRITE,
        Permission.AUDIT_READ,
    },
    
    Role.NETWORK_ANALYST: {
        Permission.USER_READ,
        Permission.SYSTEM_READ,
        Permission.THREAT_READ,
        Permission.NETWORK_READ, Permission.NETWORK_WRITE,
        Permission.LOG_READ,
        Permission.MODEL_READ,
        Permission.SETTINGS_READ,
        Permission.SECURITY_READ,
        Permission.AUDIT_READ,
    },
    
    Role.THREAT_ANALYST: {
        Permission.USER_READ,
        Permission.SYSTEM_READ,
        Permission.THREAT_READ, Permission.THREAT_WRITE,
        Permission.NETWORK_READ,
        Permission.LOG_READ,
        Permission.MODEL_READ, Permission.MODEL_WRITE,
        Permission.SETTINGS_READ,
        Permission.SECURITY_READ,
        Permission.AUDIT_READ,
    },
    
    Role.VIEWER: {
        Permission.USER_READ,
        Permission.SYSTEM_READ,
        Permission.THREAT_READ,
        Permission.NETWORK_READ,
        Permission.LOG_READ,
        Permission.MODEL_READ,
        Permission.SETTINGS_READ,
        Permission.SECURITY_READ,
        Permission.AUDIT_READ,
    },
    
    Role.GUEST: {
        Permission.SYSTEM_READ,
        Permission.THREAT_READ,
        Permission.NETWORK_READ,
        Permission.LOG_READ,
    },
}

@dataclass
class UserContext:
    """User context with permissions and role information."""
    user: User
    roles: Set[Role]
    permissions: Set[Permission]
    is_superuser: bool
    session_data: Optional[Dict[str, Any]] = None

class AuthorizationManager:
    """Manages authorization and role-based access control."""
    
    def __init__(self):
        self.permission_cache: Dict[int, Set[Permission]] = {}
        self.role_cache: Dict[int, Set[Role]] = {}
    
    def get_user_roles(self, user: User) -> Set[Role]:
        """Get user roles."""
        if user.id in self.role_cache:
            return self.role_cache[user.id]
        
        roles = set()
        
        # Super admin gets all roles
        if user.is_superuser:
            roles.add(Role.SUPER_ADMIN)
        else:
            # For now, assign roles based on user properties
            # In a full implementation, this would come from a user_roles table
            if user.is_superuser:
                roles.add(Role.SUPER_ADMIN)
            elif hasattr(user, 'role') and user.role:
                try:
                    roles.add(Role(user.role))
                except ValueError:
                    roles.add(Role.VIEWER)  # Default role
            else:
                roles.add(Role.VIEWER)  # Default role
        
        self.role_cache[user.id] = roles
        return roles
    
    def get_user_permissions(self, user: User) -> Set[Permission]:
        """Get user permissions based on roles."""
        if user.id in self.permission_cache:
            return self.permission_cache[user.id]
        
        roles = self.get_user_roles(user)
        permissions = set()
        
        for role in roles:
            permissions.update(ROLE_PERMISSIONS.get(role, set()))
        
        self.permission_cache[user.id] = permissions
        return permissions
    
    def has_permission(self, user: User, permission: Permission) -> bool:
        """Check if user has specific permission."""
        if user.is_superuser:
            return True
        
        user_permissions = self.get_user_permissions(user)
        return permission in user_permissions
    
    def has_any_permission(self, user: User, permissions: List[Permission]) -> bool:
        """Check if user has any of the specified permissions."""
        if user.is_superuser:
            return True
        
        user_permissions = self.get_user_permissions(user)
        return any(perm in user_permissions for perm in permissions)
    
    def has_all_permissions(self, user: User, permissions: List[Permission]) -> bool:
        """Check if user has all specified permissions."""
        if user.is_superuser:
            return True
        
        user_permissions = self.get_user_permissions(user)
        return all(perm in user_permissions for perm in permissions)
    
    def create_user_context(self, user: User, session_data: Optional[Dict[str, Any]] = None) -> UserContext:
        """Create user context with roles and permissions."""
        roles = self.get_user_roles(user)
        permissions = self.get_user_permissions(user)
        
        return UserContext(
            user=user,
            roles=roles,
            permissions=permissions,
            is_superuser=user.is_superuser,
            session_data=session_data
        )
    
    def clear_user_cache(self, user_id: int):
        """Clear cached permissions and roles for user."""
        self.permission_cache.pop(user_id, None)
        self.role_cache.pop(user_id, None)
    
    def clear_all_cache(self):
        """Clear all cached data."""
        self.permission_cache.clear()
        self.role_cache.clear()

# Global authorization manager
auth_manager = AuthorizationManager()

# Dependency functions
def require_permission(permission: Permission):
    """Dependency to require specific permission."""
    def dependency(current_user: User = Depends(get_current_user)) -> User:
        if not auth_manager.has_permission(current_user, permission):
            logger.warning(
                f"User {current_user.username} attempted to access resource requiring {permission.value}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission required: {permission.value}"
            )
        return current_user
    return dependency

def require_any_permission(*permissions: Permission):
    """Dependency to require any of the specified permissions."""
    def dependency(current_user: User = Depends(get_current_user)) -> User:
        if not auth_manager.has_any_permission(current_user, list(permissions)):
            logger.warning(
                f"User {current_user.username} attempted to access resource requiring any of {[p.value for p in permissions]}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"One of these permissions required: {', '.join(p.value for p in permissions)}"
            )
        return current_user
    return dependency

def require_all_permissions(*permissions: Permission):
    """Dependency to require all specified permissions."""
    def dependency(current_user: User = Depends(get_current_user)) -> User:
        if not auth_manager.has_all_permissions(current_user, list(permissions)):
            logger.warning(
                f"User {current_user.username} attempted to access resource requiring all of {[p.value for p in permissions]}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"All of these permissions required: {', '.join(p.value for p in permissions)}"
            )
        return current_user
    return dependency

def require_role(role: Role):
    """Dependency to require specific role."""
    def dependency(current_user: User = Depends(get_current_user)) -> User:
        user_roles = auth_manager.get_user_roles(current_user)
        if role not in user_roles and not current_user.is_superuser:
            logger.warning(
                f"User {current_user.username} attempted to access resource requiring role {role.value}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role required: {role.value}"
            )
        return current_user
    return dependency

def get_user_context(current_user: User = Depends(get_current_user)) -> UserContext:
    """Get user context with roles and permissions."""
    return auth_manager.create_user_context(current_user)

# Resource-based access control
class ResourceAccessControl:
    """Resource-based access control for fine-grained permissions."""
    
    @staticmethod
    def can_access_user_data(current_user: User, target_user_id: int) -> bool:
        """Check if user can access another user's data."""
        # Users can access their own data
        if current_user.id == target_user_id:
            return True
        
        # Admins can access any user data
        if auth_manager.has_permission(current_user, Permission.USER_ADMIN):
            return True
        
        # Users with USER_READ can read basic user info
        if auth_manager.has_permission(current_user, Permission.USER_READ):
            return True
        
        return False
    
    @staticmethod
    def can_modify_user_data(current_user: User, target_user_id: int) -> bool:
        """Check if user can modify another user's data."""
        # Users can modify their own data (limited)
        if current_user.id == target_user_id:
            return True
        
        # Admins can modify any user data
        if auth_manager.has_permission(current_user, Permission.USER_ADMIN):
            return True
        
        # Users with USER_WRITE can modify some user data
        if auth_manager.has_permission(current_user, Permission.USER_WRITE):
            return True
        
        return False
    
    @staticmethod
    def can_delete_user(current_user: User, target_user_id: int) -> bool:
        """Check if user can delete another user."""
        # Users cannot delete themselves
        if current_user.id == target_user_id:
            return False
        
        # Only admins can delete users
        return auth_manager.has_permission(current_user, Permission.USER_DELETE)
    
    @staticmethod
    def can_access_system_logs(current_user: User, log_level: str = "info") -> bool:
        """Check if user can access system logs."""
        # Different log levels require different permissions
        if log_level in ["error", "critical"]:
            return auth_manager.has_permission(current_user, Permission.SECURITY_READ)
        elif log_level == "warning":
            return auth_manager.has_permission(current_user, Permission.SYSTEM_READ)
        else:
            return auth_manager.has_permission(current_user, Permission.LOG_READ)
    
    @staticmethod
    def can_modify_system_settings(current_user: User, setting_category: str) -> bool:
        """Check if user can modify system settings."""
        # Security settings require special permission
        if setting_category in ["security", "authentication", "encryption"]:
            return auth_manager.has_permission(current_user, Permission.SECURITY_ADMIN)
        
        # Network settings
        if setting_category in ["network", "firewall", "monitoring"]:
            return auth_manager.has_permission(current_user, Permission.NETWORK_ADMIN)
        
        # General settings
        return auth_manager.has_permission(current_user, Permission.SETTINGS_WRITE)

# Audit logging for authorization
class AuthorizationAuditor:
    """Audit authorization decisions and access attempts."""
    
    def __init__(self):
        self.access_log: List[Dict[str, Any]] = []
    
    def log_access_attempt(
        self,
        user: User,
        resource: str,
        action: str,
        granted: bool,
        reason: Optional[str] = None
    ):
        """Log access attempt."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user.id,
            "username": user.username,
            "resource": resource,
            "action": action,
            "granted": granted,
            "reason": reason,
            "user_roles": [role.value for role in auth_manager.get_user_roles(user)],
            "user_permissions": [perm.value for perm in auth_manager.get_user_permissions(user)]
        }
        
        self.access_log.append(log_entry)
        
        # Log to file
        log_level = logging.INFO if granted else logging.WARNING
        logger.log(
            log_level,
            f"Access {'granted' if granted else 'denied'}: {user.username} -> {resource}:{action} | Reason: {reason}"
        )
    
    def get_access_log(self, user_id: Optional[int] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get access log entries."""
        logs = self.access_log
        
        if user_id:
            logs = [log for log in logs if log["user_id"] == user_id]
        
        return logs[-limit:]

# Global auditor
auth_auditor = AuthorizationAuditor()

# Decorator for automatic authorization auditing
def audit_access(resource: str, action: str):
    """Decorator to audit access attempts."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Extract current_user from kwargs
            current_user = kwargs.get('current_user')
            if not current_user:
                # Try to find it in args
                for arg in args:
                    if isinstance(arg, User):
                        current_user = arg
                        break
            
            if current_user:
                try:
                    result = func(*args, **kwargs)
                    auth_auditor.log_access_attempt(
                        current_user, resource, action, True, "Access granted"
                    )
                    return result
                except HTTPException as e:
                    if e.status_code == status.HTTP_403_FORBIDDEN:
                        auth_auditor.log_access_attempt(
                            current_user, resource, action, False, e.detail
                        )
                    raise
                except Exception as e:
                    auth_auditor.log_access_attempt(
                        current_user, resource, action, False, f"Error: {str(e)}"
                    )
                    raise
            else:
                return func(*args, **kwargs)
        
        return wrapper
    return decorator

# Export authorization components
__all__ = [
    'Permission',
    'Role',
    'ROLE_PERMISSIONS',
    'UserContext',
    'AuthorizationManager',
    'auth_manager',
    'require_permission',
    'require_any_permission',
    'require_all_permissions',
    'require_role',
    'get_user_context',
    'ResourceAccessControl',
    'AuthorizationAuditor',
    'auth_auditor',
    'audit_access'
]

