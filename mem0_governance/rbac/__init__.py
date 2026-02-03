"""
RBAC (Role-Based Access Control) Module

Provides role and permission management with deny-by-default access control.
"""

from enum import Enum
from typing import Set, List, Optional, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime
import hashlib


class Permission(Enum):
    """Fine-grained permissions for Mem0 operations"""
    
    # Memory operations
    MEMORY_READ = "memory:read"
    MEMORY_WRITE = "memory:write"
    MEMORY_DELETE = "memory:delete"
    MEMORY_SEARCH = "memory:search"
    
    # User operations
    USER_READ = "user:read"
    USER_WRITE = "user:write"
    USER_DELETE = "user:delete"
    
    # Admin operations
    ADMIN_RBAC = "admin:rbac"
    ADMIN_AUDIT = "admin:audit"
    ADMIN_POLICY = "admin:policy"
    ADMIN_TENANT = "admin:tenant"
    
    # Audit operations
    AUDIT_READ = "audit:read"
    AUDIT_EXPORT = "audit:export"


class Role(Enum):
    """Predefined roles with specific permission sets"""
    
    ADMIN = "admin"
    AUDITOR = "auditor"
    USER = "user"
    READ_ONLY = "read_only"
    GUEST = "guest"


@dataclass
class RoleDefinition:
    """Definition of a role with its permissions"""
    
    name: Role
    permissions: Set[Permission]
    description: str
    inherits_from: Optional[Role] = None


# Role hierarchy with explicit permissions (deny-by-default)
ROLE_DEFINITIONS: Dict[Role, RoleDefinition] = {
    Role.ADMIN: RoleDefinition(
        name=Role.ADMIN,
        permissions={
            Permission.MEMORY_READ,
            Permission.MEMORY_WRITE,
            Permission.MEMORY_DELETE,
            Permission.MEMORY_SEARCH,
            Permission.USER_READ,
            Permission.USER_WRITE,
            Permission.USER_DELETE,
            Permission.ADMIN_RBAC,
            Permission.ADMIN_AUDIT,
            Permission.ADMIN_POLICY,
            Permission.ADMIN_TENANT,
            Permission.AUDIT_READ,
            Permission.AUDIT_EXPORT,
        },
        description="Full administrative access to all resources",
    ),
    Role.AUDITOR: RoleDefinition(
        name=Role.AUDITOR,
        permissions={
            Permission.MEMORY_READ,
            Permission.MEMORY_SEARCH,
            Permission.USER_READ,
            Permission.AUDIT_READ,
            Permission.AUDIT_EXPORT,
        },
        description="Read-only access with audit log export capabilities",
    ),
    Role.USER: RoleDefinition(
        name=Role.USER,
        permissions={
            Permission.MEMORY_READ,
            Permission.MEMORY_WRITE,
            Permission.MEMORY_DELETE,
            Permission.MEMORY_SEARCH,
        },
        description="Standard user with memory management capabilities",
    ),
    Role.READ_ONLY: RoleDefinition(
        name=Role.READ_ONLY,
        permissions={
            Permission.MEMORY_READ,
            Permission.MEMORY_SEARCH,
        },
        description="Read-only access to memories",
    ),
    Role.GUEST: RoleDefinition(
        name=Role.GUEST,
        permissions=set(),  # No permissions by default
        description="Guest access with no default permissions",
    ),
}


@dataclass
class Subject:
    """Represents an entity that can have roles and permissions"""
    
    id: str
    name: str
    roles: Set[Role] = field(default_factory=set)
    tenant_id: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_all_permissions(self) -> Set[Permission]:
        """Get all permissions from assigned roles"""
        permissions: Set[Permission] = set()
        for role in self.roles:
            if role in ROLE_DEFINITIONS:
                permissions.update(ROLE_DEFINITIONS[role].permissions)
        return permissions
    
    def has_permission(self, permission: Permission) -> bool:
        """Check if subject has a specific permission"""
        return permission in self.get_all_permissions()
    
    def has_any_permission(self, permissions: List[Permission]) -> bool:
        """Check if subject has any of the specified permissions"""
        subject_perms = self.get_all_permissions()
        return any(perm in subject_perms for perm in permissions)
    
    def has_all_permissions(self, permissions: List[Permission]) -> bool:
        """Check if subject has all of the specified permissions"""
        subject_perms = self.get_all_permissions()
        return all(perm in subject_perms for perm in permissions)


class RBACManager:
    """
    RBAC Manager for enforcing role-based access control.
    
    Follows deny-by-default principle: access is denied unless explicitly granted.
    """
    
    def __init__(self) -> None:
        self._subjects: Dict[str, Subject] = {}
        
    def create_subject(
        self,
        subject_id: str,
        name: str,
        roles: Optional[Set[Role]] = None,
        tenant_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Subject:
        """Create a new subject with specified roles"""
        if roles is None:
            roles = {Role.GUEST}  # Default to no permissions
            
        subject = Subject(
            id=subject_id,
            name=name,
            roles=roles,
            tenant_id=tenant_id,
            metadata=metadata or {},
        )
        self._subjects[subject_id] = subject
        return subject
    
    def get_subject(self, subject_id: str) -> Optional[Subject]:
        """Retrieve a subject by ID"""
        return self._subjects.get(subject_id)
    
    def assign_role(self, subject_id: str, role: Role) -> bool:
        """Assign a role to a subject"""
        subject = self._subjects.get(subject_id)
        if not subject:
            return False
        subject.roles.add(role)
        return True
    
    def revoke_role(self, subject_id: str, role: Role) -> bool:
        """Revoke a role from a subject"""
        subject = self._subjects.get(subject_id)
        if not subject:
            return False
        subject.roles.discard(role)
        return True
    
    def check_permission(
        self,
        subject_id: str,
        permission: Permission,
        tenant_id: Optional[str] = None,
    ) -> bool:
        """
        Check if a subject has a specific permission.
        
        Args:
            subject_id: ID of the subject
            permission: Permission to check
            tenant_id: Optional tenant context for multi-tenancy
            
        Returns:
            True if permission is granted, False otherwise (deny-by-default)
        """
        subject = self._subjects.get(subject_id)
        if not subject:
            return False  # Deny by default
        
        # Enforce tenant isolation if tenant_id is provided
        if tenant_id and subject.tenant_id != tenant_id:
            return False  # Cross-tenant access denied
        
        return subject.has_permission(permission)
    
    def get_subject_permissions(self, subject_id: str) -> Set[Permission]:
        """Get all permissions for a subject"""
        subject = self._subjects.get(subject_id)
        if not subject:
            return set()
        return subject.get_all_permissions()
    
    def list_subjects_by_tenant(self, tenant_id: str) -> List[Subject]:
        """List all subjects for a specific tenant"""
        return [s for s in self._subjects.values() if s.tenant_id == tenant_id]
