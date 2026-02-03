"""
Tenant Isolation Module

Provides multi-tenant context management and isolation enforcement.
"""

from typing import Optional, Dict, Any, List, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import hashlib
import re


class TenantStatus(Enum):
    """Tenant account status"""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DISABLED = "disabled"


@dataclass
class TenantContext:
    """
    Represents a tenant in a multi-tenant system.
    
    Each tenant is isolated and cannot access resources from other tenants.
    """
    
    id: str
    name: str
    status: TenantStatus = TenantStatus.ACTIVE
    created_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)
    allowed_domains: Set[str] = field(default_factory=set)
    resource_limits: Dict[str, int] = field(default_factory=dict)
    
    def is_active(self) -> bool:
        """Check if tenant is active"""
        return self.status == TenantStatus.ACTIVE
    
    def validate_domain(self, domain: str) -> bool:
        """Check if a domain is allowed for this tenant"""
        if not self.allowed_domains:
            return True  # No domain restrictions
        return domain in self.allowed_domains


class TenantManager:
    """
    Manages tenant lifecycle and enforces tenant isolation.
    
    Ensures strict data separation between tenants.
    """
    
    def __init__(self) -> None:
        self._tenants: Dict[str, TenantContext] = {}
        self._current_tenant: Optional[str] = None
        
    def create_tenant(
        self,
        tenant_id: str,
        name: str,
        status: TenantStatus = TenantStatus.ACTIVE,
        metadata: Optional[Dict[str, Any]] = None,
        allowed_domains: Optional[Set[str]] = None,
        resource_limits: Optional[Dict[str, int]] = None,
    ) -> TenantContext:
        """
        Create a new tenant.
        
        Args:
            tenant_id: Unique identifier for the tenant
            name: Human-readable tenant name
            status: Initial status (default: ACTIVE)
            metadata: Additional tenant metadata
            allowed_domains: Set of allowed email domains
            resource_limits: Resource usage limits
            
        Returns:
            Created TenantContext
            
        Raises:
            ValueError: If tenant_id already exists
        """
        if tenant_id in self._tenants:
            raise ValueError(f"Tenant {tenant_id} already exists")
        
        # Validate tenant_id format (alphanumeric, dash, underscore only)
        if not re.match(r'^[a-zA-Z0-9_-]+$', tenant_id):
            raise ValueError(
                f"Invalid tenant_id format: {tenant_id}. "
                "Use only alphanumeric characters, dashes, and underscores."
            )
        
        tenant = TenantContext(
            id=tenant_id,
            name=name,
            status=status,
            metadata=metadata or {},
            allowed_domains=allowed_domains or set(),
            resource_limits=resource_limits or {},
        )
        
        self._tenants[tenant_id] = tenant
        return tenant
    
    def get_tenant(self, tenant_id: str) -> Optional[TenantContext]:
        """Retrieve a tenant by ID"""
        return self._tenants.get(tenant_id)
    
    def list_tenants(self, status: Optional[TenantStatus] = None) -> List[TenantContext]:
        """
        List all tenants, optionally filtered by status.
        
        Args:
            status: Optional status filter
            
        Returns:
            List of matching tenants
        """
        tenants = list(self._tenants.values())
        if status:
            tenants = [t for t in tenants if t.status == status]
        return tenants
    
    def update_tenant_status(self, tenant_id: str, status: TenantStatus) -> bool:
        """Update a tenant's status"""
        tenant = self._tenants.get(tenant_id)
        if not tenant:
            return False
        tenant.status = status
        return True
    
    def delete_tenant(self, tenant_id: str) -> bool:
        """
        Delete a tenant (soft delete by setting status to DISABLED).
        
        Note: This does not delete tenant data, just disables the tenant.
        Data deletion should be handled separately with proper audit logging.
        """
        tenant = self._tenants.get(tenant_id)
        if not tenant:
            return False
        tenant.status = TenantStatus.DISABLED
        return True
    
    def set_current_tenant(self, tenant_id: str) -> bool:
        """
        Set the current tenant context.
        
        This should be called at the start of each request/operation.
        """
        if tenant_id not in self._tenants:
            return False
        self._current_tenant = tenant_id
        return True
    
    def get_current_tenant(self) -> Optional[TenantContext]:
        """Get the current tenant context"""
        if not self._current_tenant:
            return None
        return self._tenants.get(self._current_tenant)
    
    def clear_current_tenant(self) -> None:
        """Clear the current tenant context"""
        self._current_tenant = None
    
    def validate_tenant_access(
        self,
        tenant_id: str,
        resource_tenant_id: str,
    ) -> bool:
        """
        Validate that a tenant can access a resource.
        
        Enforces tenant isolation: a tenant can only access its own resources.
        
        Args:
            tenant_id: ID of the tenant making the request
            resource_tenant_id: ID of the tenant that owns the resource
            
        Returns:
            True if access is allowed, False otherwise
        """
        # Strict tenant isolation: deny cross-tenant access
        return tenant_id == resource_tenant_id
    
    def check_resource_limit(
        self,
        tenant_id: str,
        resource_type: str,
        current_count: int,
    ) -> bool:
        """
        Check if a tenant has exceeded a resource limit.
        
        Args:
            tenant_id: Tenant ID
            resource_type: Type of resource (e.g., "memories", "users")
            current_count: Current resource count
            
        Returns:
            True if within limits, False if limit exceeded
        """
        tenant = self._tenants.get(tenant_id)
        if not tenant:
            return False
        
        limit = tenant.resource_limits.get(resource_type)
        if limit is None:
            return True  # No limit set
        
        return current_count < limit
