"""
Tests for tenant isolation module
"""

import pytest
from mem0_governance.tenant import (
    TenantContext,
    TenantManager,
    TenantStatus,
)


def test_tenant_creation():
    """Test tenant context creation"""
    tenant = TenantContext(
        id="tenant1",
        name="Tenant One",
        status=TenantStatus.ACTIVE,
    )
    
    assert tenant.id == "tenant1"
    assert tenant.name == "Tenant One"
    assert tenant.is_active()


def test_tenant_manager_create():
    """Test tenant creation via manager"""
    manager = TenantManager()
    
    tenant = manager.create_tenant(
        tenant_id="acme-corp",
        name="ACME Corporation",
        status=TenantStatus.ACTIVE,
    )
    
    assert tenant.id == "acme-corp"
    assert tenant.name == "ACME Corporation"
    assert manager.get_tenant("acme-corp") is not None


def test_tenant_id_validation():
    """Test tenant ID format validation"""
    manager = TenantManager()
    
    # Valid IDs
    manager.create_tenant("tenant-1", "Tenant 1")
    manager.create_tenant("tenant_2", "Tenant 2")
    manager.create_tenant("TenantABC", "Tenant ABC")
    
    # Invalid IDs should raise ValueError
    with pytest.raises(ValueError):
        manager.create_tenant("tenant@123", "Invalid")
    
    with pytest.raises(ValueError):
        manager.create_tenant("tenant 123", "Invalid")


def test_duplicate_tenant():
    """Test that duplicate tenant IDs are rejected"""
    manager = TenantManager()
    manager.create_tenant("tenant1", "Tenant 1")
    
    with pytest.raises(ValueError):
        manager.create_tenant("tenant1", "Duplicate")


def test_tenant_status_update():
    """Test tenant status updates"""
    manager = TenantManager()
    manager.create_tenant("tenant1", "Tenant 1", status=TenantStatus.ACTIVE)
    
    # Suspend tenant
    assert manager.update_tenant_status("tenant1", TenantStatus.SUSPENDED)
    tenant = manager.get_tenant("tenant1")
    assert tenant.status == TenantStatus.SUSPENDED
    assert not tenant.is_active()


def test_tenant_isolation():
    """Test strict tenant isolation"""
    manager = TenantManager()
    
    # Same tenant should be allowed
    assert manager.validate_tenant_access("tenant1", "tenant1")
    
    # Different tenant should be denied
    assert not manager.validate_tenant_access("tenant1", "tenant2")


def test_current_tenant_context():
    """Test tenant context management"""
    manager = TenantManager()
    manager.create_tenant("tenant1", "Tenant 1")
    
    # Set current tenant
    assert manager.set_current_tenant("tenant1")
    assert manager.get_current_tenant() is not None
    assert manager.get_current_tenant().id == "tenant1"
    
    # Clear current tenant
    manager.clear_current_tenant()
    assert manager.get_current_tenant() is None


def test_list_tenants():
    """Test listing tenants"""
    manager = TenantManager()
    
    manager.create_tenant("tenant1", "Tenant 1", status=TenantStatus.ACTIVE)
    manager.create_tenant("tenant2", "Tenant 2", status=TenantStatus.SUSPENDED)
    manager.create_tenant("tenant3", "Tenant 3", status=TenantStatus.ACTIVE)
    
    # List all tenants
    all_tenants = manager.list_tenants()
    assert len(all_tenants) == 3
    
    # List active tenants only
    active_tenants = manager.list_tenants(status=TenantStatus.ACTIVE)
    assert len(active_tenants) == 2


def test_tenant_resource_limits():
    """Test tenant resource limits"""
    manager = TenantManager()
    
    manager.create_tenant(
        "tenant1",
        "Tenant 1",
        resource_limits={"memories": 1000, "users": 50}
    )
    
    # Within limits
    assert manager.check_resource_limit("tenant1", "memories", 500)
    assert manager.check_resource_limit("tenant1", "users", 25)
    
    # Exceeding limits
    assert not manager.check_resource_limit("tenant1", "memories", 1000)
    assert not manager.check_resource_limit("tenant1", "users", 50)
    
    # No limit set
    assert manager.check_resource_limit("tenant1", "api_calls", 999999)


def test_tenant_domain_validation():
    """Test domain validation for tenants"""
    tenant = TenantContext(
        id="tenant1",
        name="Tenant 1",
        allowed_domains={"acme.com", "example.com"}
    )
    
    assert tenant.validate_domain("acme.com")
    assert tenant.validate_domain("example.com")
    assert not tenant.validate_domain("evil.com")


def test_tenant_soft_delete():
    """Test tenant soft deletion"""
    manager = TenantManager()
    manager.create_tenant("tenant1", "Tenant 1")
    
    # Soft delete
    assert manager.delete_tenant("tenant1")
    
    # Tenant still exists but is disabled
    tenant = manager.get_tenant("tenant1")
    assert tenant is not None
    assert tenant.status == TenantStatus.DISABLED
    assert not tenant.is_active()
