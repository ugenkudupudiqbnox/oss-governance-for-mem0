"""
Tests for RBAC module
"""

import pytest
from mem0_governance.rbac import (
    Role,
    Permission,
    RBACManager,
    Subject,
    ROLE_DEFINITIONS,
)


def test_role_definitions_exist():
    """Test that all roles have definitions"""
    for role in Role:
        assert role in ROLE_DEFINITIONS


def test_subject_creation():
    """Test subject creation with roles"""
    subject = Subject(
        id="user123",
        name="John Doe",
        roles={Role.USER},
        tenant_id="tenant1",
    )
    
    assert subject.id == "user123"
    assert subject.name == "John Doe"
    assert Role.USER in subject.roles
    assert subject.tenant_id == "tenant1"


def test_subject_permissions():
    """Test permission checking for subjects"""
    subject = Subject(
        id="user123",
        name="John Doe",
        roles={Role.USER},
    )
    
    # USER role should have memory read permission
    assert subject.has_permission(Permission.MEMORY_READ)
    assert subject.has_permission(Permission.MEMORY_WRITE)
    
    # USER role should NOT have admin permissions
    assert not subject.has_permission(Permission.ADMIN_RBAC)


def test_admin_has_all_permissions():
    """Test that admin role has all permissions"""
    subject = Subject(
        id="admin1",
        name="Admin User",
        roles={Role.ADMIN},
    )
    
    # Admin should have all permissions
    for permission in Permission:
        assert subject.has_permission(permission)


def test_guest_has_no_permissions():
    """Test that guest role has no permissions (deny-by-default)"""
    subject = Subject(
        id="guest1",
        name="Guest User",
        roles={Role.GUEST},
    )
    
    # Guest should have no permissions
    assert len(subject.get_all_permissions()) == 0


def test_rbac_manager_create_subject():
    """Test RBAC manager subject creation"""
    rbac = RBACManager()
    
    subject = rbac.create_subject(
        subject_id="user123",
        name="John Doe",
        roles={Role.USER},
        tenant_id="tenant1",
    )
    
    assert subject.id == "user123"
    assert rbac.get_subject("user123") is not None


def test_rbac_manager_assign_role():
    """Test role assignment"""
    rbac = RBACManager()
    rbac.create_subject("user123", "John Doe", roles={Role.USER})
    
    # Assign auditor role
    assert rbac.assign_role("user123", Role.AUDITOR)
    
    subject = rbac.get_subject("user123")
    assert Role.AUDITOR in subject.roles


def test_rbac_manager_revoke_role():
    """Test role revocation"""
    rbac = RBACManager()
    rbac.create_subject("user123", "John Doe", roles={Role.USER, Role.AUDITOR})
    
    # Revoke auditor role
    assert rbac.revoke_role("user123", Role.AUDITOR)
    
    subject = rbac.get_subject("user123")
    assert Role.AUDITOR not in subject.roles


def test_rbac_deny_by_default():
    """Test deny-by-default behavior"""
    rbac = RBACManager()
    
    # Non-existent subject should be denied
    assert not rbac.check_permission("nonexistent", Permission.MEMORY_READ)
    
    # Guest with no roles should be denied
    rbac.create_subject("guest1", "Guest", roles={Role.GUEST})
    assert not rbac.check_permission("guest1", Permission.MEMORY_READ)


def test_rbac_tenant_isolation():
    """Test tenant isolation in permission checks"""
    rbac = RBACManager()
    
    # Create subject in tenant1
    rbac.create_subject(
        subject_id="user123",
        name="John Doe",
        roles={Role.USER},
        tenant_id="tenant1",
    )
    
    # Access to own tenant should be allowed
    assert rbac.check_permission(
        "user123",
        Permission.MEMORY_READ,
        tenant_id="tenant1",
    )
    
    # Cross-tenant access should be denied
    assert not rbac.check_permission(
        "user123",
        Permission.MEMORY_READ,
        tenant_id="tenant2",
    )


def test_rbac_list_subjects_by_tenant():
    """Test listing subjects by tenant"""
    rbac = RBACManager()
    
    rbac.create_subject("user1", "User 1", tenant_id="tenant1")
    rbac.create_subject("user2", "User 2", tenant_id="tenant1")
    rbac.create_subject("user3", "User 3", tenant_id="tenant2")
    
    tenant1_subjects = rbac.list_subjects_by_tenant("tenant1")
    assert len(tenant1_subjects) == 2
    
    tenant2_subjects = rbac.list_subjects_by_tenant("tenant2")
    assert len(tenant2_subjects) == 1


def test_multiple_roles():
    """Test subject with multiple roles"""
    subject = Subject(
        id="user123",
        name="John Doe",
        roles={Role.USER, Role.AUDITOR},
    )
    
    # Should have permissions from both roles
    assert subject.has_permission(Permission.MEMORY_READ)  # from USER
    assert subject.has_permission(Permission.MEMORY_WRITE)  # from USER
    assert subject.has_permission(Permission.AUDIT_EXPORT)  # from AUDITOR
