"""
Tests for policy engine module
"""

import pytest
from mem0_governance.policy import (
    Policy,
    PolicyStatement,
    PolicyEffect,
    PolicyEngine,
    PolicyDecision,
    create_default_deny_policy,
    create_tenant_isolation_policy,
)


def test_policy_statement_creation():
    """Test policy statement creation"""
    stmt = PolicyStatement(
        effect=PolicyEffect.ALLOW,
        actions=["memory:read", "memory:write"],
        resources=["memory:*"],
    )
    
    assert stmt.effect == PolicyEffect.ALLOW
    assert "memory:read" in stmt.actions


def test_policy_statement_action_matching():
    """Test action matching with wildcards"""
    stmt = PolicyStatement(
        effect=PolicyEffect.ALLOW,
        actions=["memory:*"],
        resources=["*"],
    )
    
    assert stmt.matches_action("memory:read")
    assert stmt.matches_action("memory:write")
    assert not stmt.matches_action("user:read")


def test_policy_statement_resource_matching():
    """Test resource matching with wildcards"""
    stmt = PolicyStatement(
        effect=PolicyEffect.ALLOW,
        actions=["*"],
        resources=["memory:tenant:123:*"],
    )
    
    assert stmt.matches_resource("memory:tenant:123:mem456")
    assert not stmt.matches_resource("memory:tenant:456:mem789")


def test_policy_creation():
    """Test policy creation"""
    policy = Policy(
        id="test-policy",
        name="Test Policy",
        statements=[
            PolicyStatement(
                effect=PolicyEffect.ALLOW,
                actions=["memory:read"],
                resources=["*"],
            )
        ],
    )
    
    assert policy.id == "test-policy"
    assert len(policy.statements) == 1


def test_policy_from_dict():
    """Test loading policy from dictionary"""
    data = {
        "id": "test-policy",
        "name": "Test Policy",
        "version": "1.0",
        "statements": [
            {
                "effect": "allow",
                "actions": ["memory:read"],
                "resources": ["*"],
            }
        ],
    }
    
    policy = Policy.from_dict(data)
    assert policy.id == "test-policy"
    assert len(policy.statements) == 1


def test_policy_to_dict():
    """Test converting policy to dictionary"""
    policy = Policy(
        id="test-policy",
        name="Test Policy",
        statements=[
            PolicyStatement(
                effect=PolicyEffect.ALLOW,
                actions=["memory:read"],
                resources=["*"],
            )
        ],
    )
    
    data = policy.to_dict()
    assert data["id"] == "test-policy"
    assert len(data["statements"]) == 1


def test_policy_engine_deny_by_default():
    """Test deny-by-default behavior"""
    engine = PolicyEngine()
    
    # No policies = DENY
    decision = engine.evaluate(
        action="memory:read",
        resource="memory:123",
    )
    assert decision == PolicyDecision.DENIED


def test_policy_engine_explicit_allow():
    """Test explicit allow"""
    engine = PolicyEngine()
    
    policy = Policy(
        id="allow-read",
        name="Allow Read",
        statements=[
            PolicyStatement(
                effect=PolicyEffect.ALLOW,
                actions=["memory:read"],
                resources=["*"],
            )
        ],
    )
    engine.add_policy(policy)
    
    decision = engine.evaluate(
        action="memory:read",
        resource="memory:123",
    )
    assert decision == PolicyDecision.ALLOWED


def test_policy_engine_explicit_deny_wins():
    """Test that explicit DENY takes precedence over ALLOW"""
    engine = PolicyEngine()
    
    # Add allow policy
    allow_policy = Policy(
        id="allow-all",
        name="Allow All",
        statements=[
            PolicyStatement(
                effect=PolicyEffect.ALLOW,
                actions=["*"],
                resources=["*"],
            )
        ],
    )
    engine.add_policy(allow_policy)
    
    # Add deny policy
    deny_policy = Policy(
        id="deny-delete",
        name="Deny Delete",
        statements=[
            PolicyStatement(
                effect=PolicyEffect.DENY,
                actions=["memory:delete"],
                resources=["*"],
            )
        ],
    )
    engine.add_policy(deny_policy)
    
    # Read should be allowed
    decision = engine.evaluate("memory:read", "memory:123")
    assert decision == PolicyDecision.ALLOWED
    
    # Delete should be denied
    decision = engine.evaluate("memory:delete", "memory:123")
    assert decision == PolicyDecision.DENIED


def test_policy_conditions():
    """Test policy conditions"""
    engine = PolicyEngine()
    
    policy = Policy(
        id="tenant-policy",
        name="Tenant Policy",
        statements=[
            PolicyStatement(
                effect=PolicyEffect.ALLOW,
                actions=["memory:read"],
                resources=["*"],
                conditions={"tenant_id": {"equals": "tenant1"}},
            )
        ],
    )
    engine.add_policy(policy)
    
    # Should be allowed with correct tenant
    decision = engine.evaluate(
        action="memory:read",
        resource="memory:123",
        context={"tenant_id": "tenant1"},
    )
    assert decision == PolicyDecision.ALLOWED
    
    # Should be denied with wrong tenant
    decision = engine.evaluate(
        action="memory:read",
        resource="memory:123",
        context={"tenant_id": "tenant2"},
    )
    assert decision == PolicyDecision.DENIED


def test_default_deny_policy():
    """Test default deny policy creation"""
    policy = create_default_deny_policy()
    
    assert policy.id == "default-deny"
    assert len(policy.statements) == 1
    assert policy.statements[0].effect == PolicyEffect.DENY


def test_tenant_isolation_policy():
    """Test tenant isolation policy creation"""
    policy = create_tenant_isolation_policy("tenant1")
    
    assert "tenant1" in policy.id
    assert len(policy.statements) >= 1


def test_policy_removal():
    """Test removing policies"""
    engine = PolicyEngine()
    
    policy = Policy(
        id="test-policy",
        name="Test",
        statements=[],
    )
    engine.add_policy(policy)
    
    assert engine.get_policy("test-policy") is not None
    assert engine.remove_policy("test-policy")
    assert engine.get_policy("test-policy") is None


def test_policy_list():
    """Test listing policies"""
    engine = PolicyEngine()
    
    engine.add_policy(Policy(id="policy1", name="Policy 1", statements=[]))
    engine.add_policy(Policy(id="policy2", name="Policy 2", statements=[]))
    
    policies = engine.list_policies()
    assert len(policies) == 2
