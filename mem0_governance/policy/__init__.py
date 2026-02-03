"""
Policy Engine Module

Implements deny-by-default policy evaluation with policy-as-code support.
"""

from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import yaml
import json


class PolicyEffect(Enum):
    """Policy evaluation effect"""
    ALLOW = "allow"
    DENY = "deny"


class PolicyDecision(Enum):
    """Final policy decision"""
    ALLOWED = "allowed"
    DENIED = "denied"


@dataclass
class PolicyStatement:
    """
    Represents a single policy statement.
    
    Follows AWS IAM-like policy structure.
    """
    
    effect: PolicyEffect
    actions: List[str]
    resources: List[str]
    conditions: Optional[Dict[str, Any]] = None
    
    def matches_action(self, action: str) -> bool:
        """Check if action matches this statement"""
        for pattern in self.actions:
            if pattern == "*" or pattern == action:
                return True
            # Support wildcard matching (e.g., "memory:*")
            if "*" in pattern:
                prefix = pattern.replace("*", "")
                if action.startswith(prefix):
                    return True
        return False
    
    def matches_resource(self, resource: str) -> bool:
        """Check if resource matches this statement"""
        for pattern in self.resources:
            if pattern == "*" or pattern == resource:
                return True
            # Support wildcard matching
            if "*" in pattern:
                prefix = pattern.replace("*", "")
                if resource.startswith(prefix):
                    return True
        return False
    
    def evaluate_conditions(self, context: Dict[str, Any]) -> bool:
        """Evaluate conditions against context"""
        if not self.conditions:
            return True
        
        for condition_key, condition_value in self.conditions.items():
            context_value = context.get(condition_key)
            
            # Simple equality check
            if isinstance(condition_value, dict):
                # Support operators like {"equals": "value"}
                for operator, expected in condition_value.items():
                    if operator == "equals" and context_value != expected:
                        return False
                    elif operator == "not_equals" and context_value == expected:
                        return False
                    elif operator == "in" and context_value not in expected:
                        return False
            else:
                # Direct comparison
                if context_value != condition_value:
                    return False
        
        return True


@dataclass
class Policy:
    """
    Represents a complete policy with multiple statements.
    
    Policies are evaluated in order, with explicit DENY taking precedence.
    """
    
    id: str
    name: str
    version: str = "1.0"
    statements: List[PolicyStatement] = field(default_factory=list)
    description: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @classmethod
    def from_yaml(cls, yaml_str: str) -> "Policy":
        """Load policy from YAML string"""
        data = yaml.safe_load(yaml_str)
        return cls.from_dict(data)
    
    @classmethod
    def from_json(cls, json_str: str) -> "Policy":
        """Load policy from JSON string"""
        data = json.loads(json_str)
        return cls.from_dict(data)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Policy":
        """Load policy from dictionary"""
        statements = []
        for stmt_data in data.get("statements", []):
            statements.append(
                PolicyStatement(
                    effect=PolicyEffect(stmt_data["effect"].lower()),
                    actions=stmt_data["actions"],
                    resources=stmt_data["resources"],
                    conditions=stmt_data.get("conditions"),
                )
            )
        
        return cls(
            id=data["id"],
            name=data["name"],
            version=data.get("version", "1.0"),
            statements=statements,
            description=data.get("description", ""),
            metadata=data.get("metadata", {}),
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert policy to dictionary"""
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "statements": [
                {
                    "effect": stmt.effect.value,
                    "actions": stmt.actions,
                    "resources": stmt.resources,
                    "conditions": stmt.conditions,
                }
                for stmt in self.statements
            ],
            "metadata": self.metadata,
        }
    
    def to_yaml(self) -> str:
        """Convert policy to YAML string"""
        return yaml.dump(self.to_dict(), default_flow_style=False)
    
    def to_json(self) -> str:
        """Convert policy to JSON string"""
        return json.dumps(self.to_dict(), indent=2)


class PolicyEngine:
    """
    Policy evaluation engine with deny-by-default semantics.
    
    Evaluation rules:
    1. If no policies match, DENY (default)
    2. If any explicit DENY matches, DENY
    3. If any ALLOW matches and no DENY, ALLOW
    4. Otherwise, DENY
    """
    
    def __init__(self) -> None:
        self._policies: Dict[str, Policy] = {}
        
    def add_policy(self, policy: Policy) -> None:
        """Add a policy to the engine"""
        self._policies[policy.id] = policy
    
    def remove_policy(self, policy_id: str) -> bool:
        """Remove a policy from the engine"""
        if policy_id in self._policies:
            del self._policies[policy_id]
            return True
        return False
    
    def get_policy(self, policy_id: str) -> Optional[Policy]:
        """Get a policy by ID"""
        return self._policies.get(policy_id)
    
    def list_policies(self) -> List[Policy]:
        """List all policies"""
        return list(self._policies.values())
    
    def evaluate(
        self,
        action: str,
        resource: str,
        context: Optional[Dict[str, Any]] = None,
        policy_ids: Optional[List[str]] = None,
    ) -> PolicyDecision:
        """
        Evaluate policies for an action on a resource.
        
        Args:
            action: Action to evaluate (e.g., "memory:read")
            resource: Resource to evaluate (e.g., "memory:tenant1:mem123")
            context: Additional context for condition evaluation
            policy_ids: Optional list of specific policy IDs to evaluate
            
        Returns:
            PolicyDecision.ALLOWED or PolicyDecision.DENIED
        """
        context = context or {}
        
        # Select policies to evaluate
        if policy_ids:
            policies = [self._policies[pid] for pid in policy_ids if pid in self._policies]
        else:
            policies = list(self._policies.values())
        
        # If no policies, deny by default
        if not policies:
            return PolicyDecision.DENIED
        
        has_allow = False
        has_deny = False
        
        # Evaluate all policies
        for policy in policies:
            for statement in policy.statements:
                # Check if statement matches action and resource
                if not statement.matches_action(action):
                    continue
                if not statement.matches_resource(resource):
                    continue
                if not statement.evaluate_conditions(context):
                    continue
                
                # Statement matches
                if statement.effect == PolicyEffect.DENY:
                    has_deny = True
                elif statement.effect == PolicyEffect.ALLOW:
                    has_allow = True
        
        # Apply evaluation rules
        # Explicit DENY always wins
        if has_deny:
            return PolicyDecision.DENIED
        
        # ALLOW only if explicitly stated
        if has_allow:
            return PolicyDecision.ALLOWED
        
        # Default DENY
        return PolicyDecision.DENIED
    
    def load_policies_from_directory(self, directory: str) -> int:
        """
        Load policies from a directory containing YAML/JSON files.
        
        Returns:
            Number of policies loaded
        """
        import os
        
        count = 0
        if not os.path.exists(directory):
            return count
        
        for filename in os.listdir(directory):
            filepath = os.path.join(directory, filename)
            if not os.path.isfile(filepath):
                continue
            
            try:
                with open(filepath, 'r') as f:
                    content = f.read()
                    
                if filename.endswith('.yaml') or filename.endswith('.yml'):
                    policy = Policy.from_yaml(content)
                    self.add_policy(policy)
                    count += 1
                elif filename.endswith('.json'):
                    policy = Policy.from_json(content)
                    self.add_policy(policy)
                    count += 1
            except Exception as e:
                # Log error but continue processing other files
                print(f"Error loading policy from {filename}: {e}")
        
        return count


def create_default_deny_policy() -> Policy:
    """Create a default deny-all policy"""
    return Policy(
        id="default-deny",
        name="Default Deny All",
        description="Default policy that denies all actions (fail-safe)",
        statements=[
            PolicyStatement(
                effect=PolicyEffect.DENY,
                actions=["*"],
                resources=["*"],
            )
        ],
    )


def create_tenant_isolation_policy(tenant_id: str) -> Policy:
    """
    Create a policy that enforces tenant isolation.
    
    Only allows access to resources belonging to the specified tenant.
    """
    return Policy(
        id=f"tenant-isolation-{tenant_id}",
        name=f"Tenant Isolation - {tenant_id}",
        description=f"Enforces tenant isolation for tenant {tenant_id}",
        statements=[
            PolicyStatement(
                effect=PolicyEffect.ALLOW,
                actions=["*"],
                resources=[f"*:tenant:{tenant_id}:*"],
                conditions={
                    "tenant_id": {"equals": tenant_id}
                },
            ),
            PolicyStatement(
                effect=PolicyEffect.DENY,
                actions=["*"],
                resources=["*"],
                conditions={
                    "tenant_id": {"not_equals": tenant_id}
                },
            ),
        ],
    )
