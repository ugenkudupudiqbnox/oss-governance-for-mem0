"""
Configuration Module

Manages configuration without hard-coded secrets or sensitive data.
"""

from typing import Dict, Any, Optional, List
import os
import yaml
import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class GovernanceConfig:
    """
    Central configuration for governance pack.
    
    All secrets should come from environment variables, not config files.
    """
    
    # RBAC settings
    rbac_enabled: bool = True
    default_role: str = "guest"
    
    # Tenant settings
    tenant_isolation_enabled: bool = True
    max_tenants: Optional[int] = None
    
    # Policy settings
    policy_engine_enabled: bool = True
    policy_directory: Optional[str] = None
    deny_by_default: bool = True
    
    # Audit settings
    audit_enabled: bool = True
    audit_retention_days: int = 365
    audit_export_enabled: bool = True
    
    # Security settings
    require_secure_secrets: bool = True
    min_secret_length: int = 32
    rate_limit_enabled: bool = True
    rate_limit_requests: int = 100
    rate_limit_window: int = 60
    
    # Environment
    environment: str = "production"
    debug: bool = False
    
    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @classmethod
    def from_env(cls, prefix: str = "MEM0_GOV_") -> "GovernanceConfig":
        """
        Load configuration from environment variables.
        
        Args:
            prefix: Environment variable prefix
            
        Returns:
            GovernanceConfig instance
        """
        def get_bool(key: str, default: bool) -> bool:
            value = os.environ.get(f"{prefix}{key}")
            if value is None:
                return default
            return value.lower() in ("true", "1", "yes", "on")
        
        def get_int(key: str, default: int) -> int:
            value = os.environ.get(f"{prefix}{key}")
            if value is None:
                return default
            try:
                return int(value)
            except ValueError:
                return default
        
        def get_str(key: str, default: str) -> str:
            return os.environ.get(f"{prefix}{key}", default)
        
        return cls(
            rbac_enabled=get_bool("RBAC_ENABLED", True),
            default_role=get_str("DEFAULT_ROLE", "guest"),
            tenant_isolation_enabled=get_bool("TENANT_ISOLATION_ENABLED", True),
            max_tenants=get_int("MAX_TENANTS", 0) or None,
            policy_engine_enabled=get_bool("POLICY_ENGINE_ENABLED", True),
            policy_directory=os.environ.get(f"{prefix}POLICY_DIRECTORY"),
            deny_by_default=get_bool("DENY_BY_DEFAULT", True),
            audit_enabled=get_bool("AUDIT_ENABLED", True),
            audit_retention_days=get_int("AUDIT_RETENTION_DAYS", 365),
            audit_export_enabled=get_bool("AUDIT_EXPORT_ENABLED", True),
            require_secure_secrets=get_bool("REQUIRE_SECURE_SECRETS", True),
            min_secret_length=get_int("MIN_SECRET_LENGTH", 32),
            rate_limit_enabled=get_bool("RATE_LIMIT_ENABLED", True),
            rate_limit_requests=get_int("RATE_LIMIT_REQUESTS", 100),
            rate_limit_window=get_int("RATE_LIMIT_WINDOW", 60),
            environment=get_str("ENVIRONMENT", "production"),
            debug=get_bool("DEBUG", False),
        )
    
    @classmethod
    def from_file(cls, filepath: str) -> "GovernanceConfig":
        """
        Load configuration from a YAML or JSON file.
        
        Note: Files should NOT contain secrets!
        
        Args:
            filepath: Path to config file
            
        Returns:
            GovernanceConfig instance
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {filepath}")
        
        with open(filepath, 'r') as f:
            if filepath.endswith('.yaml') or filepath.endswith('.yml'):
                data = yaml.safe_load(f)
            elif filepath.endswith('.json'):
                data = json.load(f)
            else:
                raise ValueError(f"Unsupported config format: {filepath}")
        
        return cls(**data)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary"""
        return {
            "rbac_enabled": self.rbac_enabled,
            "default_role": self.default_role,
            "tenant_isolation_enabled": self.tenant_isolation_enabled,
            "max_tenants": self.max_tenants,
            "policy_engine_enabled": self.policy_engine_enabled,
            "policy_directory": self.policy_directory,
            "deny_by_default": self.deny_by_default,
            "audit_enabled": self.audit_enabled,
            "audit_retention_days": self.audit_retention_days,
            "audit_export_enabled": self.audit_export_enabled,
            "require_secure_secrets": self.require_secure_secrets,
            "min_secret_length": self.min_secret_length,
            "rate_limit_enabled": self.rate_limit_enabled,
            "rate_limit_requests": self.rate_limit_requests,
            "rate_limit_window": self.rate_limit_window,
            "environment": self.environment,
            "debug": self.debug,
            "metadata": self.metadata,
        }
    
    def validate(self) -> List[str]:
        """
        Validate configuration.
        
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        if self.audit_retention_days < 1:
            errors.append("audit_retention_days must be at least 1")
        
        if self.min_secret_length < 8:
            errors.append("min_secret_length must be at least 8")
        
        if self.rate_limit_requests < 1:
            errors.append("rate_limit_requests must be at least 1")
        
        if self.rate_limit_window < 1:
            errors.append("rate_limit_window must be at least 1")
        
        if self.environment not in ("development", "staging", "production"):
            errors.append(
                f"Invalid environment: {self.environment}. "
                "Must be development, staging, or production"
            )
        
        return errors
