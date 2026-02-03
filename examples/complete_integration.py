"""
Example: Complete Governance Integration

This example demonstrates how to integrate all governance components
to create a secure, auditable, multi-tenant Mem0 wrapper.
"""

from mem0_governance import (
    RBACManager, Role, Permission,
    TenantManager, TenantStatus,
    PolicyEngine, Policy, PolicyDecision,
    AuditLogger, AuditEventType, AuditSeverity,
    SecretManager, InputValidator,
)
from mem0_governance.config import GovernanceConfig
from mem0_governance.policy import create_tenant_isolation_policy
from typing import Optional, Dict, Any


class SecureMem0Wrapper:
    """
    Secure wrapper around Mem0 with full governance controls.
    
    This demonstrates how to integrate all governance features
    to create a production-ready, compliant memory system.
    """
    
    def __init__(self, config: Optional[GovernanceConfig] = None):
        """Initialize governance components"""
        
        # Load configuration
        self.config = config or GovernanceConfig.from_env()
        
        # Initialize governance components
        self.rbac = RBACManager()
        self.tenant_mgr = TenantManager()
        self.policy_engine = PolicyEngine()
        self.audit_logger = AuditLogger()
        self.secret_mgr = SecretManager()
        self.validator = InputValidator()
        
        # Load policies
        if self.config.policy_directory:
            self.policy_engine.load_policies_from_directory(
                self.config.policy_directory
            )
        
        # Note: In production, initialize actual Mem0 client here
        # self.mem0_client = Mem0Client(api_key=self.secret_mgr.get_secret("API_KEY"))
    
    def create_tenant(
        self,
        tenant_id: str,
        name: str,
        admin_user_id: str,
        admin_name: str,
    ) -> Dict[str, Any]:
        """
        Create a new tenant with admin user.
        
        This sets up tenant isolation and initial admin access.
        """
        
        # Validate inputs
        if not self.validator.validate_alphanumeric(tenant_id, allow_extended=True):
            raise ValueError("Invalid tenant ID format")
        
        # Create tenant
        tenant = self.tenant_mgr.create_tenant(
            tenant_id=tenant_id,
            name=name,
            status=TenantStatus.ACTIVE,
        )
        
        # Create tenant isolation policy
        isolation_policy = create_tenant_isolation_policy(tenant_id)
        self.policy_engine.add_policy(isolation_policy)
        
        # Create admin user
        admin = self.rbac.create_subject(
            subject_id=admin_user_id,
            name=admin_name,
            roles={Role.ADMIN},
            tenant_id=tenant_id,
        )
        
        # Log tenant creation
        self.audit_logger.log_event(
            event_type=AuditEventType.TENANT_CREATE,
            actor_id="system",
            actor_name="System",
            action="create_tenant",
            result="success",
            tenant_id=tenant_id,
            severity=AuditSeverity.INFO,
            details={
                "tenant_name": name,
                "admin_user_id": admin_user_id,
            },
        )
        
        return {
            "tenant_id": tenant.id,
            "tenant_name": tenant.name,
            "admin_user_id": admin.id,
        }
    
    def read_memory(
        self,
        user_id: str,
        user_name: str,
        tenant_id: str,
        memory_id: str,
        source_ip: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Read a memory with full governance checks.
        
        This demonstrates the complete security flow:
        1. Set tenant context
        2. Check RBAC permissions
        3. Evaluate policies
        4. Perform operation
        5. Log to audit trail
        """
        
        # 1. Set tenant context
        if not self.tenant_mgr.set_current_tenant(tenant_id):
            raise ValueError(f"Invalid tenant: {tenant_id}")
        
        tenant = self.tenant_mgr.get_current_tenant()
        if not tenant or not tenant.is_active():
            self.audit_logger.log_event(
                event_type=AuditEventType.SECURITY_ACCESS_DENIED,
                actor_id=user_id,
                actor_name=user_name,
                action="read_memory",
                result="denied",
                tenant_id=tenant_id,
                details={"reason": "Tenant not active"},
                severity=AuditSeverity.WARNING,
            )
            raise PermissionError("Tenant not active")
        
        # 2. Check RBAC permission
        if not self.rbac.check_permission(
            subject_id=user_id,
            permission=Permission.MEMORY_READ,
            tenant_id=tenant_id,
        ):
            self.audit_logger.log_event(
                event_type=AuditEventType.SECURITY_ACCESS_DENIED,
                actor_id=user_id,
                actor_name=user_name,
                action="read_memory",
                result="denied",
                tenant_id=tenant_id,
                resource_type="memory",
                resource_id=memory_id,
                details={"reason": "Insufficient RBAC permissions"},
                severity=AuditSeverity.WARNING,
                source_ip=source_ip,
            )
            raise PermissionError("Insufficient permissions")
        
        # 3. Evaluate policies
        resource_arn = f"memory:tenant:{tenant_id}:{memory_id}"
        decision = self.policy_engine.evaluate(
            action="memory:read",
            resource=resource_arn,
            context={
                "tenant_id": tenant_id,
                "user_id": user_id,
            },
        )
        
        if decision == PolicyDecision.DENIED:
            self.audit_logger.log_event(
                event_type=AuditEventType.POLICY_EVALUATE,
                actor_id=user_id,
                actor_name=user_name,
                action="policy_deny",
                result="denied",
                tenant_id=tenant_id,
                resource_type="memory",
                resource_id=memory_id,
                details={"reason": "Policy denied access"},
                severity=AuditSeverity.WARNING,
                source_ip=source_ip,
            )
            raise PermissionError("Policy denied access")
        
        # 4. Perform operation (call Mem0)
        try:
            # In production: result = self.mem0_client.get(memory_id)
            result = {
                "memory_id": memory_id,
                "content": "Sample memory content",
                "tenant_id": tenant_id,
            }
            
            # 5. Log successful access
            self.audit_logger.log_event(
                event_type=AuditEventType.MEMORY_READ,
                actor_id=user_id,
                actor_name=user_name,
                action="read_memory",
                result="success",
                tenant_id=tenant_id,
                resource_type="memory",
                resource_id=memory_id,
                severity=AuditSeverity.INFO,
                source_ip=source_ip,
            )
            
            return result
            
        except Exception as e:
            # Log error
            self.audit_logger.log_event(
                event_type=AuditEventType.MEMORY_READ,
                actor_id=user_id,
                actor_name=user_name,
                action="read_memory",
                result="error",
                tenant_id=tenant_id,
                resource_type="memory",
                resource_id=memory_id,
                details={"error": str(e)},
                severity=AuditSeverity.ERROR,
                source_ip=source_ip,
            )
            raise
        
        finally:
            # Clear tenant context
            self.tenant_mgr.clear_current_tenant()
    
    def export_audit_logs(
        self,
        requester_id: str,
        requester_name: str,
        tenant_id: str,
        format: str = "json",
    ) -> str:
        """
        Export audit logs for compliance.
        
        Requires AUDIT_EXPORT permission.
        """
        
        # Check permission
        if not self.rbac.check_permission(
            subject_id=requester_id,
            permission=Permission.AUDIT_EXPORT,
            tenant_id=tenant_id,
        ):
            self.audit_logger.log_event(
                event_type=AuditEventType.SECURITY_ACCESS_DENIED,
                actor_id=requester_id,
                actor_name=requester_name,
                action="export_audit_logs",
                result="denied",
                tenant_id=tenant_id,
                severity=AuditSeverity.WARNING,
            )
            raise PermissionError("Insufficient permissions for audit export")
        
        # Export logs
        logs = self.audit_logger.export_events(
            format=format,
            tenant_id=tenant_id,
        )
        
        # Log export
        self.audit_logger.log_event(
            event_type=AuditEventType.AUDIT_EXPORT,
            actor_id=requester_id,
            actor_name=requester_name,
            action="export_audit_logs",
            result="success",
            tenant_id=tenant_id,
            severity=AuditSeverity.INFO,
            details={"format": format, "record_count": self.audit_logger.get_event_count()},
        )
        
        return logs
    
    def verify_audit_integrity(self) -> bool:
        """
        Verify audit log integrity.
        
        Returns True if no tampering detected.
        """
        is_valid = self.audit_logger.verify_integrity()
        
        if not is_valid:
            # Log critical security event
            self.audit_logger.log_event(
                event_type=AuditEventType.SECURITY_VIOLATION,
                actor_id="system",
                actor_name="System",
                action="audit_integrity_check",
                result="failed",
                severity=AuditSeverity.CRITICAL,
                details={"reason": "Audit log tampering detected"},
            )
        
        return is_valid


def main():
    """Example usage"""
    
    # Initialize governance wrapper
    wrapper = SecureMem0Wrapper()
    
    # Create tenant with admin
    tenant_info = wrapper.create_tenant(
        tenant_id="acme-corp",
        name="ACME Corporation",
        admin_user_id="admin001",
        admin_name="Admin User",
    )
    print(f"Created tenant: {tenant_info}")
    
    # Create regular user
    wrapper.rbac.create_subject(
        subject_id="user001",
        name="John Doe",
        roles={Role.USER},
        tenant_id="acme-corp",
    )
    
    # Read memory with full governance
    try:
        memory = wrapper.read_memory(
            user_id="user001",
            user_name="John Doe",
            tenant_id="acme-corp",
            memory_id="mem123",
            source_ip="192.168.1.100",
        )
        print(f"Successfully read memory: {memory}")
    except PermissionError as e:
        print(f"Access denied: {e}")
    
    # Export audit logs (requires AUDIT_EXPORT permission)
    try:
        logs = wrapper.export_audit_logs(
            requester_id="admin001",
            requester_name="Admin User",
            tenant_id="acme-corp",
            format="json",
        )
        print(f"Exported {len(logs)} bytes of audit logs")
    except PermissionError as e:
        print(f"Audit export denied: {e}")
    
    # Verify audit integrity
    is_valid = wrapper.verify_audit_integrity()
    print(f"Audit log integrity: {'VALID' if is_valid else 'COMPROMISED'}")


if __name__ == "__main__":
    main()
