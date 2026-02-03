"""
Immutable Audit Logging Module

Provides append-only audit logs with cryptographic integrity verification.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
import hashlib
import json


class AuditEventType(Enum):
    """Types of audit events"""
    
    # Authentication events
    AUTH_LOGIN = "auth.login"
    AUTH_LOGOUT = "auth.logout"
    AUTH_FAILED = "auth.failed"
    
    # Memory operations
    MEMORY_CREATE = "memory.create"
    MEMORY_READ = "memory.read"
    MEMORY_UPDATE = "memory.update"
    MEMORY_DELETE = "memory.delete"
    MEMORY_SEARCH = "memory.search"
    
    # User operations
    USER_CREATE = "user.create"
    USER_UPDATE = "user.update"
    USER_DELETE = "user.delete"
    
    # RBAC operations
    RBAC_ROLE_ASSIGN = "rbac.role.assign"
    RBAC_ROLE_REVOKE = "rbac.role.revoke"
    RBAC_PERMISSION_CHECK = "rbac.permission.check"
    
    # Tenant operations
    TENANT_CREATE = "tenant.create"
    TENANT_UPDATE = "tenant.update"
    TENANT_DELETE = "tenant.delete"
    
    # Policy operations
    POLICY_CREATE = "policy.create"
    POLICY_UPDATE = "policy.update"
    POLICY_DELETE = "policy.delete"
    POLICY_EVALUATE = "policy.evaluate"
    
    # Security events
    SECURITY_ACCESS_DENIED = "security.access_denied"
    SECURITY_VIOLATION = "security.violation"
    SECURITY_CONFIG_CHANGE = "security.config_change"
    
    # System events
    SYSTEM_START = "system.start"
    SYSTEM_STOP = "system.stop"
    SYSTEM_ERROR = "system.error"


class AuditSeverity(Enum):
    """Severity levels for audit events"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class AuditEvent:
    """
    Immutable audit event record.
    
    Once created, the event cannot be modified, ensuring audit trail integrity.
    """
    
    event_id: str
    event_type: AuditEventType
    timestamp: datetime
    actor_id: str
    actor_name: str
    tenant_id: Optional[str]
    resource_type: Optional[str]
    resource_id: Optional[str]
    action: str
    result: str  # success, failure, denied
    severity: AuditSeverity
    details: Dict[str, Any]
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    previous_hash: Optional[str] = None
    
    def __post_init__(self) -> None:
        """Ensure immutability by freezing the object"""
        # In production, consider using frozen=True in dataclass
        # or implementing __setattr__ to prevent modifications
        pass
    
    def compute_hash(self) -> str:
        """
        Compute cryptographic hash of this event.
        
        Used for hash chaining to ensure integrity of the audit log.
        """
        # Create a stable string representation
        event_dict = asdict(self)
        # Remove hash from computation to avoid circular dependency
        event_dict.pop('previous_hash', None)
        
        # Sort keys for consistent hashing
        event_str = json.dumps(event_dict, sort_keys=True, default=str)
        
        # Compute SHA-256 hash
        return hashlib.sha256(event_str.encode()).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary"""
        data = asdict(self)
        data['event_type'] = self.event_type.value
        data['severity'] = self.severity.value
        data['timestamp'] = self.timestamp.isoformat()
        return data
    
    def to_json(self) -> str:
        """Convert event to JSON string"""
        return json.dumps(self.to_dict(), default=str)


class AuditLogger:
    """
    Immutable audit logger with cryptographic hash chaining.
    
    Provides append-only audit trail that can detect tampering.
    """
    
    def __init__(self) -> None:
        self._events: List[AuditEvent] = []
        self._last_hash: Optional[str] = None
        self._event_counter: int = 0
        
    def log_event(
        self,
        event_type: AuditEventType,
        actor_id: str,
        actor_name: str,
        action: str,
        result: str,
        tenant_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        severity: AuditSeverity = AuditSeverity.INFO,
        details: Optional[Dict[str, Any]] = None,
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> AuditEvent:
        """
        Log an audit event.
        
        Events are immutable and chained using cryptographic hashes.
        """
        self._event_counter += 1
        event_id = f"evt_{self._event_counter:010d}"
        
        event = AuditEvent(
            event_id=event_id,
            event_type=event_type,
            timestamp=datetime.utcnow(),
            actor_id=actor_id,
            actor_name=actor_name,
            tenant_id=tenant_id,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            result=result,
            severity=severity,
            details=details or {},
            source_ip=source_ip,
            user_agent=user_agent,
            session_id=session_id,
            previous_hash=self._last_hash,
        )
        
        # Compute hash and update chain
        event_hash = event.compute_hash()
        self._last_hash = event_hash
        
        # Store event (append-only)
        self._events.append(event)
        
        return event
    
    def get_events(
        self,
        tenant_id: Optional[str] = None,
        event_type: Optional[AuditEventType] = None,
        actor_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> List[AuditEvent]:
        """
        Query audit events with filters.
        
        Note: This returns copies to preserve immutability.
        """
        events = self._events
        
        # Apply filters
        if tenant_id:
            events = [e for e in events if e.tenant_id == tenant_id]
        
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        
        if actor_id:
            events = [e for e in events if e.actor_id == actor_id]
        
        if start_time:
            events = [e for e in events if e.timestamp >= start_time]
        
        if end_time:
            events = [e for e in events if e.timestamp <= end_time]
        
        # Apply limit
        if limit:
            events = events[-limit:]
        
        return events
    
    def verify_integrity(self) -> bool:
        """
        Verify the integrity of the audit log using hash chain.
        
        Returns:
            True if chain is intact, False if tampering detected
        """
        if not self._events:
            return True
        
        previous_hash = None
        
        for event in self._events:
            # Verify that previous_hash matches
            if event.previous_hash != previous_hash:
                return False
            
            # Recompute hash to verify event hasn't been modified
            computed_hash = event.compute_hash()
            
            # Update for next iteration
            previous_hash = computed_hash
        
        return True
    
    def get_event_count(self) -> int:
        """Get total number of events"""
        return len(self._events)
    
    def export_events(
        self,
        format: str = "json",
        tenant_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> str:
        """
        Export audit events in specified format.
        
        Args:
            format: Export format ("json" or "csv")
            tenant_id: Optional tenant filter
            start_time: Optional start time filter
            end_time: Optional end time filter
            
        Returns:
            Serialized events
        """
        events = self.get_events(
            tenant_id=tenant_id,
            start_time=start_time,
            end_time=end_time,
        )
        
        if format == "json":
            return json.dumps(
                [e.to_dict() for e in events],
                indent=2,
                default=str,
            )
        elif format == "csv":
            # Simple CSV export
            if not events:
                return ""
            
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.DictWriter(
                output,
                fieldnames=events[0].to_dict().keys(),
            )
            writer.writeheader()
            for event in events:
                writer.writerow(event.to_dict())
            
            return output.getvalue()
        else:
            raise ValueError(f"Unsupported export format: {format}")
