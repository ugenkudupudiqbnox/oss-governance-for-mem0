"""
Tests for audit logging module
"""

import pytest
from datetime import datetime
from mem0_governance.audit import (
    AuditEvent,
    AuditEventType,
    AuditSeverity,
    AuditLogger,
)


def test_audit_event_creation():
    """Test audit event creation"""
    event = AuditEvent(
        event_id="evt001",
        event_type=AuditEventType.MEMORY_READ,
        timestamp=datetime.utcnow(),
        actor_id="user123",
        actor_name="John Doe",
        tenant_id="tenant1",
        resource_type="memory",
        resource_id="mem456",
        action="read_memory",
        result="success",
        severity=AuditSeverity.INFO,
        details={},
    )
    
    assert event.event_id == "evt001"
    assert event.event_type == AuditEventType.MEMORY_READ
    assert event.actor_id == "user123"


def test_audit_event_hash():
    """Test audit event hash computation"""
    event = AuditEvent(
        event_id="evt001",
        event_type=AuditEventType.MEMORY_READ,
        timestamp=datetime.utcnow(),
        actor_id="user123",
        actor_name="John Doe",
        tenant_id="tenant1",
        resource_type="memory",
        resource_id="mem456",
        action="read_memory",
        result="success",
        severity=AuditSeverity.INFO,
        details={},
    )
    
    hash1 = event.compute_hash()
    hash2 = event.compute_hash()
    
    # Hash should be deterministic
    assert hash1 == hash2
    assert len(hash1) == 64  # SHA-256 produces 64 hex characters


def test_audit_logger_log_event():
    """Test logging an event"""
    logger = AuditLogger()
    
    event = logger.log_event(
        event_type=AuditEventType.MEMORY_READ,
        actor_id="user123",
        actor_name="John Doe",
        action="read_memory",
        result="success",
        tenant_id="tenant1",
        resource_type="memory",
        resource_id="mem456",
    )
    
    assert event.event_id == "evt_0000000001"
    assert event.event_type == AuditEventType.MEMORY_READ


def test_audit_logger_hash_chaining():
    """Test hash chaining in audit log"""
    logger = AuditLogger()
    
    event1 = logger.log_event(
        event_type=AuditEventType.MEMORY_READ,
        actor_id="user123",
        actor_name="John Doe",
        action="read_memory",
        result="success",
    )
    
    event2 = logger.log_event(
        event_type=AuditEventType.MEMORY_UPDATE,
        actor_id="user123",
        actor_name="John Doe",
        action="write_memory",
        result="success",
    )
    
    # First event should have no previous hash
    assert event1.previous_hash is None
    
    # Second event should reference first event's hash
    assert event2.previous_hash is not None
    assert event2.previous_hash == event1.compute_hash()


def test_audit_logger_integrity_verification():
    """Test audit log integrity verification"""
    logger = AuditLogger()
    
    # Log some events
    for i in range(5):
        logger.log_event(
            event_type=AuditEventType.MEMORY_READ,
            actor_id=f"user{i}",
            actor_name=f"User {i}",
            action="read_memory",
            result="success",
        )
    
    # Verify integrity
    assert logger.verify_integrity()


def test_audit_logger_query_by_tenant():
    """Test querying events by tenant"""
    logger = AuditLogger()
    
    logger.log_event(
        event_type=AuditEventType.MEMORY_READ,
        actor_id="user1",
        actor_name="User 1",
        action="read_memory",
        result="success",
        tenant_id="tenant1",
    )
    
    logger.log_event(
        event_type=AuditEventType.MEMORY_READ,
        actor_id="user2",
        actor_name="User 2",
        action="read_memory",
        result="success",
        tenant_id="tenant2",
    )
    
    # Query tenant1 events
    tenant1_events = logger.get_events(tenant_id="tenant1")
    assert len(tenant1_events) == 1
    assert tenant1_events[0].tenant_id == "tenant1"


def test_audit_logger_query_by_event_type():
    """Test querying events by type"""
    logger = AuditLogger()
    
    logger.log_event(
        event_type=AuditEventType.MEMORY_READ,
        actor_id="user1",
        actor_name="User 1",
        action="read_memory",
        result="success",
    )
    
    logger.log_event(
        event_type=AuditEventType.MEMORY_UPDATE,
        actor_id="user1",
        actor_name="User 1",
        action="write_memory",
        result="success",
    )
    
    # Query read events
    read_events = logger.get_events(event_type=AuditEventType.MEMORY_READ)
    assert len(read_events) == 1
    assert read_events[0].event_type == AuditEventType.MEMORY_READ


def test_audit_logger_query_by_actor():
    """Test querying events by actor"""
    logger = AuditLogger()
    
    logger.log_event(
        event_type=AuditEventType.MEMORY_READ,
        actor_id="user1",
        actor_name="User 1",
        action="read_memory",
        result="success",
    )
    
    logger.log_event(
        event_type=AuditEventType.MEMORY_READ,
        actor_id="user2",
        actor_name="User 2",
        action="read_memory",
        result="success",
    )
    
    # Query user1 events
    user1_events = logger.get_events(actor_id="user1")
    assert len(user1_events) == 1
    assert user1_events[0].actor_id == "user1"


def test_audit_logger_export_json():
    """Test exporting events as JSON"""
    logger = AuditLogger()
    
    logger.log_event(
        event_type=AuditEventType.MEMORY_READ,
        actor_id="user1",
        actor_name="User 1",
        action="read_memory",
        result="success",
    )
    
    json_export = logger.export_events(format="json")
    assert isinstance(json_export, str)
    assert "evt_0000000001" in json_export


def test_audit_logger_export_csv():
    """Test exporting events as CSV"""
    logger = AuditLogger()
    
    logger.log_event(
        event_type=AuditEventType.MEMORY_READ,
        actor_id="user1",
        actor_name="User 1",
        action="read_memory",
        result="success",
    )
    
    csv_export = logger.export_events(format="csv")
    assert isinstance(csv_export, str)
    assert "event_id" in csv_export  # Header
    assert "evt_0000000001" in csv_export


def test_audit_logger_event_count():
    """Test getting event count"""
    logger = AuditLogger()
    
    assert logger.get_event_count() == 0
    
    logger.log_event(
        event_type=AuditEventType.MEMORY_READ,
        actor_id="user1",
        actor_name="User 1",
        action="read_memory",
        result="success",
    )
    
    assert logger.get_event_count() == 1


def test_security_event_logging():
    """Test logging security events with high severity"""
    logger = AuditLogger()
    
    event = logger.log_event(
        event_type=AuditEventType.SECURITY_VIOLATION,
        actor_id="user123",
        actor_name="Suspicious User",
        action="multiple_failed_logins",
        result="blocked",
        severity=AuditSeverity.CRITICAL,
        details={"attempts": 10},
    )
    
    assert event.severity == AuditSeverity.CRITICAL
    assert event.event_type == AuditEventType.SECURITY_VIOLATION
