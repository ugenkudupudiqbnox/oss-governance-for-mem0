# Access Control Policy Tests
# Run with: opa test . -v

package mem0.access

# =============================================================================
# DENY BY DEFAULT TESTS
# =============================================================================

test_deny_by_default if {
    not allow with input as {}
}

test_deny_without_user if {
    not allow with input as {
        "operation": "mem0_search"
    }
}

test_deny_without_operation if {
    not allow with input as {
        "user": {"id": "user123", "role": "user"}
    }
}

# =============================================================================
# AUTHENTICATION TESTS
# =============================================================================

test_authenticated_with_valid_id if {
    is_authenticated with input as {
        "user": {"id": "user123"}
    }
}

test_not_authenticated_with_empty_id if {
    not is_authenticated with input as {
        "user": {"id": ""}
    }
}

test_not_authenticated_without_user if {
    not is_authenticated with input as {}
}

# =============================================================================
# ROLE VALIDATION TESTS
# =============================================================================

test_valid_role_admin if {
    has_valid_role with input as {
        "user": {"role": "admin"}
    }
}

test_valid_role_user if {
    has_valid_role with input as {
        "user": {"role": "user"}
    }
}

test_invalid_role if {
    not has_valid_role with input as {
        "user": {"role": "invalid_role"}
    }
}

# =============================================================================
# OPERATION AUTHORIZATION TESTS
# =============================================================================

test_admin_can_search if {
    operation_is_authorized with input as {
        "user": {"role": "admin"},
        "operation": "mem0_search"
    }
}

test_admin_can_delete if {
    operation_is_authorized with input as {
        "user": {"role": "admin"},
        "operation": "mem0_delete"
    }
}

test_user_can_search if {
    operation_is_authorized with input as {
        "user": {"role": "user"},
        "operation": "mem0_search"
    }
}

test_user_cannot_delete if {
    not operation_is_authorized with input as {
        "user": {"role": "user"},
        "operation": "mem0_delete"
    }
}

test_viewer_can_search if {
    operation_is_authorized with input as {
        "user": {"role": "viewer"},
        "operation": "mem0_search"
    }
}

test_viewer_cannot_add if {
    not operation_is_authorized with input as {
        "user": {"role": "viewer"},
        "operation": "mem0_add"
    }
}

test_auditor_can_view_audit if {
    operation_is_authorized with input as {
        "user": {"role": "auditor"},
        "operation": "audit_view"
    }
}

test_auditor_cannot_search_mem0 if {
    not operation_is_authorized with input as {
        "user": {"role": "auditor"},
        "operation": "mem0_search"
    }
}

# =============================================================================
# DATA CLASSIFICATION TESTS
# =============================================================================

test_admin_can_access_restricted if {
    resource_access_allowed with input as {
        "user": {"role": "admin"},
        "resource": {"classification": "restricted"}
    }
}

test_analyst_cannot_access_restricted if {
    not resource_access_allowed with input as {
        "user": {"role": "analyst"},
        "resource": {"classification": "restricted"}
    }
}

test_analyst_can_access_confidential if {
    resource_access_allowed with input as {
        "user": {"role": "analyst"},
        "resource": {"classification": "confidential"}
    }
}

test_user_can_access_internal if {
    resource_access_allowed with input as {
        "user": {"role": "user"},
        "resource": {"classification": "internal"}
    }
}

test_user_cannot_access_confidential if {
    not resource_access_allowed with input as {
        "user": {"role": "user"},
        "resource": {"classification": "confidential"}
    }
}

test_viewer_can_access_public if {
    resource_access_allowed with input as {
        "user": {"role": "viewer"},
        "resource": {"classification": "public"}
    }
}

test_no_classification_defaults_to_internal if {
    resource_access_allowed with input as {
        "user": {"role": "user"},
        "resource": {"type": "memory"}
    }
}

# =============================================================================
# FULL ACCESS TESTS
# =============================================================================

test_admin_full_access if {
    allow with input as {
        "user": {"id": "admin1", "role": "admin"},
        "operation": "mem0_search",
        "resource": {"classification": "restricted"},
        "context": {}
    }
}

test_analyst_search_internal if {
    allow with input as {
        "user": {"id": "analyst1", "role": "analyst"},
        "operation": "mem0_search",
        "resource": {"classification": "internal"},
        "context": {}
    }
}

test_user_search_public if {
    allow with input as {
        "user": {"id": "user1", "role": "user"},
        "operation": "mem0_search",
        "resource": {"classification": "public"},
        "context": {}
    }
}

test_viewer_cannot_add if {
    not allow with input as {
        "user": {"id": "viewer1", "role": "viewer"},
        "operation": "mem0_add",
        "resource": {"classification": "public"},
        "context": {}
    }
}

test_user_cannot_access_restricted if {
    not allow with input as {
        "user": {"id": "user1", "role": "user"},
        "operation": "mem0_search",
        "resource": {"classification": "restricted"},
        "context": {}
    }
}

# =============================================================================
# EMERGENCY ACCESS TESTS
# =============================================================================

test_emergency_access_with_admin if {
    allow with input as {
        "user": {"id": "admin1", "role": "admin"},
        "operation": "mem0_search",
        "emergency_access": true,
        "emergency_ticket_id": "INC-12345",
        "context": {}
    }
}

test_emergency_access_requires_ticket if {
    not allow with input as {
        "user": {"id": "admin1", "role": "admin"},
        "operation": "mem0_search",
        "emergency_access": true,
        "context": {}
    }
}

test_emergency_access_requires_elevated_role if {
    not allow with input as {
        "user": {"id": "user1", "role": "user"},
        "operation": "mem0_search",
        "emergency_access": true,
        "emergency_ticket_id": "INC-12345",
        "context": {}
    }
}

# =============================================================================
# ADMIN OVERRIDE TESTS
# =============================================================================

test_admin_override if {
    allow with input as {
        "user": {"id": "admin1", "role": "admin"},
        "operation": "mem0_search",
        "override_requested": true,
        "context": {}
    }
}

test_non_admin_cannot_override if {
    not allow with input as {
        "user": {"id": "user1", "role": "user"},
        "operation": "mem0_delete",
        "override_requested": true,
        "context": {}
    }
}

# =============================================================================
# DELETE OPERATION TESTS
# =============================================================================

test_admin_can_delete_any_resource if {
    delete_authorized with input as {
        "user": {"id": "admin1", "role": "admin"},
        "operation": "mem0_delete",
        "resource": {"owner_id": "other_user"}
    }
}

test_analyst_can_delete_own_resource if {
    delete_authorized with input as {
        "user": {"id": "analyst1", "role": "analyst"},
        "operation": "mem0_delete",
        "resource": {"owner_id": "analyst1"}
    }
}

test_analyst_cannot_delete_others_resource if {
    not delete_authorized with input as {
        "user": {"id": "analyst1", "role": "analyst"},
        "operation": "mem0_delete",
        "resource": {"owner_id": "other_user"}
    }
}

test_user_cannot_delete if {
    not delete_authorized with input as {
        "user": {"id": "user1", "role": "user"},
        "operation": "mem0_delete",
        "resource": {"owner_id": "user1"}
    }
}

# =============================================================================
# DENY REASON TESTS
# =============================================================================

test_deny_reason_no_auth if {
    reason := deny_reason with input as {
        "user": {"id": ""},
        "operation": "mem0_search"
    }
    startswith(reason, "Authentication failed")
}

test_deny_reason_invalid_role if {
    reason := deny_reason with input as {
        "user": {"id": "user1", "role": "invalid"},
        "operation": "mem0_search"
    }
    startswith(reason, "Authorization failed: User role")
}

test_deny_reason_unauthorized_operation if {
    reason := deny_reason with input as {
        "user": {"id": "user1", "role": "viewer"},
        "operation": "mem0_delete",
        "context": {}
    }
    contains(reason, "Operation")
}

# =============================================================================
# AUDIT CONTEXT TESTS
# =============================================================================

test_audit_context_contains_user_id if {
    context := audit_context with input as {
        "user": {"id": "user123", "role": "user"},
        "operation": "mem0_search"
    }
    context.user_id == "user123"
}

test_audit_context_contains_decision if {
    context := audit_context with input as {
        "user": {"id": "admin1", "role": "admin"},
        "operation": "mem0_search",
        "context": {}
    }
    context.decision == true
}

test_audit_context_contains_policy_version if {
    context := audit_context with input as {
        "user": {"id": "user1", "role": "user"},
        "operation": "mem0_search"
    }
    context.policy_version == "1.0.0"
}
