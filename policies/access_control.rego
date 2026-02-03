# Governance Pack for Mem0 - Access Control Policy
# Written in OPA Rego (Open Policy Agent)
#
# This policy implements deny-by-default access control for Mem0 operations.
# All access is denied unless explicitly allowed by these rules.
#
# Policy Version: 1.0.0
# Last Updated: 2026-02-03

package mem0.access

import future.keywords.if
import future.keywords.in

# =============================================================================
# DEFAULT DENY
# =============================================================================

# By default, all access is denied
default allow = false

# Default reasons for denial
default deny_reason = "Access denied by default policy"

# =============================================================================
# MAIN AUTHORIZATION RULE
# =============================================================================

# Allow access if ALL of the following conditions are met
allow if {
    is_authenticated
    has_valid_role
    operation_is_authorized
    resource_access_allowed
    within_allowed_context
}

# Capture the reason for allowing access
allow_reason = reason if {
    allow
    reason := "Access granted: All security checks passed"
}

# Capture the reason for denying access
deny_reason = reason if {
    not is_authenticated
    reason := "Authentication failed: User not authenticated"
} else = reason if {
    not has_valid_role
    reason := "Authorization failed: User role is invalid or missing"
} else = reason if {
    not operation_is_authorized
    reason := sprintf("Authorization failed: Operation '%s' not allowed for role '%s'", [input.operation, input.user.role])
} else = reason if {
    not resource_access_allowed
    reason := sprintf("Authorization failed: Access to '%s' classification denied", [input.resource.classification])
} else = reason if {
    not within_allowed_context
    reason := "Authorization failed: Request context does not meet security requirements"
}

# =============================================================================
# AUTHENTICATION
# =============================================================================

# User must be authenticated with a valid ID
is_authenticated if {
    input.user.id
    input.user.id != ""
    count(input.user.id) > 0
}

# =============================================================================
# AUTHORIZATION - ROLE VALIDATION
# =============================================================================

# Valid roles in the system
valid_roles := {"admin", "security_officer", "analyst", "user", "viewer", "auditor"}

# User must have a valid role
has_valid_role if {
    input.user.role
    input.user.role in valid_roles
}

# =============================================================================
# AUTHORIZATION - OPERATION PERMISSIONS
# =============================================================================

# Define which roles can perform which operations
role_permissions := {
    "admin": {
        "mem0_search",
        "mem0_add",
        "mem0_update", 
        "mem0_delete",
        "mem0_get",
        "policy_view",
        "policy_update",
        "user_manage",
        "audit_view"
    },
    "security_officer": {
        "mem0_search",
        "mem0_add",
        "mem0_update",
        "mem0_get",
        "policy_view",
        "audit_view",
        "user_view"
    },
    "analyst": {
        "mem0_search",
        "mem0_add",
        "mem0_update",
        "mem0_get"
    },
    "user": {
        "mem0_search",
        "mem0_add",
        "mem0_get"
    },
    "viewer": {
        "mem0_search",
        "mem0_get"
    },
    "auditor": {
        "audit_view",
        "policy_view"
    }
}

# Check if the operation is authorized for the user's role
operation_is_authorized if {
    input.operation
    input.user.role
    permissions := role_permissions[input.user.role]
    input.operation in permissions
}

# =============================================================================
# AUTHORIZATION - DATA CLASSIFICATION
# =============================================================================

# Define which roles can access which data classifications
classification_access := {
    "public": {"admin", "security_officer", "analyst", "user", "viewer", "auditor"},
    "internal": {"admin", "security_officer", "analyst", "user"},
    "confidential": {"admin", "security_officer", "analyst"},
    "restricted": {"admin", "security_officer"}
}

# Check if user's role can access the resource's classification
resource_access_allowed if {
    # If no resource or classification specified, allow (will be checked elsewhere)
    not input.resource
}

resource_access_allowed if {
    # If resource exists but no classification, default to internal
    input.resource
    not input.resource.classification
    input.user.role in classification_access["internal"]
}

resource_access_allowed if {
    # Check classification access
    input.resource.classification
    allowed_roles := classification_access[input.resource.classification]
    input.user.role in allowed_roles
}

# =============================================================================
# CONTEXT-BASED CONTROLS
# =============================================================================

# Check if the request context meets security requirements
within_allowed_context if {
    valid_source_ip
    valid_request_time
    # Add more context checks as needed
}

# Validate source IP (example - modify for your environment)
valid_source_ip if {
    # If no IP context provided, allow (will be logged)
    not input.context.ip
}

valid_source_ip if {
    # Allow from private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    input.context.ip
    # This is a simplified check - use proper IP validation in production
    true  # Replace with actual IP range validation
}

# Time-based access control
valid_request_time if {
    # If no time context provided, allow
    not input.context.time
}

valid_request_time if {
    # Allow 24/7 for now - uncomment to restrict to business hours
    input.context.time
    true
    
    # Uncomment for business hours only (8 AM - 6 PM, Mon-Fri):
    # time_obj := time.parse_rfc3339_ns(input.context.time)
    # hour := time.clock(time_obj)[0]
    # weekday := time.weekday(time_obj)
    # hour >= 8
    # hour < 18
    # weekday != "Saturday"
    # weekday != "Sunday"
}

# =============================================================================
# SPECIAL RULES
# =============================================================================

# Admins can bypass some restrictions (but still logged)
admin_override if {
    input.user.role == "admin"
    input.override_requested == true
}

# Emergency access (requires special flag and is heavily audited)
emergency_access if {
    input.emergency_access == true
    input.emergency_ticket_id
    input.user.role in {"admin", "security_officer"}
}

# Allow with admin override
allow if {
    admin_override
}

# Allow with emergency access
allow if {
    emergency_access
}

# =============================================================================
# RESOURCE-SPECIFIC RULES
# =============================================================================

# Users can only access their own memories unless they have elevated privileges
own_resource_only if {
    input.resource.owner_id == input.user.id
}

own_resource_only if {
    input.user.role in {"admin", "security_officer"}
}

# For delete operations, additional checks
delete_authorized if {
    input.operation == "mem0_delete"
    own_resource_only
    input.user.role in {"admin", "analyst"}
}

# If operation is delete, apply additional rule
allow if {
    delete_authorized
    has_valid_role
    is_authenticated
    within_allowed_context
}

# =============================================================================
# AUDIT HELPER FUNCTIONS
# =============================================================================

# Generate audit context for logging
audit_context = context if {
    context := {
        "user_id": input.user.id,
        "user_role": input.user.role,
        "operation": input.operation,
        "resource_type": object.get(input.resource, "type", "unknown"),
        "resource_id": object.get(input.resource, "id", "unknown"),
        "classification": object.get(input.resource, "classification", "unknown"),
        "decision": allow,
        "reason": allow_reason if allow else deny_reason,
        "policy_version": "1.0.0"
    }
}

# =============================================================================
# RATE LIMITING (Example - requires external data)
# =============================================================================

# Example rate limit check (would need integration with rate limit service)
# within_rate_limit if {
#     input.user.id
#     # In production, check against rate limit service or cache
#     # For now, always return true
#     true
# }

# =============================================================================
# DATA VALIDATION
# =============================================================================

# Validate that required input fields are present
valid_input if {
    input.user
    input.user.id
    input.user.role
    input.operation
}

# Input validation failure reason
invalid_input_reason = reason if {
    not input.user
    reason := "Invalid input: 'user' object is required"
} else = reason if {
    not input.user.id
    reason := "Invalid input: 'user.id' is required"
} else = reason if {
    not input.user.role
    reason := "Invalid input: 'user.role' is required"
} else = reason if {
    not input.operation
    reason := "Invalid input: 'operation' is required"
}

# =============================================================================
# TESTING HELPER RULES
# =============================================================================

# Helper to test individual conditions (useful for debugging)
test_results = results if {
    results := {
        "is_authenticated": is_authenticated,
        "has_valid_role": has_valid_role,
        "operation_is_authorized": operation_is_authorized,
        "resource_access_allowed": resource_access_allowed,
        "within_allowed_context": within_allowed_context,
        "final_decision": allow
    }
}
