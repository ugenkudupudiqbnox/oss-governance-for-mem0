#!/bin/bash
# Policy Validation Script
# Tests the OPA policy syntax and runs unit tests

set -e

echo "=================================="
echo "Governance Pack Policy Validation"
echo "=================================="
echo ""

# Check if OPA is installed
if ! command -v opa &> /dev/null; then
    echo "❌ OPA is not installed"
    echo ""
    echo "Please install OPA first:"
    echo "  macOS:   brew install opa"
    echo "  Linux:   curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64"
    echo "  Windows: Download from https://www.openpolicyagent.org/downloads/"
    echo ""
    exit 1
fi

echo "✓ OPA is installed: $(opa version)"
echo ""

# Navigate to policies directory
cd "$(dirname "$0")"

echo "Step 1: Checking policy syntax..."
if opa check access_control.rego; then
    echo "✓ Policy syntax is valid"
else
    echo "❌ Policy syntax check failed"
    exit 1
fi
echo ""

echo "Step 2: Running unit tests..."
if opa test . -v; then
    echo "✓ All tests passed"
else
    echo "❌ Some tests failed"
    exit 1
fi
echo ""

echo "Step 3: Testing example inputs..."

echo "  Testing admin access (should allow)..."
RESULT=$(opa eval -d access_control.rego -i example_admin_access.json "data.mem0.access.allow" --format raw)
if [ "$RESULT" = "true" ]; then
    echo "  ✓ Admin access allowed as expected"
else
    echo "  ❌ Admin access denied (unexpected)"
    exit 1
fi

echo "  Testing user access to restricted data (should deny)..."
RESULT=$(opa eval -d access_control.rego -i example_user_denied.json "data.mem0.access.allow" --format raw)
if [ "$RESULT" = "false" ]; then
    echo "  ✓ User access denied as expected"
else
    echo "  ❌ User access allowed (unexpected)"
    exit 1
fi

echo ""
echo "Step 4: Checking deny reasons..."
REASON=$(opa eval -d access_control.rego -i example_user_denied.json "data.mem0.access.deny_reason" --format raw)
echo "  Deny reason: $REASON"
if [ -n "$REASON" ]; then
    echo "  ✓ Deny reason provided"
else
    echo "  ❌ No deny reason provided"
    exit 1
fi

echo ""
echo "=================================="
echo "✅ All validation checks passed!"
echo "=================================="
echo ""
echo "Next steps:"
echo "  1. Review the policy in access_control.rego"
echo "  2. Customize roles and permissions for your organization"
echo "  3. Add organization-specific rules"
echo "  4. Run 'opa test . -v' after making changes"
echo "  5. Deploy the policy to your OPA server"
echo ""
