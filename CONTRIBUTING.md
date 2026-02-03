# Contributing to Governance Pack for Mem0

Thank you for your interest in contributing! This project helps organizations implement enterprise-grade governance for Mem0 integrations.

## 🎯 Contribution Areas

We welcome contributions in these areas:

### Documentation
- Improve architecture diagrams
- Add integration examples
- Expand threat model
- Add tutorials and guides
- Fix typos and clarify content

### Compliance
- Update control mappings for new framework versions
- Add mappings for additional frameworks (HIPAA, GDPR, etc.)
- Contribute compliance queries
- Share audit report templates

### Policy-as-Code
- Add new policy patterns
- Improve existing policies
- Add policy tests
- Share real-world policy examples

### Audit Schema
- Optimize database performance
- Add new query examples
- Support additional databases
- Improve schema documentation

## 🚀 Getting Started

1. **Fork the repository**
2. **Clone your fork**
3. **Create a feature branch**: `git checkout -b feature/your-feature-name`
4. **Make your changes**
5. **Test your changes** (see below)
6. **Commit with clear messages**: `git commit -m "Add: description of change"`
7. **Push to your fork**: `git push origin feature/your-feature-name`
8. **Open a Pull Request**

## ✅ Testing Changes

### For Policy Changes

```bash
cd policies/

# Validate syntax
opa check access_control.rego

# Run tests
opa test . -v

# Test with example inputs
./validate_policy.sh
```

### For SQL Schema Changes

```bash
# Test on a development database
psql -U test_user -d test_db -f schemas/audit_log_schema.sql

# Run example queries
psql -U test_user -d test_db -f schemas/query_examples.sql
```

### For Documentation

- Check for broken links
- Verify code examples work
- Ensure formatting is consistent
- Test commands if provided

## 📝 Commit Message Guidelines

Use clear, descriptive commit messages:

- `Add: new feature or file`
- `Update: modify existing feature`
- `Fix: bug fix`
- `Docs: documentation changes`
- `Test: add or update tests`
- `Refactor: code refactoring`

Examples:
- `Add: HIPAA compliance mapping`
- `Fix: SQL syntax in SOC2 query example`
- `Update: policy for time-based access control`
- `Docs: improve quick start guide`

## 🔍 Pull Request Guidelines

### PR Title

Use a clear, descriptive title:
- `Add GDPR compliance mapping`
- `Fix audit log query performance issue`
- `Update policy tests for new roles`

### PR Description

Include:
1. **What**: What changes did you make?
2. **Why**: Why are these changes needed?
3. **How**: How do the changes work?
4. **Testing**: How did you test the changes?
5. **Impact**: What impact do the changes have?

### Example PR Description

```markdown
## What
Add HIPAA compliance control mapping document.

## Why
Many healthcare organizations need HIPAA compliance for handling PHI.

## How
- Created compliance/HIPAA_MAPPING.md
- Mapped controls to governance pack features
- Added HIPAA-specific audit queries
- Updated compliance/README.md

## Testing
- Verified all links work
- Tested SQL queries on sample data
- Reviewed against latest HIPAA Security Rule

## Impact
- Helps healthcare orgs meet HIPAA requirements
- No breaking changes
- Adds new optional documentation
```

## 🔒 Security Considerations

When contributing, please:

1. **Never commit secrets** - No API keys, passwords, or credentials
2. **Consider threat model** - Ensure changes don't introduce vulnerabilities
3. **Test security controls** - Verify access controls work as intended
4. **Document security implications** - Explain security impact of changes
5. **Report vulnerabilities privately** - Email security@ instead of opening issues

## 📋 Code Style

### OPA Rego Policies

- Use meaningful variable names
- Add comments for complex rules
- Include package documentation
- Write tests for all rules
- Follow [OPA best practices](https://www.openpolicyagent.org/docs/latest/policy-performance/)

```rego
# Good
allow if {
    is_authenticated
    has_permission
    within_business_hours
}

# Less clear
allow if {
    check1
    check2
    check3
}
```

### SQL

- Use consistent formatting
- Add comments for complex queries
- Use meaningful aliases
- Include EXPLAIN plans for performance-critical queries

```sql
-- Good
SELECT 
    user_id,
    COUNT(*) as access_count,
    MAX(timestamp) as last_access
FROM audit_logs
WHERE timestamp >= NOW() - INTERVAL '30 days'
GROUP BY user_id;

-- Less clear
SELECT user_id,COUNT(*),MAX(timestamp) FROM audit_logs WHERE timestamp>=NOW()-INTERVAL '30 days' GROUP BY user_id;
```

### Markdown

- Use headers consistently
- Include code blocks with language tags
- Add tables of contents for long documents
- Use relative links for internal docs

## 🎨 Documentation Standards

### Structure

- **Overview** at the top
- **Quick examples** early
- **Detailed explanations** later
- **References** at the end

### Tone

- Clear and professional
- Assume reader has context about Mem0
- Explain security and compliance terms
- Include "why" not just "how"

### Code Examples

- Include complete, working examples
- Add comments explaining key parts
- Show both good and bad patterns
- Provide multiple languages when relevant

## 🐛 Reporting Bugs

Open an issue with:

1. **Clear title**: "Audit query fails with large datasets"
2. **Description**: What's wrong?
3. **Steps to reproduce**: How to see the bug
4. **Expected behavior**: What should happen
5. **Actual behavior**: What actually happens
6. **Environment**: Version, database, OS, etc.

## 💡 Suggesting Features

Open an issue or discussion with:

1. **Problem**: What problem does this solve?
2. **Proposed solution**: Your suggested approach
3. **Alternatives**: Other options considered
4. **Use case**: Real-world scenario
5. **Impact**: Who benefits and how

## 🎓 Learning Resources

### Before Contributing

Familiarize yourself with:
- [Mem0 Documentation](https://docs.mem0.ai/)
- [OPA/Rego Language](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [PostgreSQL](https://www.postgresql.org/docs/)
- [SOC 2](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report.html)
- [ISO 27001](https://www.iso.org/standard/27001)

## 📜 License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0, the same license as this project.

## 🤝 Code of Conduct

### Our Pledge

We pledge to make participation in this project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity and expression, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards

**Positive behavior:**
- Using welcoming and inclusive language
- Being respectful of differing viewpoints
- Gracefully accepting constructive criticism
- Focusing on what's best for the community
- Showing empathy towards others

**Unacceptable behavior:**
- Trolling, insulting/derogatory comments, and personal or political attacks
- Public or private harassment
- Publishing others' private information without permission
- Other conduct which could reasonably be considered inappropriate

### Enforcement

Violations may result in:
1. Warning
2. Temporary ban
3. Permanent ban

Report violations to project maintainers.

## ✨ Recognition

Contributors are recognized in:
- README acknowledgments
- Release notes
- Git commit history

Significant contributors may be invited to become maintainers.

## 📧 Contact

- **General questions**: Open a GitHub Discussion
- **Bug reports**: Open a GitHub Issue
- **Security issues**: Email security@ (not public issues)
- **Maintainers**: See README for list

## 🙏 Thank You!

Every contribution helps make this project more useful for organizations implementing governance for Mem0. Whether it's fixing a typo or adding a major feature, we appreciate your effort!

Happy contributing! 🎉
