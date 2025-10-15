# Security Policy

## Supported Versions

We actively support the following versions of KMIM with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in KMIM, please follow responsible disclosure practices:

### For Security Vulnerabilities

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please:

1. **Email us privately** at [security@yourdomain.com] with:
   - A detailed description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact assessment
   - Your contact information

2. **Wait for our response** before disclosing publicly
   - We aim to respond within 48 hours
   - We'll work with you to understand and fix the issue
   - We'll coordinate public disclosure timing

3. **Give us reasonable time** to fix the issue before public disclosure
   - Typically 90 days for critical vulnerabilities
   - We may request extended time for complex issues

### For Security-Related Improvements

For general security improvements or questions that don't involve active vulnerabilities, you can:
- Create a GitHub issue using the security template
- Start a discussion in GitHub Discussions
- Submit a pull request with improvements

## Security Considerations

### KMIM's Security Model

KMIM requires root privileges to:
- Load eBPF programs into the kernel
- Access `/proc/modules` and `/proc/kallsyms`
- Monitor kernel module activities

This is inherent to its functionality but comes with security implications:

1. **Privilege Escalation**: Always run KMIM with the minimum necessary privileges
2. **eBPF Safety**: Our eBPF programs are verified by the kernel, but bugs could potentially cause issues
3. **Data Sensitivity**: KMIM accesses kernel symbols and module information

### Best Practices for Users

1. **Verify Installation**:
   ```bash
   # Verify the package integrity
   pip install kmim --verify
   ```

2. **Run with Minimal Privileges**:
   ```bash
   # Use sudo only when necessary
   sudo python -m cli.kmim scan
   ```

3. **Secure Your Baselines**:
   - Store baseline files in secure locations
   - Use appropriate file permissions (600 or 640)
   - Consider encrypting sensitive baseline data

4. **Regular Updates**:
   - Keep KMIM updated to the latest version
   - Monitor our security advisories
   - Update dependencies regularly

### Known Security Considerations

1. **Root Requirement**: KMIM requires root privileges for eBPF operations
2. **Kernel Interaction**: Direct interaction with kernel through eBPF and proc filesystem
3. **File Permissions**: Baseline files may contain sensitive system information

## Security Testing

We perform the following security tests:

- Static code analysis with bandit
- Dependency vulnerability scanning
- eBPF program verification
- Privilege escalation testing
- Input validation testing

## Acknowledgments

We appreciate security researchers and users who responsibly disclose vulnerabilities. Contributors who follow responsible disclosure will be:

- Credited in our security advisories (with permission)
- Acknowledged in our changelog
- Invited to test fixes before public release

## Contact

- **Security Email**: security@yourdomain.com
- **General Contact**: [your-email@domain.com]
- **GitHub Issues**: For non-security issues only

---

**Note**: Replace email addresses and contact information with your actual details before publishing.
