### Added
- GitHub Dependabot configuration for `pip`, `docker`, and `github-actions` ecosystems with weekly group updates.
- Trust-On-First-Use (TOFU) host key verification for SSH connections to the VPS gateway.
- Automated daily database backup utility.

### Changed

### Fixed
- Potential command injection vulnerability in iptables rule cleanup via remote shell execution.
- Memory leak in in-memory fallback rate limiting algorithm.
- Reset of VPS host key fingerprint upon host or key configuration changes.
