### Added
- CI: Docker image workflow now also builds and publishes the `dev` tag on pushes to the `dev` branch.

### Changed
- Docker: Increased `HEALTHCHECK` `start-period` from 10s to 30s to accommodate slow Python startup with heavy dependencies (webauthn, redis, paramiko).

### Fixed
