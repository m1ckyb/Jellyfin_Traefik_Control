# Changelog

All notable changes to this project will be documented in this file.

## [0.3.1] - 2026-08-05

### Added
- CI: Docker image workflow now also builds and publishes the `dev` tag on pushes to the `dev` branch.

### Changed
- Docker: Increased `HEALTHCHECK` `start-period` from 10s to 30s to accommodate slow Python startup with heavy dependencies (webauthn, redis, paramiko).

### Fixed
- Docker: Fixed `HEALTHCHECK` using `localhost` which resolves to `::1` (IPv6) in Alpine, causing `wget` to get "Connection refused" despite the app running. Changed to explicit `127.0.0.1`.

## [0.3.0] - 2026-08-05

### Added
- GitHub Dependabot configuration for `pip`, `docker`, and `github-actions` ecosystems with weekly group updates.
- Trust-On-First-Use (TOFU) host key verification for SSH connections to the VPS gateway.
- Automated daily database backup utility.

### Fixed
- Potential command injection vulnerability in iptables rule cleanup via remote shell execution.
- Memory leak in in-memory fallback rate limiting algorithm.
- Reset of VPS host key fingerprint upon host or key configuration changes.

## [0.2.0] - 2026-07-19

### Security
- Authentication: Added whitelist IP check on `/api/settings` and `/api/settings/restore` endpoints.
- Authentication: Added Redis-backed rate limiting on `/auth/login/2fa` (5 attempts/5 min), `/auth/register/begin`, and `/auth/login/begin` (10 per minute per IP).
- Authentication: Added password complexity requirements (upper, lower, number, special character).
- Authentication: Added re-authentication requirement (password) before disabling 2FA.
- Authentication: Removed plaintext password logging from `/api/users/<username>/reset-password`.
- Config: Removed `chmod 777` from entrypoint; secrets and database now use `chmod 600`/`chmod 700`.
- Config: Secret key file created with restrictive permissions (`0o600`).
- Session: Enabled `HttpOnly`, `SameSite=Lax`, and `Secure` (when not debug) cookie flags.
- Session: Set `PERMANENT_SESSION_LIFETIME` to 24 hours.
- SSH: Changed host key verification from `AutoAddPolicy` to `WarningPolicy` with system known_hosts fallback.
- UniFi: Made TLS verification configurable via `UNIFI_VERIFY_SSL` setting.
- Replaced `random` module with `secrets` for all random generation.
- Added security headers: `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`.

### Changed
- Database: Enabled WAL journal mode for concurrent read/write performance.
- Database: Added connection timeouts, busy timeouts, and `check_same_thread=False` for SQLite.
- Database: Enforced foreign keys via `PRAGMA foreign_keys = ON` on every connection.
- Database: Wrapped all migrations in `BEGIN IMMEDIATE` / `COMMIT` transactions with rollback on failure.
- Database: Added migration 11 to initialize `ENFORCE_2FA` setting default.
- Redis: Added connection pooling with automatic config-change detection, `retry_on_timeout`, and explicit timeouts.
- Cloudflare: Added configurable request timeout (15s default) to `cf_request()`.
- Threading: Added `RLock` around `turn_on_service`, `turn_off_service`, and `rotate_firewall_port` to prevent race conditions.
- Threading: Added `Lock` around all shared caches (`UNIFI_STATUS_CACHE`, `HEALTH_STATUS_CACHE`, `_public_ip_cache`).
- Graceful Shutdown: Added signal handler for `SIGTERM`/`SIGINT` that sets a shutdown event; all background loops now exit cleanly.
- Networking: Added public IP caching (5-minute TTL) with lock-based thread safety.
- Logging: Replaced all bare `except:` clauses across `main.py`, `routing.py`, and `mqtt_handler.py` with specific exception types.
- Logging: Added structured logging module (`logging_config.py`) with `RotatingFileHandler`, request ID tracking, and `X-Request-ID` response header.
- Monitoring: Added `/healthz` endpoint (unauthenticated) returning database, Redis, and MQTT component health with HTTP 200/503.

### DevOps
- CI: Added GitHub Actions workflow (`ci.yml`) with ruff linting, bandit security scanning, and Docker build verification.
- Docker: Added `HEALTHCHECK` instruction to Dockerfile (30s interval, 5s timeout, 10s start period).
- Docker: Updated `.dockerignore` to exclude sensitive files (AUDIT/, SECURITY/, config.db, .secret_key, app.log, .env.*).
- Logging: Replaced truncating log file with `RotatingFileHandler` (10MB max, 5 backups).
- Gunicorn: Configured with 4 threads (`gthread` worker class), 120s timeout, 30s graceful shutdown, 5s keep-alive.

### Testing
- Added 88 unit and integration tests across `test_auth.py`, `test_settings.py`, and `test_services.py`.
- Tests cover: login/2FA/recovery, password complexity, CSRF bypass, settings whitelist enforcement, service CRUD/enable/disable, and health check endpoint.

### Fixed
- Security: Added username enumeration prevention on `/auth/login/begin` (generic error messages).
- Security: Increased recovery code entropy from 40-bit to 64-bit (`secrets.token_hex(8)`).
- Frontend: Replaced `innerHTML` in diagnostics modal with safe DOM parsing to prevent XSS.
- DevOps: Added placeholder values to `.env.example` to prevent accidental credential use.

## [0.1.2] - 2026-05-17

### Added
- MQTT: Added support for rotating service URLs from Home Assistant via a new "Rotate URL" button entity. (Note: Subdomain rotation now preserves the current firewall port).
- MQTT: Added global MQTT buttons for Home Assistant: "Rotate Firewall Port", "Turn All Services ON", and "Turn All Services OFF".
- Settings UI: Added a "Test Connection" button for UniFi integration to validate credentials.

### Changed
- Settings UI: Reorganized Firewall Controller section to group action buttons at the bottom for better clarity.
- Dependencies: Updated `redis`, `requests`, `gunicorn`, `Flask-WTF`, and `paramiko` to newer versions in `requirements.txt`.

### Fixed
- UniFi: Improved API resilience by implementing robust retry logic for rate limits (429 errors) and optimized URL rotation to eliminate redundant controller requests.
- MQTT: Fixed a bug where global MQTT commands (Rotate Port, All On/Off) were ignored due to a topic length check.
- MQTT: Refactored URL rotation to feel more atomic and suppressed redundant "Shutdown/Enabling" banners during the rotation process.

## [0.1.1] - 2026-05-16

### Added
- Settings UI: Added a "Test Connection" button for UniFi integration to validate credentials.

### Changed
- Settings UI: Reorganized Firewall Controller section to group action buttons at the bottom for better clarity.
- Settings UI: Cleaned up redundant dividers and extra whitespace for a more consistent visual hierarchy.

### Fixed
- UI: Fixed rendering issues in the Settings page caused by stray HTML tags and redundant borders.

## [0.1.0] - 2026-05-16

### Removed
- Home Assistant: Removed legacy direct API integration (HASS_URL, HASS_TOKEN, etc.) as it has been superseded by MQTT.
- UI: Removed Home Assistant configuration modal and service-level entity ID fields.
- UI: Removed Home Assistant onboarding step.

### Fixed
- MQTT: Fixed duplicate checkmark emoji in connection success message.

## [0.0.28] - 2026-05-16

### Added
- Routing: Support for service-level Routing Mode (Cloudflare or VPS/WireGuard).
- MQTT: Expanded service sensor with additional attributes (Router, Service, Target, Prefix, Current URL, Health, and Routing Mode).
- MQTT: Added automatic discovery cleanup when a service is deleted.
- MQTT: Added immediate discovery/state updates when a service is created or edited.

### Changed
- Dashboard UI: Separated "Target" and "Route" into distinct fields on service cards for better clarity.
- Updated `redis` to 7.3.0 and `python-dotenv` to 1.2.2 in `requirements.txt`.
- Added a note to `README.md` clarifying that the project was created with AI assistance.

### Fixed
- MQTT: Corrected "Routing Mode" attribute to show user-friendly labels (Cloudflare/VPS Gateway) instead of internal values.
- MQTT: Removed port from "Current URL" attribute as external access is always via standard ports.

## [0.0.27] - 2026-02-21

### Added
- Security assessment using `bandit` and `safety` tools.

### Changed
- Pinned Python dependencies in `requirements.txt` to specific, current versions for enhanced security and reproducibility.

### Fixed
- Potential vulnerability warnings from unpinned dependencies by explicitly specifying versions.

## [0.0.26] - 2026-01-20

### Added
- **MQTT Integration**: Implemented MQTT support for Home Assistant Auto Discovery and control (`paho-mqtt`).
- **Settings UI**: Added MQTT configuration section to the "Integrations" tab with a Test Connection button.
- **Backend**: Added background MQTT handler for state updates and command processing.

### Changed
- **Dependencies**: Added `paho-mqtt` to `requirements.txt`.
- **UI**: Added visual separation (`<hr>`) between MQTT and Redis settings in the Integrations tab.

### Fixed
- **Settings Form**: Resolved issue where "Save Settings" button was unresponsive due to a nested `<form>` tag in the API Keys section. Converted API Key creation to use AJAX/Fetch.
- **Settings Form**: Removed `required` attribute from hidden inputs in the settings form to prevent browser validation blocking submission when tabs are switched.
- **Settings Form**: Fixed a warning about "invalid settings" when saving, caused by the `csrf_token` being flagged as disallowed.
- **Backend**: Fixed a deadlock in the MQTT handler reloading logic by using `RLock` instead of `Lock`.

## [0.0.25] - 2026-01-19

### Changed
- Updated service card layout to ensure buttons and footer actions are always aligned to the bottom of the card.
- Changed default application port from 5000 to 5001 to avoid conflicts with other common services (e.g., Docker Registry, Flask defaults).

## [0.0.24] - 2025-12-23

### Added
- **Infrastructure**: Added support for "VPS Gateway + WireGuard" routing mode, allowing RouteGhost to bypass Cloudflare Proxy and UniFi ingress entirely by tunneling traffic through a remote VPS.
- **UI**: Added "VPS / WireGuard" settings tab to configure SSH credentials and WireGuard peers.
- **Backend**: Implemented `routing.py` module for managing WireGuard interfaces and remote VPS `iptables` rules via SSH.
- **Dependencies**: Added `wireguard-tools`, `openresolv`, `iproute2`, `openssh-client`, and `paramiko` to the Docker image.

### Security
- **Hardening**: Implemented strict input sanitization (`shlex.quote`) and validation for all VPS/WireGuard settings to prevent command injection and configuration tampering.
- **Whitelist**: Expanded `ALLOWED_USER_SETTINGS` to include new VPS configuration keys.

### Changed
- Refactored Settings UI:
    - Moved Traefik and Redis settings to the "Integrations" tab.
    - Consolidated "VPS / WireGuard" tab into "Infrastructure" tab.
    - Added "Routing Mode" dropdown to "Infrastructure" tab to toggle between "Cloudflare + Firewall" and "VPS + WireGuard" settings.
    - Moved Firewall settings to "Infrastructure" tab under "Cloudflare + Firewall" mode.
    - Renamed "UniFi Controller" section to "Firewall Controller" in settings.

### Fixed
- Improved security in `base.html` by replacing `innerHTML` with `textContent` for firewall status updates to prevent potential XSS from external API data.

## [0.0.23] - 2025-12-22

### Fixed
- Debounced `turn_off_service` to ignore redundant shutdown requests if the service is already offline.

## [0.0.22] - 2025-12-22

### Changed
- Refactored `main.py` to remove legacy CLI code and `argparse` dependency.
- Hardened `static/js/main.js` against XSS by sanitizing inputs in `showDiagnosticsModal`.
- Home Assistant config modal now uses a clearer placeholder for API keys and prevents password manager interference.

### Fixed
- Reverted API Key selection flow in HASS modal to simplify the user experience (removed misleading "Authorize" flow).

### Removed
- Removed legacy `cmd_on` and `cmd_off` functions from `main.py`.

## [0.0.21] - 2025-12-22

### Added
- Option to delete WebAuthn passkeys from the Settings page.
- API Key selection dropdown in Home Assistant settings modal with re-authorization flow.

## [0.0.20] - 2025-12-21

### Added
- **Docker**: Configurable timezone support in the Docker container via `TZ` environment variable.
- **Logging**: Application logs now include local timestamps with timezone offset for better readability.

## [0.0.19] - 2025-12-21

### Added
- **UI/UX**: Added a "Clear Traefik Routes from Redis" button in the Redis settings to allow manual cleanup of orphan Traefik entries.
- **API**: Added `/api/test/redis/clear` endpoint to facilitate manual Redis cleanup.
- **Logging**: Added "Actor" identification to service startup and shutdown logs. Logs now explicitly show whether an action was triggered via the WebUI (with username), an API Key (with key name), or a background task.

### Changed
- **UI/UX**: The "Rotate URL" button is now automatically disabled for services that have "Randomize Suffix" turned off, as static subdomains do not support rotation.
- **Documentation**: Refined the release process instructions in `GEMINI.md` to prevent changelog duplication and clarify the branch merge workflow.
- **Documentation**: Updated `GEMINI.md` with modern development guidelines including non-root execution, named volume usage, and mandatory security/vulnerability testing for new code changes.

### Fixed
- **Core**: Fixed a `SyntaxError` in `main.py` caused by an unmatched closing brace in the `turn_on_service` function.
- **Core**: Restored the `/api/test/redis/clear` endpoint which was accidentally corrupted in a previous edit, fixing the "Error: JSON.parse" issue when clearing Redis routes.
- **Docker**: Cleaned up `entrypoint.sh` startup logs to remove verbose diagnostic information.

## [0.0.18] - 2025-12-21

### Added
- **Documentation**: Created comprehensive security review document (`SECURITY/COPILOT_SECURITY_REVIEW_DEC_21_2025.md`) and executive summary.
- **API**: Added robust validation functions for subdomains, router names, service names, and target URLs.
- **API**: Implemented `ALLOWED_USER_SETTINGS` whitelist to prevent unauthorized configuration changes.

### Changed
- **Security**: Implemented strict SSRF protection in URL validation, blocking loopback and link-local addresses.
- **Security**: Hardened flash message rendering against XSS using Jinja's `tojson` filter.
- **Security**: Improved error handling to prevent sensitive information disclosure in user-facing messages.

## [0.0.17] - 2025-12-20

### Changed
- **Security**: Updated Docker image to run as a non-root user (`appuser`) with configurable UID/GID (`PUID`/`PGID`), improving container security and host file system compatibility.
- **Infrastructure**: Switched from host-mounted directories to **Named Docker Volumes** (`routeghost_data`) for the `/app/data` directory. This resolves SQLite "readonly database" errors and permission issues specifically encountered when running via WSL2 on Windows host mounts.

### Fixed
- **Docker**: Fixed `sqlite3.OperationalError: attempt to write a readonly database` by enhancing the entrypoint script with recursive ownership/permission enforcement and adding startup diagnostic logging.
- **Docker**: Fixed permission issues with log files and persistent storage by adding an `entrypoint.sh` script that uses `su-exec` to correct file ownership at runtime.
- **Home Assistant Integration**: Fixed a bug where "None" would be rendered and saved in the Home Assistant Entity ID field when left empty.

## [0.0.16] - 2025-12-20

### Changed
- **Branding**: Renamed the project from "Traefik Route Control" to **RouteGhost** 👻 and updated all UI elements, documentation, and Docker configuration.

## [0.0.15] - 2025-12-20

### Fixed
- **UI**: Fixed a bug where the Regex Pattern was still visible on the dashboard even when "Show Regex Pattern" was disabled for the service.

## [0.0.14] - 2025-12-20

### Added
- **Service Configuration**: Added "Show Regex Pattern" toggle to service edit page, allowing users to control whether the regex pattern is displayed on the dashboard for that service.

## [0.0.13] - 2025-12-20

### Changed
- Streamlined `README.md` for better readability and conciseness.
- Updated `GEMINI.md` Release Process section to include dev release workflow and expanded release steps (PR, GitHub Release, Pre-release).

## [0.0.12] - 2025-12-19

### Added
- **UI/UX**: Added a "Rotate Port" button to the main dashboard to manually trigger an immediate firewall port rotation.

### Changed
- **UI/UX**: Added a "Save" button to the Base URL field in the Home Assistant Settings modal.
- **UI/UX**: Added an editable "Base URL" field to the Home Assistant Settings modal.
- **UI/UX**: Replaced the numeric input for "Port Rotation Interval" with a dropdown menu featuring 30-minute increments up to 8 hours for better usability.
- **UI/UX**: "Check Health" and "Rotate Port" buttons on the dashboard are now automatically disabled when the firewall is closed.
- **UI/UX**: Enhanced disabled button styling with reduced opacity and saturation.
- **UI/UX**: Dynamic status updates: Toggling services now updates the firewall status and buttons without a page refresh.
- **UI/UX**: Dynamic health updates: Clicking "Check Health" updates service cards without a page refresh.
- **UI/UX**: Background status polling: The dashboard now polls the server status every 30 seconds.
- **License**: Switched project license to **GNU Affero General Public License v3.0 (AGPLv3)**.

### Fixed
- **Core**: Editing an active service now automatically synchronizes configuration with external APIs.

## [0.0.11] - 2025-12-19

### Added
- **API**: Added `/api/settings` endpoint for saving individual configuration settings via AJAX.

## [0.0.10] - 2025-12-19

### Added
- **Authentication**: Added support for traditional password-based login alongside Passkeys.
- **Security**: Implemented TOTP-based 2FA with QR code setup and recovery codes.
- **Security**: Added Global 2FA enforcement and rate limiting on login attempts.
- **Monitoring**: Added background health checks and Discord webhook notifications.
- **UI/UX**: Reorganized Settings page into a tabbed interface.
- **UI/UX**: Added Dark Mode toggle and Backup/Restore functionality.

## [0.0.1] - Initial Release
- Basic Traefik route rotation.
- Cloudflare DNS and Origin Rule integration.
- UniFi Firewall integration.