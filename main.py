#!/usr/bin/env python3
import redis
import requests
import threading
import signal
import string
import os
import sys
import builtins
import logging
import uuid
import urllib3
from urllib.parse import urlparse
import json
import secrets
import time
from datetime import datetime
import base64
import hashlib
import ipaddress
import socket
import re
from functools import wraps
from dotenv import load_dotenv
from logging_config import setup_logging, get_logger
from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session, has_request_context, make_response, g
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    AuthenticatorAttachment,
    ResidentKeyRequirement,
)
try:
    import pyotp
    import qrcode
    from io import BytesIO
except ImportError:
    pyotp = None
    qrcode = None
from webauthn.helpers.cose import COSEAlgorithmIdentifier
import database as db
import routing
from mqtt_handler import mqtt_manager

# Import DATA_DIR for secret key storage
from database import DATA_DIR

# --- LOGGING SETUP ---
class Tee(object):
    def __init__(self, *files):
        self.files = files
    def write(self, obj):
        for f in self.files:
            try:
                f.write(obj)
                f.flush()
            except Exception: pass
    def flush(self):
        for f in self.files:
            try: f.flush()
            except Exception: pass

LOG_FILE = os.path.join(DATA_DIR, 'app.log')
# Set up rotating log file and redirect stdout/stderr
try:
    from logging.handlers import RotatingFileHandler
    
    log_rotator = RotatingFileHandler(
        LOG_FILE, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'
    )
    # Write a startup marker
    log_rotator.stream.write(f"--- Log Started at {time.ctime()} ---\n")
    
    sys.stdout = Tee(sys.stdout, log_rotator.stream)
    sys.stderr = Tee(sys.stderr, log_rotator.stream)
except Exception as e:
    print(f"⚠️ Failed to setup logging: {e}")

# Override print to include timestamps
original_print = builtins.print
def timestamped_print(*args, **kwargs):
    file = kwargs.get('file', sys.stdout)
    # Only add timestamp if printing to stdout/stderr (which are Tee objects)
    if file in (sys.stdout, sys.stderr):
        try:
            ts = datetime.now().astimezone().strftime("[%Y-%m-%d %H:%M:%S %z]")
        except Exception:
            # Fallback if astimezone fails
            ts = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        
        sep = kwargs.get('sep', ' ')
        msg = sep.join(map(str, args))
        # Remove sep from kwargs as we handled it, to avoid double separator usage if we were passing multiple args
        # But we are passing a single string, so sep is ignored by print for the content, 
        # but we should keep it in kwargs if print uses it? print(obj, sep=...) 
        # Actually print(single_obj, sep=...) sep is unused.
        
        original_print(f"{ts} {msg}", **kwargs)
    else:
        original_print(*args, **kwargs)

builtins.print = timestamped_print

# ---------------------

# Suppress InsecureRequestWarning for UniFi self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================= CONFIGURATION =================
script_dir = os.path.dirname(os.path.abspath(__file__))

# Initialize database
db.init_db()

# Initialize structured logging
setup_logging(log_dir=DATA_DIR)

logger = get_logger("routeghost")

# Constants
# Settings are now stored in database and configured via web UI
# No longer required at startup
REQUIRED_SETTINGS = []

def get_version():
    """Read version from VERSION.txt"""
    try:
        version_file = os.path.join(script_dir, 'VERSION.txt')
        if os.path.exists(version_file):
            with open(version_file, 'r') as f:
                return f.read().strip()
        
        # Try current working directory as fallback
        cwd_file = os.path.join(os.getcwd(), 'VERSION.txt')
        if os.path.exists(cwd_file):
            with open(cwd_file, 'r') as f:
                return f.read().strip()
    except Exception as e:
        print(f"⚠️ Error reading version: {e}")
        
    return "Unknown"

def migrate_env_to_db():
    """Migrate settings from .env file to database (one-time)."""
    env_keys = [
        "CF_API_TOKEN", "CF_ZONE_ID", "DOMAIN_ROOT", "ORIGIN_RULE_NAME",
        "REDIS_HOST", "REDIS_PORT", "REDIS_PASS",
        "UNIFI_HOST", "UNIFI_USER", "UNIFI_PASS", "UNIFI_RULE_NAME"
    ]
    
    migrated = False
    for key in env_keys:
        value = os.getenv(key)
        if value and not db.get_setting(key):
            db.set_setting(key, value)
            migrated = True
    
    # Migrate single service to database if env vars exist
    router_name = os.getenv("ROUTER_NAME")
    service_name = os.getenv("SERVICE_NAME")
    target_url = os.getenv("TARGET_INT_URL")
    
    if router_name and service_name and target_url:
        services = db.get_all_services()
        if not services:
            # Create default service from env
            db.add_service(
                name="Jellyfin",
                router_name=router_name,
                service_name=service_name,
                target_url=target_url,
                subdomain_prefix="jf"
            )
            migrated = True
    
    # Set defaults for new settings if they don't exist
    if not db.get_setting("FIREWALL_TYPE"):
        # Default to unifi if UNIFI_HOST is set, otherwise none
        if db.get_setting("UNIFI_HOST"):
            db.set_setting("FIREWALL_TYPE", "unifi")
        else:
            db.set_setting("FIREWALL_TYPE", "none")
        migrated = True
    
    if migrated:
        print("✅ Migrated settings from .env to database")

# Try to load from .env file if exists (for migration)
env_path = os.path.join(script_dir, ".env")
if os.path.exists(env_path):
    load_dotenv(env_path)

def get_setting(key, required=True):
    """Get a setting from database.
    
    Args:
        key: The setting key to retrieve
        required: Documentation hint only (no longer enforced at startup).
                  Validation happens at point of use.
    
    Returns:
        The setting value or None if not found
    """
    value = db.get_setting(key)
    # Settings are now optional at startup and configured via web UI
    # No longer print errors for missing settings during startup
    return value

# API Settings
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", 5001))

# ================= INPUT VALIDATION FUNCTIONS =================

def validate_subdomain_prefix(prefix):
    """Validate subdomain prefix for DNS safety.
    
    DNS label rules: alphanumeric and hyphens only, no leading/trailing hyphens.
    Max 63 characters per label.
    
    Args:
        prefix: The subdomain prefix to validate
        
    Returns:
        str: Validated and normalized (lowercase) prefix
        
    Raises:
        ValueError: If prefix is invalid
    """
    if not prefix:
        raise ValueError("Subdomain prefix is required")
    
    prefix = prefix.strip()
    
    # DNS label rules: alphanumeric and hyphens only, no leading/trailing hyphens
    # Pattern allows single character (e.g., 'a') or multiple with hyphens in middle
    if not re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?$', prefix, re.IGNORECASE):
        raise ValueError("Subdomain prefix must contain only letters, numbers, and hyphens (not at start/end)")
    
    if len(prefix) > 63:
        raise ValueError("Subdomain prefix too long (max 63 characters)")
    
    return prefix.lower()

def validate_router_name(name):
    """Validate router name for Traefik/Redis safety.
    
    Args:
        name: The router name to validate
        
    Returns:
        str: Validated router name
        
    Raises:
        ValueError: If name is invalid
    """
    if not name:
        raise ValueError("Router name is required")
    
    name = name.strip()
    
    # Alphanumeric, hyphens, underscores only
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        raise ValueError("Router name must contain only letters, numbers, hyphens, and underscores")
    
    if len(name) > 64:
        raise ValueError("Router name too long (max 64 characters)")
    
    return name

def validate_service_name(name):
    """Validate service name for Traefik/Redis safety.
    
    Args:
        name: The service name to validate
        
    Returns:
        str: Validated service name
        
    Raises:
        ValueError: If name is invalid
    """
    # Same rules as router name
    if not name:
        raise ValueError("Service name is required")
    
    name = name.strip()
    
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        raise ValueError("Service name must contain only letters, numbers, hyphens, and underscores")
    
    if len(name) > 64:
        raise ValueError("Service name too long (max 64 characters)")
    
    return name

def validate_display_name(name):
    """Validate display name (more permissive than router/service names).
    
    Args:
        name: The display name to validate
        
    Returns:
        str: Validated display name
        
    Raises:
        ValueError: If name is invalid
    """
    if not name:
        raise ValueError("Display name is required")
    
    name = name.strip()
    
    if len(name) > 128:
        raise ValueError("Display name too long (max 128 characters)")
    
    # Allow most characters for display, but ensure it's not empty after stripping
    if not name:
        raise ValueError("Display name cannot be empty or whitespace only")
    
    return name

def validate_target_url(url):
    """Validate target URL for security.
    
    Checks for:
    - Valid HTTP/HTTPS scheme
    - No credentials in URL
    - Valid hostname
    - Not link-local, loopback, or multicast addresses
    
    Note: This function resolves hostnames using IPv4 (socket.gethostbyname).
    Hostnames that only resolve to IPv6 addresses will be rejected.
    
    Args:
        url: The URL to validate
        
    Returns:
        str: Validated URL
        
    Raises:
        ValueError: If URL is invalid or potentially dangerous
    """
    if not url:
        raise ValueError("Target URL is required")
    
    url = url.strip()
    
    if not url.startswith(('http://', 'https://')):
        raise ValueError("Target URL must start with http:// or https://")
    
    try:
        parsed = urlparse(url)
        
        if not parsed.netloc:
            raise ValueError("Invalid URL format - missing hostname")
        
        # Check for credentials in URL (security risk)
        if '@' in parsed.netloc:
            raise ValueError("URLs with embedded credentials are not allowed for security reasons")
        
        # Extract hostname (handles IPv6)
        hostname = parsed.hostname
        if not hostname:
            raise ValueError("Invalid hostname in URL")
        
        # Resolve hostname to IP and check for dangerous address ranges
        try:
            # Use getaddrinfo to support both IPv4 and IPv6
            # AF_UNSPEC allows both IPv4 and IPv6
            # We only need one address, so take the first result
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            if not addr_info:
                raise ValueError(f"Cannot resolve hostname '{hostname}'")
            
            # Get the first IP address (format is (family, type, proto, canonname, sockaddr))
            # sockaddr is a tuple (address, port) for AF_INET or (address, port, flowinfo, scopeid) for AF_INET6
            ip_str = addr_info[0][4][0]
            ip_obj = ipaddress.ip_address(ip_str)
            
            # Block link-local (169.254.0.0/16, fe80::/10)
            # These addresses are auto-assigned and shouldn't be used
            if ip_obj.is_link_local:
                raise ValueError("Link-local addresses (169.254.x.x, fe80::) are not allowed")
            
            # Block loopback (127.0.0.0/8, ::1)
            # Prevents SSRF attacks against the RouteGhost server itself
            if ip_obj.is_loopback:
                raise ValueError("Loopback addresses (localhost, 127.x.x.x, ::1) are not allowed")
            
            # Block multicast
            if ip_obj.is_multicast:
                raise ValueError("Multicast addresses are not allowed")
            
            # Note: We allow private IPs (192.168.x.x, 10.x.x.x, 172.16-31.x.x, fd00::/8)
            # because this application is designed to proxy to internal services
                
        except socket.gaierror:
            raise ValueError(f"Cannot resolve hostname '{hostname}'")
        
        return url
        
    except ValueError:
        raise
    except Exception as e:
        raise ValueError(f"Invalid URL: {str(e)}")

# ================= HELPER FUNCTIONS =================

# Locks for thread safety
_cache_lock = threading.Lock()
_service_ops_lock = threading.RLock()  # RLock because rotate_service calls turn_off + turn_on
_shutdown_event = threading.Event()

def request_shutdown(signum=None, frame=None):
    """Signal handler for graceful shutdown."""
    print("🛑 Shutdown signal received, stopping background threads...")
    _shutdown_event.set()

def get_unifi_verify_ssl():
    """Check if UniFi TLS verification is enabled. Default: False for self-signed certs."""
    return get_setting('UNIFI_VERIFY_SSL', '0') == '1'

_redis_client = None
_redis_config_hash = None

def get_redis():
    """Get a Redis connection with automatic retry and config-change detection."""
    global _redis_client, _redis_config_hash
    try:
        redis_host = get_setting("REDIS_HOST")
        if not redis_host:
            return None

        redis_port_str = get_setting("REDIS_PORT", required=False)
        redis_port = int(redis_port_str) if redis_port_str else 6379
        redis_pass = get_setting("REDIS_PASS", required=False)

        config_key = f"{redis_host}:{redis_port}:{redis_pass or ''}"
        if _redis_client and _redis_config_hash == config_key:
            try:
                _redis_client.ping()
                return _redis_client
            except redis.ConnectionError:
                pass

        client = redis.Redis(
            host=redis_host,
            port=redis_port,
            password=redis_pass if redis_pass else None,
            decode_responses=True,
            socket_timeout=5,
            socket_connect_timeout=5,
            retry_on_timeout=True,
        )
        client.ping()
        _redis_client = client
        _redis_config_hash = config_key
        return client
    except Exception as e:
        print(f"❌ Redis Connection Error: {e}")
        _redis_client = None
        _redis_config_hash = None
        return None

_public_ip_cache = {"ip": None, "timestamp": 0}
_PUBLIC_IP_CACHE_TTL = 300  # 5 minutes

def get_public_ip():
    """Get the public IP, cached for 5 minutes to avoid repeated lookups."""
    now = time.time()
    with _cache_lock:
        if _public_ip_cache["ip"] and now - _public_ip_cache["timestamp"] < _PUBLIC_IP_CACHE_TTL:
            return _public_ip_cache["ip"]
    try:
        ip = requests.get("https://api.ipify.org", timeout=5).text
        with _cache_lock:
            _public_ip_cache["ip"] = ip
            _public_ip_cache["timestamp"] = now
        return ip
    except (requests.RequestException, ValueError) as e:
        print(f"⚠️ Failed to get public IP: {e}")
        with _cache_lock:
            return _public_ip_cache["ip"] or "Unknown"

# Rate limiting storage
LOGIN_ATTEMPTS = {}

def check_rate_limit(ip_address, limit=5, window=60):
    """Simple in-memory rate limiting (fallback when Redis unavailable)."""
    current_time = time.time()
    if ip_address not in LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS[ip_address] = []
    
    # Filter out timestamps older than the window
    LOGIN_ATTEMPTS[ip_address] = [t for t in LOGIN_ATTEMPTS[ip_address] if current_time - t < window]
    
    # Evict stale IPs to prevent memory leak (keep at most 10000 entries)
    if len(LOGIN_ATTEMPTS) > 10000:
        stale_ips = [ip for ip, ts in LOGIN_ATTEMPTS.items() if not ts]
        for ip in stale_ips[:5000]:
            del LOGIN_ATTEMPTS[ip]
    
    # Check if limit reached
    if len(LOGIN_ATTEMPTS[ip_address]) >= limit:
        return False
    
    # Add current attempt
    LOGIN_ATTEMPTS[ip_address].append(current_time)
    return True

def check_rate_limit_redis(key_prefix, identifier, limit=5, window=60):
    """Redis-backed rate limiting. Falls back to in-memory if Redis unavailable."""
    r = get_redis()
    if r is None:
        # Fallback to in-memory for the specific key
        return check_rate_limit(f"{key_prefix}:{identifier}", limit, window)
    
    try:
        key = f"rate_limit:{key_prefix}:{identifier}"
        pipe = r.pipeline()
        now = time.time()
        window_start = now - window
        
        # Remove expired entries
        pipe.zremrangebyscore(key, 0, window_start)
        # Count current entries
        pipe.zcard(key)
        # Add current attempt
        pipe.zadd(key, {str(now): now})
        # Set expiry on the key
        pipe.expire(key, window)
        
        results = pipe.execute()
        current_count = results[1]
        
        if current_count >= limit:
            # Remove the attempt we just added since we're over limit
            pipe.zrem(key, str(now))
            pipe.execute()
            return False
        
        return True
    except Exception as e:
        logger.warning("Redis rate limit error: %s, falling back to in-memory", e)
        return check_rate_limit(f"{key_prefix}:{identifier}", limit, window)

def check_2fa_rate_limit(identifier, limit=5, window=300):
    """Rate limit for 2FA verification (5 attempts per 5 minutes)."""
    return check_rate_limit_redis("2fa", identifier, limit, window)

def check_webauthn_rate_limit(identifier, limit=10, window=60):
    """Rate limit for WebAuthn operations (10 attempts per minute)."""
    return check_rate_limit_redis("webauthn", identifier, limit, window)

def check_port_open(port, session=None, base_url=None):
    """
    Check if a port is open by verifying the UniFi firewall rule status.
    
    Note: This function checks if the firewall rule is enabled, not if the port
    is actually accessible from the internet. A full external port check would 
    require using third-party services which may have rate limits or reliability issues.
    
    Args:
        port: The port number to check
    
    Returns:
        dict: {"open": bool or None, "error": str or None}
              - open=True: Port confirmed accessible (firewall rule enabled with correct port)
              - open=False: Port not accessible (firewall rule has issues)
              - open=None: Port status unknown (firewall control not configured)
    """
    try:
        # Check if the UniFi rule is enabled with the correct port
        rule_info = check_unifi_rule(session=session, base_url=base_url)
        
        if rule_info is None:
            # Firewall control is disabled or not configured
            # Return unknown status rather than assuming it's open
            return {"open": None, "error": "Firewall control not configured - port status unknown"}
        
        if rule_info.get("enabled") and rule_info.get("port") == port:
            return {"open": True, "error": None}
        else:
            return {"open": False, "error": f"Firewall rule shows port {rule_info.get('port', 'unknown')} instead of {port}"}
    except Exception as e:
        return {"open": False, "error": str(e)}


# List of well-known ports to avoid (from IANA registry)
# https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
RESERVED_PORTS = set([
    # System Ports (1-1023)
    *range(1, 1024),
    # Commonly used registered ports (1024-49151)
    1080, 1194, 1433, 1434, 1521, 1701, 1723, 1883, 1900,
    2049, 2082, 2083, 2086, 2087, 2095, 2096, 2375, 2376, 2377, 2379, 2380,
    3000, 3001, 3002, 3003, 3004, 3005, 3006, 3128, 3268, 3269, 3306, 3389,
    4443, 4444, 4567, 4789, 4822,
    5000, 5001, 5432, 5433, 5555, 5672, 5900, 5901, 5984, 5985, 5986,
    6379, 6443, 6666, 6667, 6697,
    7000, 7001, 7077, 7443, 7474, 7687,
    8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009,
    8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
    8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099,
    8123, 8180, 8181, 8200, 8243, 8280, 8281, 8443, 8444, 8530, 8531, 8545, 8554, 8880, 8888, 8889,
    9000, 9001, 9002, 9003, 9009, 9042, 9090, 9091, 9092, 9093, 9094, 9095, 9096, 9100, 9200, 9300, 9418, 9443,
    10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007, 10008, 10009, 10050, 10051,
    11211, 11371,
    15672,
    16379,
    17500,
    19132, 19133,
    20000,
    25565, 25575,
    27015, 27016, 27017, 27018, 27019,
    28015, 28016, 28017,
    32400,
    33060,
    35197,
    37777,
    50000, 50001, 50002,
])

def generate_random_port():
    """
    Generate a random port between 1024 and 65535, avoiding known assigned ports.
    Returns a port number that is not in the RESERVED_PORTS set.
    
    Note: With ~63,000 available ports (64,535 total - 1,184 reserved), the random
    selection approach is efficient. Even with 100 services running, we have a 
    >99.9% chance of finding a port in the first 1000 attempts.
    """
    # Get active ports once to avoid repeated database queries
    services = db.get_all_services()
    ports_in_use = {s.get('current_port') for s in services 
                    if s.get('enabled') and s.get('current_port') is not None}
    
    max_attempts = 1000
    for _ in range(max_attempts):
        port = secrets.randbelow(65536 - 1024) + 1024
        if port not in RESERVED_PORTS and port not in ports_in_use:
            return port
    
    # Fallback: try to find a port in a safe range that avoids both reserved and in-use ports
    # Using higher port range which has fewer common services
    for _ in range(max_attempts):
        port = secrets.randbelow(65536 - 49152) + 49152
        if port not in RESERVED_PORTS and port not in ports_in_use:
            return port
    
    # Ultimate fallback (should never reach here given 64k port space)
    # Return a port in the dynamic range, even if it might be reserved
    return secrets.randbelow(65536 - 49152) + 49152

def count_active_routers():
    """Counts how many Traefik routers are currently active in Redis."""
    r = get_redis()
    keys = r.keys("traefik/http/routers/*/rule")
    return len(keys)

def cf_request(method, endpoint, data=None, timeout=15):
    cf_token = get_setting("CF_API_TOKEN")
    cf_zone_id = get_setting("CF_ZONE_ID")
    
    if not cf_token or not cf_zone_id:
        print(f"❌ Cloudflare settings not configured")
        return None
    
    headers = {
        "Authorization": f"Bearer {cf_token}",
        "Content-Type": "application/json"
    }
    url = f"https://api.cloudflare.com/client/v4/zones/{cf_zone_id}/{endpoint}"
    response = requests.request(method, url, headers=headers, json=data, timeout=timeout)
    if not response.ok:
        print(f"❌ Cloudflare Error ({endpoint}): {response.text}")
        return None
    return response.json()

def should_delete_dns_record(record_name, subdomain_prefix, current_hostname=None):
    """
    Check if a DNS record should be deleted based on subdomain prefix matching.
    
    Args:
        record_name: Full DNS record name (e.g., "jf-abc123.example.com")
        subdomain_prefix: Service subdomain prefix (e.g., "jf")
        current_hostname: Optional current hostname to preserve (won't be deleted)
    
    Returns:
        bool: True if the record should be deleted, False otherwise
    """
    # Don't delete the current hostname
    if current_hostname and record_name == current_hostname:
        return False
    
    # Only delete records that actually start with this service's prefix pattern
    expected_prefix = f"{subdomain_prefix}-"
    # Extract just the subdomain part (without domain)
    subdomain = record_name.split('.')[0] if '.' in record_name else record_name
    
    return subdomain.startswith(expected_prefix)

# Global cache for UniFi status to prevent API spamming
UNIFI_STATUS_CACHE = {
    "timestamp": 0,
    "data": None,
    "ttl": 60  # seconds
}

def invalidate_unifi_cache():
    with _cache_lock:
        UNIFI_STATUS_CACHE["timestamp"] = 0

def logout_unifi(session, base_url):
    try:
        session.post(f"{base_url}/api/auth/logout", timeout=2)
    except Exception:
        pass

def unifi_request(session, method, url, **kwargs):
    """Makes a request to UniFi with retry logic for rate limits (429)."""
    if 'timeout' not in kwargs:
        kwargs['timeout'] = 15

    for attempt in range(5):
        try:
            resp = session.request(method, url, **kwargs)
            if resp.status_code == 429:
                wait_time = (attempt + 1) * 4
                print(f"   ⚠️ UniFi Rate Limit (429). Retrying in {wait_time}s...")
                time.sleep(wait_time)
                continue
            return resp
        except (requests.exceptions.RequestException, socket.timeout) as e:
            if attempt == 4:
                print(f"❌ UniFi Request Failed: {e}")
                return None
            time.sleep(2)
    return None

def login_unifi_with_retry(session, base_url, username, password):
    """Logs into UniFi with retry logic for rate limits."""
    return unifi_request(session, "POST", f"{base_url}/api/auth/login", json={"username": username, "password": password})

def sync_unifi_groups(session=None, base_url=None):
    """
    Syncs active service IPs and Ports to UniFi Firewall Groups.
    """
    # Check if configured
    ip_group_name = get_setting("UNIFI_IP_GROUP_NAME", required=False)
    port_group_name = get_setting("UNIFI_PORT_GROUP_NAME", required=False)
    traefik_lan = get_setting("TRAEFIK_LAN_CIDR", required=False)
    
    if not ip_group_name or not port_group_name:
        return
        
    print("🔹 Syncing UniFi Firewall Groups...")
    
    # 1. Calculate desired state from enabled services
    services = db.get_all_services()
    desired_ips = set()
    desired_ports = set()
    
    for service in services:
        if service['enabled']:
            try:
                # Parse target URL to get IP and Port
                parsed = urlparse(service['target_url'])
                if not parsed.netloc:
                    continue
                    
                hostname = parsed.hostname
                port = parsed.port
                
                # Default ports
                if not port:
                    if parsed.scheme == 'http': port = 80
                    elif parsed.scheme == 'https': port = 443
                
                if hostname and port:
                    # Resolve hostname to IP
                    ip = socket.gethostbyname(hostname)
                    
                    # Check if IP is in Traefik LAN (exclude if so)
                    in_lan = False
                    if traefik_lan:
                        try:
                            if ipaddress.ip_address(ip) in ipaddress.ip_network(traefik_lan):
                                in_lan = True
                        except (ValueError, TypeError):
                            pass
                    
                    if not in_lan:
                        desired_ips.add(ip)
                        desired_ports.add(str(port))
            except Exception as e:
                print(f"   ⚠️ Error parsing service {service['name']}: {e}")
    
    # 2. Update UniFi
    own_session = False
    if session is None:
        unifi_host = get_setting("UNIFI_HOST")
        unifi_user = get_setting("UNIFI_USER")
        unifi_pass = get_setting("UNIFI_PASS")
        
        if not all([unifi_host, unifi_user, unifi_pass]):
            return
            
        base_url = f"https://{unifi_host}"
        session = requests.Session()
        session.verify = get_unifi_verify_ssl()
        own_session = True
    
    try:
        if own_session:
            # Login
            resp = login_unifi_with_retry(session, base_url, unifi_user, unifi_pass)
            
            if not resp or resp.status_code != 200:
                if resp:
                    print(f"❌ UniFi Login Failed: HTTP {resp.status_code}")
                return
                
            csrf_token = resp.headers.get("x-csrf-token")
            if csrf_token:
                session.headers.update({"X-CSRF-Token": csrf_token})
        
        # Ensure headers are prepared for PUT requests
        headers = {}
        if session.headers.get("X-CSRF-Token"):
            headers["X-CSRF-Token"] = session.headers.get("X-CSRF-Token")

        # Get Firewall Groups
        resp = unifi_request(session, "GET", f"{base_url}/proxy/network/api/s/default/rest/firewallgroup")
        if not resp or resp.status_code != 200:
            return
            
        groups = resp.json().get("data", [])
        
        # Update IP Group
        ip_group = next((g for g in groups if g.get("name") == ip_group_name), None)
        if ip_group:
            # UniFi GET returns 'members', but PUT expects 'group_members'
            current_members = set(ip_group.get("members", []) or ip_group.get("group_members", []))
            if current_members != desired_ips:
                # Construct payload based on Art-of-WiFi client structure
                payload = {
                    "_id": ip_group["_id"],
                    "name": ip_group["name"],
                    "group_type": ip_group["group_type"],
                    "group_members": list(desired_ips)
                }
                if "site_id" in ip_group:
                    payload["site_id"] = ip_group["site_id"]

                resp = unifi_request(session, "PUT", f"{base_url}/proxy/network/api/s/default/rest/firewallgroup/{ip_group['_id']}", json=payload, headers=headers)
                if resp and resp.status_code == 200:
                    print(f"   Updated IP Group '{ip_group_name}': {list(desired_ips)}")
                    # Verification with retry for eventual consistency
                    verified = False
                    for attempt in range(3):
                        time.sleep(2) # Wait for propagation
                        verify_resp = unifi_request(session, "GET", f"{base_url}/proxy/network/api/s/default/rest/firewallgroup/{ip_group['_id']}")
                        if verify_resp and verify_resp.status_code == 200:
                            verified_data = verify_resp.json().get("data", [{}])[0]
                            current_members_after_update = set(verified_data.get("members", []) or verified_data.get("group_members", []))
                            if current_members_after_update == desired_ips:
                                print(f"   ✅ Verification: Group now contains {list(desired_ips)}")
                                verified = True
                                break
                            else:
                                print(f"   ⚠️ Verification attempt {attempt + 1}/3 failed: Group members do not match desired state.")
                        else:
                            print(f"   ⚠️ Verification attempt {attempt + 1}/3 failed: Could not fetch group details.")
                    if not verified:
                        print(f"   ❌ Verification failed for IP Group '{ip_group_name}' after multiple attempts.")
                else:
                    msg = resp.text if resp else "No response"
                    print(f"   ❌ Failed to update IP Group '{ip_group_name}': {msg}")
        else:
            print(f"   ⚠️ Warning: IP Group '{ip_group_name}' not found in UniFi")
            
        # Update Port Group
        port_group = next((g for g in groups if g.get("name") == port_group_name), None)
        if port_group:
            # UniFi GET returns 'members', but PUT expects 'group_members'
            current_members = set(port_group.get("members", []) or port_group.get("group_members", []))
            if current_members != desired_ports:
                # Construct payload based on Art-of-WiFi client structure
                payload = {
                    "_id": port_group["_id"],
                    "name": port_group["name"],
                    "group_type": port_group["group_type"],
                    "group_members": list(desired_ports)
                }
                if "site_id" in port_group:
                    payload["site_id"] = port_group["site_id"]

                resp = unifi_request(session, "PUT", f"{base_url}/proxy/network/api/s/default/rest/firewallgroup/{port_group['_id']}", json=payload, headers=headers)
                if resp and resp.status_code == 200:
                    print(f"   Updated Port Group '{port_group_name}': {list(desired_ports)}")
                    # Verification with retry for eventual consistency
                    verified = False
                    for attempt in range(3):
                        time.sleep(2) # Wait for propagation
                        verify_resp = unifi_request(session, "GET", f"{base_url}/proxy/network/api/s/default/rest/firewallgroup/{port_group['_id']}")
                        if verify_resp and verify_resp.status_code == 200:
                            verified_data = verify_resp.json().get("data", [{}])[0]
                            current_members_after_update = set(verified_data.get("members", []) or verified_data.get("group_members", []))
                            if current_members_after_update == desired_ports:
                                print(f"   ✅ Verification: Group now contains {list(desired_ports)}")
                                verified = True
                                break
                            else:
                                print(f"   ⚠️ Verification attempt {attempt + 1}/3 failed: Group members do not match desired state.")
                        else:
                            print(f"   ⚠️ Verification attempt {attempt + 1}/3 failed: Could not fetch group details.")
                    if not verified:
                        print(f"   ❌ Verification failed for Port Group '{port_group_name}' after multiple attempts.")
                else:
                    msg = resp.text if resp else "No response"
                    print(f"   ❌ Failed to update Port Group '{port_group_name}': {msg}")
        else:
            print(f"   ⚠️ Warning: Port Group '{port_group_name}' not found in UniFi")
            
    except Exception as e:
        print(f"❌ Error syncing UniFi groups: {e}")
    finally:
        if own_session:
            logout_unifi(session, base_url)

# ================= UNIFI LOGIC =================

def _test_service_firewall(service_id):
    """Checks if a specific service's IP/port are correctly represented in UniFi firewall groups."""
    service = db.get_service(service_id)
    if not service:
        return {"error": "Service not found", "status_code": 404}

    if not service['enabled']:
        return {"info": "Service is disabled, so firewall rules do not apply."}

    # Get UniFi settings
    firewall_type = get_setting("FIREWALL_TYPE", required=False)
    if firewall_type != "unifi":
        return {"info": f"Firewall type is '{firewall_type}', not 'unifi'. No test performed."}

    ip_group_name = get_setting("UNIFI_IP_GROUP_NAME", required=False)
    port_group_name = get_setting("UNIFI_PORT_GROUP_NAME", required=False)
    traefik_lan = get_setting("TRAEFIK_LAN_CIDR", required=False)
    unifi_host = get_setting("UNIFI_HOST")
    unifi_user = get_setting("UNIFI_USER")
    unifi_pass = get_setting("UNIFI_PASS")

    if not all([ip_group_name, port_group_name, unifi_host, unifi_user, unifi_pass]):
        return {"error": "UniFi firewall groups or credentials are not fully configured.", "status_code": 400}

    # 1. Determine expected state for the specific service
    try:
        parsed = urlparse(service['target_url'])
        hostname = parsed.hostname
        port = parsed.port
        if not port:
            port = 80 if parsed.scheme == 'http' else 443
        
        if not hostname:
            return {"error": "Could not parse hostname from service target URL.", "status_code": 400}

        service_ip = socket.gethostbyname(hostname)
        service_port = str(port)
    except Exception as e:
        return {"error": f"Failed to resolve service IP/port: {e}", "status_code": 500}

    # 2. Recalculate the complete desired state for all services
    all_services = db.get_all_services()
    overall_desired_ips = set()
    overall_desired_ports = set()

    for s in all_services:
        if s['enabled']:
            try:
                s_parsed = urlparse(s['target_url'])
                s_hostname, s_port = s_parsed.hostname, s_parsed.port
                if not s_port:
                    s_port = 80 if s_parsed.scheme == 'http' else 443
                
                if s_hostname and s_port:
                    s_ip = socket.gethostbyname(s_hostname)
                    s_in_lan = False
                    if traefik_lan:
                        if ipaddress.ip_address(s_ip) in ipaddress.ip_network(traefik_lan):
                            s_in_lan = True
                    
                    if not s_in_lan:
                        overall_desired_ips.add(s_ip)
                        overall_desired_ports.add(str(s_port))
            except Exception:
                continue # Ignore services that can't be resolved

    # 3. Connect to UniFi and get current state
    base_url = f"https://{unifi_host}"
    session = requests.Session()
    session.verify = False
    results = {}
    
    try:
        resp = login_unifi_with_retry(session, base_url, unifi_user, unifi_pass)
        if not resp or resp.status_code != 200:
            return {"error": f"UniFi Login Failed: HTTP {resp.status_code if resp else 'N/A'}", "status_code": 500}

        csrf_token = resp.headers.get("x-csrf-token")
        if csrf_token:
            session.headers.update({"X-CSRF-Token": csrf_token})

        resp = session.get(f"{base_url}/proxy/network/api/s/default/rest/firewallgroup", timeout=10)
        if resp.status_code != 200:
            return {"error": "Failed to fetch firewall groups from UniFi.", "status_code": 500}
        
        groups = resp.json().get("data", [])
        ip_group = next((g for g in groups if g.get("name") == ip_group_name), None)
        port_group = next((g for g in groups if g.get("name") == port_group_name), None)
        
        # 4. Perform checks
        
        # IP Check
        service_in_lan = False
        if traefik_lan:
            service_in_lan = ipaddress.ip_address(service_ip) in ipaddress.ip_network(traefik_lan)

        if not ip_group:
            results["ip_check"] = {"status": "fail", "message": f"IP Group '{ip_group_name}' not found."}
        else:
            current_ips = set(ip_group.get("members", []) or ip_group.get("group_members", []))
            if service_in_lan:
                if service_ip in current_ips:
                    results["ip_check"] = {"status": "fail", "message": f"IP {service_ip} should be excluded (in LAN) but was found in the group."}
                else:
                    results["ip_check"] = {"status": "ok", "message": f"IP {service_ip} is correctly excluded from the group."}
            else: # Not in LAN
                if service_ip in current_ips:
                    results["ip_check"] = {"status": "ok", "message": f"IP {service_ip} is correctly present in the group."}
                else:
                    results["ip_check"] = {"status": "fail", "message": f"IP {service_ip} is missing from the group."}

        # Port Check
        if not port_group:
            results["port_check"] = {"status": "fail", "message": f"Port Group '{port_group_name}' not found."}
        else:
            current_ports = set(port_group.get("members", []) or port_group.get("group_members", []))
            port_should_be_present = service_port in overall_desired_ports

            if port_should_be_present:
                if service_port in current_ports:
                    results["port_check"] = {"status": "ok", "message": f"Port {service_port} is correctly present in the group."}
                else:
                    results["port_check"] = {"status": "fail", "message": f"Port {service_port} should be in the group, but is missing."}
            else: # Port should not be present
                if service_port in current_ports:
                    results["port_check"] = {"status": "fail", "message": f"Port {service_port} should be excluded, but was found in the group."}
                else:
                    results["port_check"] = {"status": "ok", "message": f"Port {service_port} is correctly excluded from the group."}

    except Exception as e:
        return {"error": f"An unexpected error occurred during the test: {e}", "status_code": 500}
    finally:
        if session:
            logout_unifi(session, base_url)
    
    return results

def check_unifi_rule(session=None, base_url=None):
    """Reads the current status of the UniFi Port Forward rule.
    
    Returns:
        dict: {"enabled": bool, "port": int or None} or None if not available
              port can be None if 'dst_port' is not set in the rule
    """
    # Check if firewall control is enabled
    firewall_type = get_setting("FIREWALL_TYPE", required=False)
    if firewall_type == "none":
        return None
    
    # Check cache first
    with _cache_lock:
        if time.time() - UNIFI_STATUS_CACHE["timestamp"] < UNIFI_STATUS_CACHE["ttl"]:
            return UNIFI_STATUS_CACHE["data"]
    
    unifi_rule_name = get_setting("UNIFI_RULE_NAME", required=False)
    
    if not unifi_rule_name:
        return None
    
    own_session = False
    if session is None:
        unifi_host = get_setting("UNIFI_HOST", required=False)
        unifi_user = get_setting("UNIFI_USER", required=False)
        unifi_pass = get_setting("UNIFI_PASS", required=False)
        if not all([unifi_host, unifi_user, unifi_pass]):
            return None
        base_url = f"https://{unifi_host}"
        session = requests.Session()
        session.verify = get_unifi_verify_ssl()
        own_session = True

    try:
        if own_session:
            # Login
            resp = login_unifi_with_retry(session, base_url, unifi_user, unifi_pass)
            if not resp or resp.status_code != 200:
                return None # Login failed

        # Fetch Rules
        pf_url = f"{base_url}/proxy/network/api/s/default/rest/portforward"
        resp = session.get(pf_url, timeout=5)
        rules = resp.json().get("data", [])
        
        target_rule = next((r for r in rules if r.get("name") == unifi_rule_name), None)
        if target_rule:
            # Convert port to int for consistent comparison, with error handling
            dst_port = target_rule.get("dst_port")
            port = None
            if dst_port:
                try:
                    port = int(dst_port)
                except (ValueError, TypeError):
                    # If conversion fails, log and leave as None
                    print(f"⚠️ Warning: Invalid port value '{dst_port}' in UniFi rule")
            
            result = {
                "enabled": target_rule["enabled"],
                "port": port
            }
            
            # Update cache
            with _cache_lock:
                UNIFI_STATUS_CACHE["data"] = result
                UNIFI_STATUS_CACHE["timestamp"] = time.time()
            return result
        
    except Exception:
        return None # Connection error
    finally:
        if own_session:
            logout_unifi(session, base_url)

def toggle_unifi(enable_rule, forward_port=None, session=None, base_url=None):
    """
    Logs into UDM Pro and toggles the Port Forwarding Rule.
    
    Args:
        enable_rule: Boolean to enable/disable the rule
        forward_port: Optional port number to update in the rule
    """
    # Invalidate cache since we are changing state
    invalidate_unifi_cache()

    # Check if firewall control is enabled
    firewall_type = get_setting("FIREWALL_TYPE", required=False)
    if firewall_type == "none":
        print("⚠️ Firewall control disabled, skipping firewall control")
        return True
    
    unifi_rule_name = get_setting("UNIFI_RULE_NAME", required=False)
    
    if not unifi_rule_name:
        print("⚠️ UniFi settings not configured, skipping firewall control")
        return True
    
    own_session = False
    if session is None:
        unifi_host = get_setting("UNIFI_HOST", required=False)
        unifi_user = get_setting("UNIFI_USER", required=False)
        unifi_pass = get_setting("UNIFI_PASS", required=False)
        
        if not all([unifi_host, unifi_user, unifi_pass]):
            print("⚠️ UniFi settings not configured, skipping firewall control")
            return True
            
        base_url = f"https://{unifi_host}"
        session = requests.Session()
        session.verify = get_unifi_verify_ssl()
        own_session = True
        print(f"🔹 Connecting to UniFi Controller ({unifi_host})...")

    try:
        if own_session:
            resp = login_unifi_with_retry(session, base_url, unifi_user, unifi_pass)
            
            if not resp or resp.status_code != 200:
                if resp: print(f"❌ UniFi Login Failed: HTTP {resp.status_code}")
                return False
                
            csrf_token = resp.headers.get("x-csrf-token")
            if csrf_token:
                session.headers.update({"X-CSRF-Token": csrf_token})

    except Exception as e:
        print(f"❌ UniFi Connection Error: {e}")
        return False

    pf_url = f"{base_url}/proxy/network/api/s/default/rest/portforward"
    
    try:
        resp = unifi_request(session, "GET", pf_url)
        if not resp or resp.status_code != 200:
            return False
        rules = resp.json().get("data", [])
    except Exception as e:
        print(f"❌ Error fetching rules: {e}")
        return False

    target_rule = next((r for r in rules if r.get("name") == unifi_rule_name), None)

    if not target_rule:
        print(f"❌ Error: UniFi Rule '{unifi_rule_name}' not found!")
        return False

    # Track what changed
    changes = []
    if target_rule["enabled"] != enable_rule:
        changes.append(f"enabled={'ENABLED' if enable_rule else 'DISABLED'}")
    
    # Update the rule
    target_rule["enabled"] = enable_rule
    
    # Update the WAN port if provided
    if forward_port is not None and enable_rule:
        old_port = target_rule.get("dst_port", "unknown")
        if old_port != forward_port:
            target_rule["dst_port"] = str(forward_port)
            changes.append(f"port={forward_port}")
            print(f"   Updating WAN port: {old_port} → {forward_port}")
    
    if not changes:
        print(f"   UniFi rule is already configured correctly.")
        return True

    try:
        rule_id = target_rule["_id"]
        resp = unifi_request(session, "PUT", f"{pf_url}/{rule_id}", json=target_rule)
        
        if resp and resp.status_code == 200:
            print(f"✅ UniFi Rule '{unifi_rule_name}' updated: {', '.join(changes)}.")
            return True
        else:
            msg = resp.text if resp else "No response"
            print(f"❌ Failed to update rule: {msg}")
            return False
    except Exception as e:
        print(f"❌ Error updating rule: {e}")
        return False
    finally:
        if own_session:
            logout_unifi(session, base_url)

# Default Cloudflare Origin Rule action type
DEFAULT_ORIGIN_ACTION = "route"

def check_service_health(target_url, timeout=None):
    """Check if service target is reachable."""
    if not target_url:
        return False
    try:
        if timeout is None:
            timeout = int(get_setting("HEALTH_CHECK_TIMEOUT", required=False) or 1)
            
        requests.get(target_url, timeout=timeout, verify=False)
        return True
    except (requests.RequestException, ValueError):
        return False

# Global cache for health status
HEALTH_STATUS_CACHE = {}

def send_discord_notification(message, title=None, color=None, webhook_url=None, msg_type='system'):
    """Send a notification to Discord via Webhook."""
    # Check notification settings
    if msg_type == 'health' and db.get_setting('NOTIFY_EVENTS_HEALTH', '1') == '0':
        return
    if msg_type == 'system' and db.get_setting('NOTIFY_EVENTS_SYSTEM', '1') == '0':
        return
    
    if not webhook_url:
        webhook_url = get_setting("DISCORD_WEBHOOK_URL", required=False)
        
    if not webhook_url:
        return

    version = get_version()

    embed = {
        "description": message,
        "color": color or 0x3498db,
        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "footer": {
                            "text": f"RouteGhost v{get_version()}"
                        },    }
    
    if title:
        embed["title"] = title

    payload = {
        "embeds": [embed]
    }
    
    try:
        requests.post(webhook_url, json=payload, timeout=5)
    except Exception as e:
        print(f"⚠️ Failed to send Discord notification: {e}")

def perform_health_check():
    """Perform a single health check iteration."""
    try:
        timeout = int(get_setting("HEALTH_CHECK_TIMEOUT", required=False) or 1)
    except (ValueError, TypeError):
        timeout = 1
        
    try:
        # Use a new connection for the thread/request
        services = db.get_all_services()
        with _cache_lock:
            for service in services:
                if service['enabled']:
                    is_healthy = check_service_health(service['target_url'], timeout=timeout)
                    
                    # Check for status change
                    prev_healthy = HEALTH_STATUS_CACHE.get(service['id'])
                    
                    # Only notify if we had a previous status (to avoid startup spam) 
                    # AND the status has changed
                    if prev_healthy is not None and prev_healthy != is_healthy:
                        if is_healthy:
                            send_discord_notification(f"✅ Service **{service['name']}** is back ONLINE.", title="Health Alert: Recovered", color=0x2ecc71, msg_type='health')
                        else:
                            send_discord_notification(f"⚠️ Service **{service['name']}** is UNHEALTHY.", title="Health Alert: Failure", color=0xe74c3c, msg_type='health')
                        
                        # Update MQTT on health change
                        mqtt_manager.publish_state(service, True, healthy=is_healthy)
                    
                    HEALTH_STATUS_CACHE[service['id']] = is_healthy
                else:
                    # Remove from cache if disabled
                    if service['id'] in HEALTH_STATUS_CACHE:
                        del HEALTH_STATUS_CACHE[service['id']]
        return True
    except Exception as e:
        logger.warning("Health check error: %s", e)
        return False

def health_check_loop():
    """Background loop to check service health periodically."""
    print("🔹 Starting background health check service...")
    while not _shutdown_event.is_set():
        try:
            interval = int(get_setting("HEALTH_CHECK_INTERVAL", required=False) or 60)
        except (ValueError, TypeError):
            interval = 60
            
        if interval < 10: interval = 10
        
        perform_health_check()
        
        _shutdown_event.wait(timeout=interval)

def start_health_check_thread():
    thread = threading.Thread(target=health_check_loop, daemon=True)
    thread.start()

def port_rotation_loop():
    """Background loop to rotate firewall port periodically."""
    print("🔹 Starting background port rotation service...")
    while not _shutdown_event.is_set():
        try:
            interval_mins = int(get_setting("PORT_ROTATION_INTERVAL", required=False) or 0)
            if interval_mins > 0:
                # Check if we have active services before rotating
                services = db.get_all_services()
                if any(s['enabled'] for s in services):
                    rotate_firewall_port()
                _shutdown_event.wait(timeout=interval_mins * 60)
            else:
                _shutdown_event.wait(timeout=60)
        except Exception as e:
            logger.warning("Port rotation error: %s", e)
            _shutdown_event.wait(timeout=60)

def start_port_rotation_thread():
    thread = threading.Thread(target=port_rotation_loop, daemon=True)
    thread.start()

def get_status():
    """Get overall system status"""
    r = get_redis()
    if not r:
        return {"error": "Redis connection failed"}
    
    # Check UniFi Status
    firewall_status = "UNKNOWN"
    firewall_port = None
    rule_info = check_unifi_rule()
    if rule_info:
        if rule_info["enabled"] is True:
            firewall_status = "OPEN"
        elif rule_info["enabled"] is False:
            firewall_status = "CLOSED"
        firewall_port = rule_info.get("port")
    
    # Get all services and their status
    services = db.get_all_services()
    active_services = []
    
    for service in services:
        current_rule = r.get(f"traefik/http/routers/{service['router_name']}/rule")
        if current_rule:
            host = current_rule.replace("Host(`", "").replace("`)", "")
            
            # Check health
            is_healthy = HEALTH_STATUS_CACHE.get(service['id'], True)
            
            active_services.append({
                "id": service['id'],
                "name": service['name'],
                "hostname": f"https://{host}",
                "status": "ONLINE",
                "healthy": is_healthy
            })
    
    return {
        "firewall": firewall_status,
        "firewall_port": firewall_port,
        "active_services": active_services,
        "total_services": len(services),
        "active_count": len(active_services),
        "public_ip": get_public_ip()
    }

def get_service_status(service_id):
    """Get status of a specific service"""
    service = db.get_service(service_id)
    if not service:
        return None
    
    r = get_redis()
    if not r:
        return {"error": "Redis connection failed"}
    
    current_rule = r.get(f"traefik/http/routers/{service['router_name']}/rule")
    
    if current_rule:
        host = current_rule.replace("Host(`", "").replace("`)", "")
        
        # Check actual Redis configuration vs expected
        actual_target_url = r.get(f"traefik/http/services/{service['service_name']}/loadbalancer/servers/0/url")
        expected_target_url = service['target_url']
        
        # Check for configuration mismatch
        config_mismatch = actual_target_url != expected_target_url
        
        result = {
            "status": "ONLINE",
            "hostname": host,
            "full_url": f"https://{host}",
            "service": service,
            "config_mismatch": config_mismatch
        }
        
        # Include diagnostic info if there's a mismatch
        if config_mismatch:
            result["actual_target_url"] = actual_target_url
            result["expected_target_url"] = expected_target_url
        
        # Include port if available
        if service.get('current_port'):
            result['port'] = service['current_port']
        return result
    else:
        return {
            "status": "OFFLINE",
            "service": service
        }

def turn_off_service(service_id, actor=None, quiet=False, skip_unifi=False):
    """Turn off a specific service. Uses _service_ops_lock to serialize concurrent operations."""
    service = db.get_service(service_id)
    if not service:
        return {"error": "Service not found"}
    
    with _service_ops_lock:
        return _turn_off_service_inner(service, actor=actor, quiet=quiet, skip_unifi=skip_unifi)

def _turn_off_service_inner(service, actor=None, quiet=False, skip_unifi=False):
    service_id = service['id']
    if not actor:
        if has_request_context() and hasattr(g, 'actor'):
            actor = g.actor
        else:
            actor = "Background Task"

    if not service.get('enabled'):
        print(f"ℹ️ ({actor}) {service['name']} is already offline. Ignoring request.")
        return {"message": f"{service['name']} is already offline"}

    if not quiet:
        print(f"\n🛑 === ({actor}) SHUTTING DOWN {service['name']} ===")
    r = get_redis()
    if not r:
        return {"error": "Redis connection failed"}

    router_name = service['router_name']
    service_name = service['service_name']
    subdomain_prefix = service['subdomain_prefix']
    
    print("🔹 Removing Traefik Router...")
    r.delete(f"traefik/http/routers/{router_name}/rule")
    r.delete(f"traefik/http/routers/{router_name}/service")
    r.delete(f"traefik/http/routers/{router_name}/entryPoints/0")
    r.delete(f"traefik/http/routers/{router_name}/tls/certResolver")
    r.delete(f"traefik/http/services/{service_name}/loadbalancer/servers/0/url")

    # Determine Routing Mode
    routing_mode = routing.get_routing_mode(service)
    unifi_session = None
    unifi_base_url = None

    if routing_mode == 'unifi' and not skip_unifi:
        # Prepare UniFi Session for multiple operations
        unifi_host = get_setting("UNIFI_HOST", required=False)
        unifi_user = get_setting("UNIFI_USER", required=False)
        unifi_pass = get_setting("UNIFI_PASS", required=False)
        
        if all([unifi_host, unifi_user, unifi_pass]):
            unifi_base_url = f"https://{unifi_host}"
            unifi_session = requests.Session()
            unifi_session.verify = get_unifi_verify_ssl()
            print(f"🔹 Connecting to UniFi Controller ({unifi_host})...")
            resp = login_unifi_with_retry(unifi_session, unifi_base_url, unifi_user, unifi_pass)
            if resp and resp.status_code == 200:
                csrf_token = resp.headers.get("x-csrf-token")
                if csrf_token:
                    unifi_session.headers.update({"X-CSRF-Token": csrf_token})

        remaining_count = count_active_routers()
        print(f"   Active routers remaining: {remaining_count}")

        if remaining_count == 0:
            print("   No other services active. Closing firewall...")
            toggle_unifi(False, session=unifi_session, base_url=unifi_base_url)
        else:
            print("   ⚠️ Other services are still active. Firewall will remain OPEN.")

    elif routing_mode == 'vps':
        print("🔹 Cleaning up VPS forwarding...")
        try:
            routing.VPSManager.cleanup_port_forward(443)
        except Exception as e:
            print(f"   ⚠️ Failed to cleanup VPS: {e}")
        
        # Check active services (excluding this one)
        all_services = db.get_all_services()
        other_active = [s for s in all_services if s['enabled'] and s['id'] != service_id]
        
        if not other_active:
            print("🔹 Stopping WireGuard...")
            routing.WireGuardManager.down()

    print("🔹 Cleaning up DNS records...")
    if service.get('random_suffix', 1):
        # Random mode: Clean up any records matching prefix- pattern
        records = cf_request("GET", f"dns_records?type=A&name_contains={subdomain_prefix}-")
        if records:
            count = 0
            for record in records.get('result', []):
                if should_delete_dns_record(record['name'], subdomain_prefix):
                    print(f"   Deleting: {record['name']}")
                    cf_request("DELETE", f"dns_records/{record['id']}")
                    count += 1
            if count == 0:
                print("   No DNS records found to clean.")
    else:
        # Static mode: Clean up the specific static record
        domain_root = get_setting("DOMAIN_ROOT")
        if domain_root:
            full_hostname = f"{subdomain_prefix}.{domain_root}"
            records = cf_request("GET", f"dns_records?type=A&name={full_hostname}")
            if records and records.get('result'):
                for record in records['result']:
                    print(f"   Deleting: {record['name']}")
                    cf_request("DELETE", f"dns_records/{record['id']}")
            else:
                print("   No DNS records found to clean.")

    if routing_mode == 'unifi':
        print("🔹 Cleaning up Origin Rule...")
        origin_rule_name = get_setting("ORIGIN_RULE_NAME", required=False) or "Service Rotation"
        
        # Get all currently enabled services to build the list of hostnames
        all_services = db.get_all_services()
        # Exclude the service being turned off
        active_hostnames = [s['current_hostname'] for s in all_services if s['enabled'] and s['current_hostname'] and s['id'] != service_id]
        
        ruleset_data = cf_request("GET", "rulesets/phases/http_request_origin/entrypoint")
        if ruleset_data:
            rules = ruleset_data.get('result', {}).get('rules', [])
            target_rule = next((r for r in rules if r.get('description') == origin_rule_name), None)
            ruleset_id = ruleset_data.get('result', {}).get('id')

            if target_rule:
                if active_hostnames:
                    # Update the rule with the remaining hostnames
                    host_list = " ".join(f'"{h}"' for h in active_hostnames)
                    new_expression = f"http.host in {{{host_list}}}"
                    
                    update_data = {
                        "expression": new_expression,
                        "description": origin_rule_name,
                        "action": target_rule['action'],
                        "action_parameters": target_rule['action_parameters'],
                        "enabled": True
                    }
                    cf_request("PATCH", f"rulesets/{ruleset_id}/rules/{target_rule['id']}", update_data)
                    print(f"   Updated Origin Rule with remaining hosts: {origin_rule_name}")
                else:
                    # No active services left, delete the rule
                    cf_request("DELETE", f"rulesets/{ruleset_id}/rules/{target_rule['id']}")
                    print(f"   Deleted Origin Rule as no services are active: {origin_rule_name}")
            else:
                print(f"   No Origin Rule found to clean up.")

    # Update database - clear hostname and port
    db.update_service_status(service_id, False, None, None)
    # Update MQTT
    mqtt_manager.publish_state(service_id, False, healthy=HEALTH_STATUS_CACHE.get(service_id, True))
    
    # Sync UniFi Groups (remove this service's IP/Port if not used by others)
    if routing_mode == 'unifi' and not skip_unifi:
        sync_unifi_groups(session=unifi_session, base_url=unifi_base_url)
        if unifi_session:
            logout_unifi(unifi_session, unifi_base_url)
    
    print(f"✅ {service['name']} ACCESS DISABLED.\n")
    return {"message": f"{service['name']} disabled successfully"}

def rotate_firewall_port(actor=None):
    """
    Rotates the external firewall port for all active services without restarting them.
    Updates UniFi Port Forward and Cloudflare Origin Rule.
    Uses _service_ops_lock to serialize concurrent operations.
    """
    with _service_ops_lock:
        return _rotate_firewall_port_inner(actor=actor)

def _rotate_firewall_port_inner(actor=None):
    print(f"\n🔄 === ({actor if actor else 'System'}) ROTATING FIREWALL PORT ===")
    
    # 1. Check for active services
    services = db.get_all_services()
    active_services = [s for s in services if s['enabled']]
    
    if not active_services:
        print("   No active services. Skipping rotation.")
        return {"error": "No active services"}

    # 2. Generate new port
    new_port = generate_random_port()
    print(f"   New Port: {new_port}")

    # 3. Update UniFi Firewall
    unifi_session = None
    unifi_base_url = None
    unifi_host = get_setting("UNIFI_HOST", required=False)
    unifi_user = get_setting("UNIFI_USER", required=False)
    unifi_pass = get_setting("UNIFI_PASS", required=False)
    
    if all([unifi_host, unifi_user, unifi_pass]):
        unifi_base_url = f"https://{unifi_host}"
        unifi_session = requests.Session()
        unifi_session.verify = get_unifi_verify_ssl()
        resp = login_unifi_with_retry(unifi_session, unifi_base_url, unifi_user, unifi_pass)
        if resp and resp.status_code == 200:
            csrf_token = resp.headers.get("x-csrf-token")
            if csrf_token:
                unifi_session.headers.update({"X-CSRF-Token": csrf_token})
    
    if not toggle_unifi(True, new_port, session=unifi_session, base_url=unifi_base_url):
        if unifi_session: logout_unifi(unifi_session, unifi_base_url)
        return {"error": "Failed to update UniFi firewall"}

    # 4. Update Cloudflare Origin Rule
    origin_rule_name = get_setting("ORIGIN_RULE_NAME", required=False) or "Service Rotation"
    ruleset_data = cf_request("GET", "rulesets/phases/http_request_origin/entrypoint")
    
    if ruleset_data:
        rules = ruleset_data.get('result', {}).get('rules', [])
        target_rule = next((r for r in rules if r.get('description') == origin_rule_name), None)
        ruleset_id = ruleset_data.get('result', {}).get('id')

        if target_rule:
            # Keep existing expression, just update the port
            update_data = {
                "expression": target_rule['expression'],
                "description": origin_rule_name,
                "action": target_rule['action'],
                "action_parameters": target_rule['action_parameters'],
                "enabled": True
            }
            
            # Update port in action parameters
            if 'origin' not in update_data['action_parameters']:
                update_data['action_parameters']['origin'] = {}
            update_data['action_parameters']['origin']['port'] = new_port

            cf_request("PATCH", f"rulesets/{ruleset_id}/rules/{target_rule['id']}", update_data)
            print(f"   Updated Origin Rule port to {new_port}")
        else:
            print("   ⚠️ Origin Rule not found, skipping Cloudflare update")
    
    # 5. Update Database
    for service in active_services:
        db.update_service_status(service['id'], True, service['current_hostname'], new_port)

    # 6. Sync UniFi Groups (to ensure IP/Port groups are consistent, though port group might not change if it tracks internal ports)
    sync_unifi_groups(session=unifi_session, base_url=unifi_base_url)

    if unifi_session:
        logout_unifi(unifi_session, unifi_base_url)
        
    print("✅ Firewall port rotated successfully.")
    return {"success": True, "port": new_port}

def turn_on_service(service_id, force=False, actor=None, preferred_port=None, quiet=False, skip_unifi=False):
    """Turn on a specific service. Uses _service_ops_lock to serialize concurrent operations."""
    service = db.get_service(service_id)
    if not service:
        return {"error": "Service not found"}
    
    with _service_ops_lock:
        return _turn_on_service_inner(service, force=force, actor=actor, preferred_port=preferred_port, quiet=quiet, skip_unifi=skip_unifi)

def _turn_on_service_inner(service, force=False, actor=None, preferred_port=None, quiet=False, skip_unifi=False):
    service_id = service['id']
    if not actor:
        if has_request_context() and hasattr(g, 'actor'):
            actor = g.actor
        else:
            actor = "Background Task"

    if service.get('enabled') and not force:
        print(f"ℹ️ ({actor}) {service['name']} is already online. Ignoring request.")
        
        response = {
            "message": f"{service['name']} is already online",
            "url": f"https://{service.get('current_hostname')}",
            "port": service.get('current_port')
        }

        if service.get('show_regex', 1):
            domain_root = get_setting("DOMAIN_ROOT")
            regex_pattern = f"^https:\\/\\/{service['subdomain_prefix']}-[a-z0-9]{{8}}\\."
            if domain_root:
                regex_pattern += domain_root.replace('.', '\\.')
            regex_pattern += ".*$"
            response["regex"] = regex_pattern
        
        return response
    
    if not quiet:
        print(f"\n🚀 === ({actor}) ENABLING {service['name']} ===")
    
    # Determine Routing Mode
    routing_mode = routing.get_routing_mode(service)
    print(f"🔹 Routing Mode: {routing_mode.upper()}")
    
    # Check if any other service is already enabled and get its port
    # All active services share the same firewall port
    all_services = db.get_all_services()
    active_service_ports = set()
    active_service_with_port = None
    
    for other_service in all_services:
        if other_service['id'] != service_id and other_service['enabled']:
            port = other_service.get('current_port')
            if port:
                active_service_ports.add(port)
                if active_service_with_port is None:
                    active_service_with_port = other_service
    
    # Validate that all active services are using the same port
    if len(active_service_ports) > 1:
        print(f"⚠️ Warning: Multiple different ports detected across active services: {active_service_ports}")
        print(f"   This may indicate a configuration issue. Using port from {active_service_with_port['name']}")
    
    # Port Selection logic:
    # 1. Use preferred_port if provided (e.g. from rotation)
    # 2. Re-use existing port from another active service
    # 3. Generate new random port
    if preferred_port:
        active_service_port = preferred_port
        print(f"   Using preferred port: {active_service_port}")
    elif active_service_with_port:
        active_service_port = active_service_with_port['current_port']
        print(f"   Reusing existing port from {active_service_with_port['name']}: {active_service_port}")
    else:
        active_service_port = generate_random_port()
        print(f"   Generated new random port: {active_service_port}")
        
    random_port = active_service_port  # Use the shared port

    # === FIREWALL & ROUTING SETUP ===
    unifi_session = None
    unifi_base_url = None

    if routing_mode == 'unifi' and not skip_unifi:
        # Traditional Cloudflare + UniFi
        unifi_host = get_setting("UNIFI_HOST", required=False)
        unifi_user = get_setting("UNIFI_USER", required=False)
        unifi_pass = get_setting("UNIFI_PASS", required=False)
        
        if all([unifi_host, unifi_user, unifi_pass]):
            unifi_base_url = f"https://{unifi_host}"
            unifi_session = requests.Session()
            unifi_session.verify = get_unifi_verify_ssl()
            print(f"🔹 Connecting to UniFi Controller ({unifi_host})...")
            resp = login_unifi_with_retry(unifi_session, unifi_base_url, unifi_user, unifi_pass)
            if resp and resp.status_code == 200:
                csrf_token = resp.headers.get("x-csrf-token")
                if csrf_token:
                    unifi_session.headers.update({"X-CSRF-Token": csrf_token})
        
        # Only toggle if new port or ensuring open
        if not active_service_with_port or force:
             if not toggle_unifi(True, active_service_port, session=unifi_session, base_url=unifi_base_url):
                print("⚠️ Warning: UniFi update failed, but proceeding...")
    
    elif routing_mode == 'vps':
        # VPS Gateway + WireGuard
        print("🔹 Setting up WireGuard Connection...")
        success, msg = routing.WireGuardManager.up()
        if not success:
            return {"error": f"WireGuard failed: {msg}"}
        print(f"   WireGuard: {msg}")

        print("🔹 Configuring VPS Port Forwarding...")
        local_ip = get_setting('WG_CLIENT_ADDRESS').split('/')[0]
        try:
            # We forward Public 443 -> Local WG IP : Random Port
            routing.VPSManager.forward_port(443, local_ip, random_port)
            print(f"   Forwarded VPS:443 -> {local_ip}:{random_port}")
        except Exception as e:
            return {"error": f"VPS configuration failed: {e}"}

    domain_root = get_setting("DOMAIN_ROOT")
    if not domain_root:
        return {"error": "DOMAIN_ROOT not configured"}
    
    if service.get('random_suffix', 1):
        random_part = ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(8))
        new_subdomain = f"{service['subdomain_prefix']}-{random_part}"
    else:
        new_subdomain = service['subdomain_prefix']
        
    full_hostname = f"{new_subdomain}.{domain_root}"
    
    # Determine IP for DNS
    if routing_mode == 'vps':
        public_ip = get_setting('VPS_HOST') # The VPS IP
        proxied = False # Grey cloud
    else:
        public_ip = get_public_ip()
        proxied = True # Orange cloud
    
    print(f"   Service: {service['name']}")
    print(f"   Target:  {full_hostname}")
    print(f"   Port:    {random_port}")
    print(f"   IP:      {public_ip} (Proxied: {proxied})")

    print("🔹 Creating/Updating DNS Record...")
    # Check if record exists first (important for static mode to avoid duplicates/errors)
    existing_records = cf_request("GET", f"dns_records?type=A&name={full_hostname}")
    dns_data = {"type": "A", "name": new_subdomain, "content": public_ip, "ttl": 1, "proxied": proxied}
    
    if existing_records and existing_records.get('result'):
        # Update existing record
        record_id = existing_records['result'][0]['id']
        print(f"   Updating existing DNS record: {full_hostname}")
        result = cf_request("PUT", f"dns_records/{record_id}", dns_data)
    else:
        # Create new record
        print(f"   Creating new DNS record: {full_hostname}")
        result = cf_request("POST", "dns_records", dns_data)
        
    if not result:
        return {"error": "Failed to create DNS record"}

    if routing_mode == 'unifi':
        print("🔹 Updating Origin Rule...")
        origin_rule_name = get_setting("ORIGIN_RULE_NAME", required=False) or "Service Rotation"
        
        # Get all currently enabled services to build the list of hostnames
        all_services = db.get_all_services()
        active_hostnames = [s['current_hostname'] for s in all_services if s['enabled'] and s['current_hostname']]
        
        # Add the new hostname to the list
        if full_hostname not in active_hostnames:
            active_hostnames.append(full_hostname)
        
        # Format for Cloudflare API
        host_list = " ".join(f'"{h}"' for h in active_hostnames)
        new_expression = f"http.host in {{{host_list}}}"
        
        ruleset_data = cf_request("GET", "rulesets/phases/http_request_origin/entrypoint")
        
        if ruleset_data:
            rules = ruleset_data.get('result', {}).get('rules', [])
            target_rule = next((r for r in rules if r.get('description') == origin_rule_name), None)
            ruleset_id = ruleset_data.get('result', {}).get('id')

            if target_rule:
                # Update existing rule
                update_data = {
                    "expression": new_expression,
                    "description": origin_rule_name,
                    "action": target_rule['action'],
                    "action_parameters": target_rule['action_parameters'],
                    "enabled": True
                }
                # Also update the port in the action parameters
                if 'origin' not in update_data['action_parameters']:
                    update_data['action_parameters']['origin'] = {}
                update_data['action_parameters']['origin']['port'] = random_port

                cf_request("PATCH", f"rulesets/{ruleset_id}/rules/{target_rule['id']}", update_data)
                print(f"   Updated existing Origin Rule: {origin_rule_name}")
            else:
                # Create a new rule
                new_rule_data = {
                    "expression": new_expression,
                    "description": origin_rule_name,
                    "action": "route",
                    "action_parameters": {
                        "origin": {
                            "port": random_port
                        }
                    },
                    "enabled": True
                }
                
                rules_data = {
                    "rules": rules + [new_rule_data]
                }
                
                result = cf_request("PUT", f"rulesets/{ruleset_id}", rules_data)
                if result:
                    print(f"   Created new Origin Rule: {origin_rule_name}")
                else:
                    print(f"   ⚠️ Warning: Failed to create Origin Rule")


    # Only clean up old random records if we are in random mode
    if service.get('random_suffix', 1):
        print("🔹 Cleaning old DNS for this service...")
        records = cf_request("GET", f"dns_records?type=A&name_contains={service['subdomain_prefix']}-")
        if records:
            for record in records.get('result', []):
                if should_delete_dns_record(record['name'], service['subdomain_prefix'], full_hostname):
                    print(f"   Deleting old DNS record: {record['name']}")
                    cf_request("DELETE", f"dns_records/{record['id']}")

    print("🔹 Updating Traefik...")
    r = get_redis()
    if not r:
        return {"error": "Redis connection failed"}
    
    router_name = service['router_name']
    service_name = service['service_name']
    target_url = service['target_url']
    
    r.set(f"traefik/http/routers/{router_name}/rule", f"Host(`{full_hostname}`)")
    r.set(f"traefik/http/routers/{router_name}/service", service_name)
    r.set(f"traefik/http/routers/{router_name}/entryPoints/0", "https")
    r.set(f"traefik/http/routers/{router_name}/tls/certResolver", "main")
    r.set(f"traefik/http/services/{service_name}/loadbalancer/servers/0/url", target_url)

    # Update database with hostname and port
    db.update_service_status(service_id, True, full_hostname, random_port)
    # Update MQTT
    mqtt_manager.publish_state(service_id, True, healthy=HEALTH_STATUS_CACHE.get(service_id, True))

    # Sync UniFi Groups (add this service's IP/Port)
    if routing_mode == 'unifi' and not skip_unifi:
        sync_unifi_groups(session=unifi_session, base_url=unifi_base_url)

        # Check if port is open (brief delay to allow firewall rule to propagate)
        print("🔹 Verifying port accessibility...")
        time.sleep(1)  # Brief 1-second delay to allow firewall rule to propagate
        port_check = check_port_open(random_port, session=unifi_session, base_url=unifi_base_url)
        
        if unifi_session:
            logout_unifi(unifi_session, unifi_base_url)
        
        port_open = port_check.get("open")
        if port_open is True:
            print(f"✅ Port {random_port} verified as accessible")
            port_status = "verified"
        elif port_open is None:
            error_msg = port_check.get("error", "Unknown error")
            print(f"⚠️ Port status unknown: {error_msg}")
            port_status = "unknown"
        else:
            error_msg = port_check.get("error", "Unknown error")
            print(f"⚠️ Port verification failed: {error_msg}")
            port_status = "unverified"
    elif routing_mode == 'unifi' and skip_unifi:
        # If we skipped unifi because of rotation, assume port is still verified/ok
        port_status = "verified" 
    else:
        # For VPS mode, we can't easily check port open status from here (it's remote)
        # unless we probe it from outside or trust the SSH command.
        port_status = "assumed_open"

    print(f"✅ SUCCESS! {service['name']} live at: https://{full_hostname} (Port: {random_port})\n")
    
    response = {
        "message": f"{service['name']} enabled successfully", 
        "url": f"https://{full_hostname}", 
        "port": random_port,
        "port_status": port_status
    }

    if service.get('show_regex', 1):
        # Generate regex pattern for UI
        regex_pattern = f"^https:\\/\\/{service['subdomain_prefix']}-[a-z0-9]{{8}}\\."
        if domain_root:
            regex_pattern += domain_root.replace('.', '\\.')
        regex_pattern += ".*$"
        response["regex"] = regex_pattern

    return response

def rotate_service(service_id, actor=None):
    """Rotate URL for a service (turn off then on) while preserving the port"""
    service = db.get_service(service_id)
    if not service:
        return {"error": "Service not found"}
    
    if not service['enabled']:
        return {"error": "Service is not currently enabled"}
    
    current_port = service.get('current_port')
    print(f"\n🔄 === ({actor if actor else 'System'}) ROTATING {service['name']} URL ===")
    print(f"🔹 Preserving port: {current_port}")
    
    # Skip UniFi work during rotation as the internal IP/Port didn't change 
    # and the firewall port is being preserved.
    turn_off_service(service_id, actor=actor, quiet=True, skip_unifi=True)
    return turn_on_service(service_id, actor=actor, preferred_port=current_port, quiet=True, skip_unifi=True)

# Legacy functions for backward compatibility with CLI
# Removed cmd_off and cmd_on as they are no longer supported

# ================= API / MAIN =================
app = Flask(__name__)

# CSRF Protection
app.config['WTF_CSRF_CHECK_DEFAULT'] = False # We will manually check to exempt API keys
csrf = CSRFProtect(app)

# Session security configuration
from datetime import timedelta
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# SESSION_COOKIE_SECURE enabled when not in debug mode (requires HTTPS)
if not app.debug:
    app.config['SESSION_COOKIE_SECURE'] = True

@app.before_request
def check_csrf_protection():
    """Enforce CSRF protection globally, but exempt API key requests."""
    if request.method in ["POST", "PUT", "PATCH", "DELETE"]:
        # If API Key is present and valid-looking (we don't validate it fully here, 
        # just check presence to skip CSRF, auth decorator handles the rest), skip CSRF.
        # However, to be safe, we only skip if the header is present.
        # If an attacker forces a browser to send X-API-Key, they can bypass CSRF?
        # Browsers cannot send custom headers in cross-origin requests without CORS preflight.
        # So this is safe.
        if request.headers.get('X-API-Key'):
            return
        
        # Also exempt specific setup routes if needed, but they are browser based so should have CSRF.
        
        # Enforce CSRF
        csrf.protect()

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    # CSP: allow inline scripts (required by Flask-WTF and the existing templates)
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    return response

@app.after_request
def log_request(response):
    """Log every request with status code and add X-Request-ID header."""
    import time as _time
    request_id = getattr(g, "request_id", None)
    if request_id:
        response.headers["X-Request-ID"] = request_id
    if not request.path.startswith('/static'):
        duration = _time.monotonic() - getattr(g, '_request_start_time', _time.monotonic())
        log_level = logging.WARNING if response.status_code >= 400 else logging.INFO
        logger.log(
            log_level,
            "%s %s -> %s (%.3fs)",
            request.method,
            request.path,
            response.status_code,
            duration,
        )
    return response

@app.before_request
def start_request_timer():
    """Record request start time and assign a request ID for logging."""
    import time as _time
    g._request_start_time = _time.monotonic()
    g.request_id = uuid.uuid4().hex[:8]

# Use persistent secret key from environment or generate one and store it
SECRET_KEY_FILE = os.path.join(DATA_DIR, '.secret_key')
if os.path.exists(SECRET_KEY_FILE):
    with open(SECRET_KEY_FILE, 'rb') as f:
        app.secret_key = f.read()
else:
    app.secret_key = os.urandom(24)
    with open(SECRET_KEY_FILE, 'wb') as f:
        f.write(app.secret_key)
    # Lock down permissions on the secret key file
    try:
        os.chmod(SECRET_KEY_FILE, 0o600)
    except OSError:
        pass

# Track application startup time for initial setup window
STARTUP_TIME = time.time()
# Parse and validate SETUP_WINDOW_SECONDS (default 5 minutes, min 60s, max 1 hour)
try:
    SETUP_WINDOW_SECONDS = int(os.environ.get('SETUP_WINDOW_SECONDS', '300'))
    if SETUP_WINDOW_SECONDS < 60 or SETUP_WINDOW_SECONDS > 3600:
        print(f"⚠️ SETUP_WINDOW_SECONDS={SETUP_WINDOW_SECONDS} is outside recommended range (60-3600). Using default 300.")
        SETUP_WINDOW_SECONDS = 300
except ValueError:
    print(f"⚠️ Invalid SETUP_WINDOW_SECONDS value. Using default 300.")
    SETUP_WINDOW_SECONDS = 300

def is_in_setup_window():
    """Check if we're still in the setup window after startup."""
    return (time.time() - STARTUP_TIME) < SETUP_WINDOW_SECONDS

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Custom unauthorized handler
@login_manager.unauthorized_handler
def unauthorized():
    # During setup window with no users, redirect to login without message
    if db.count_users() == 0 and is_in_setup_window():
        return redirect(url_for('login'))
    # Otherwise show the default message
    flash('Please log in to access this page.', 'warning')
    return redirect(url_for('login'))

class User(UserMixin):
    def __init__(self, user_id, username):
        self.id = user_id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    user = db.get_user(int(user_id))
    if user:
        return User(user['id'], user['username'])
    return None

# API Key authentication support
def api_key_or_login_required(f):
    """Decorator that allows either API key or session-based authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for API key in header
        api_key = request.headers.get('X-API-Key')
        if api_key is not None:
            # API key header was provided (even if empty)
            # Strip whitespace and check if non-empty
            api_key = api_key.strip()
            if not api_key:
                # Empty API key
                return jsonify({"error": "Invalid API key"}), 401
            
            # Hash the provided key
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            # Check if key exists in database
            key_data = db.get_api_key_by_hash(key_hash)
            if key_data:
                # Update last used timestamp
                db.update_api_key_last_used(key_hash)
                # Set actor name for logging
                g.actor = f"API Key: {key_data['name']}"
                # Continue with the request
                return f(*args, **kwargs)
            else:
                # Invalid API key
                return jsonify({"error": "Invalid API key"}), 401
        
        # No API key, check for session-based authentication
        if current_user.is_authenticated:
            # Set actor name for logging
            g.actor = f"User: {current_user.username}"
            return f(*args, **kwargs)
        
        # Neither authentication method succeeded
        # For API requests (JSON expected), return 401
        # For browser requests, redirect to login
        if request.path.startswith('/api/'):
            return jsonify({"error": "Authentication required. Provide X-API-Key header or log in."}), 401
        else:
            return login_manager.unauthorized()
    
    return decorated_function

# ================= AUTHENTICATION =================
RP_ID = os.environ.get("RP_ID", "localhost")
RP_NAME = "RouteGhost"
ORIGIN = os.environ.get("ORIGIN", f"http://{RP_ID}:5001")

def get_expected_origin():
    """
    Get the expected origin for WebAuthn operations.
    For development, dynamically determine based on request to support localhost/127.0.0.1/0.0.0.0.
    For production with ORIGIN set, use the configured ORIGIN.
    """
    # If ORIGIN is explicitly set via environment variable (not default), use it
    if 'ORIGIN' in os.environ:
        return ORIGIN
    
    # For development (default config), dynamically determine origin from request
    # This allows localhost, 127.0.0.1, and other local addresses to work
    if has_request_context():
        scheme = request.scheme  # http or https
        host = request.host      # includes hostname and port
        return f"{scheme}://{host}"
    
    # Fallback to configured ORIGIN
    return ORIGIN

def get_expected_rp_id():
    """
    Get the expected RP ID for WebAuthn operations.
    For development with localhost-like addresses, use the hostname without port.
    """
    # If RP_ID is explicitly set via environment variable (not default), use it
    if 'RP_ID' in os.environ:
        return RP_ID
    
    # For development (default config), extract hostname from request
    # This supports localhost, 127.0.0.1, etc.
    if has_request_context():
        host = request.host
        # Use urlparse for robust hostname extraction that handles IPv6
        # request.host includes port, so we need to parse it properly
        # For IPv6: [::1]:5000 -> ::1
        # For IPv4: 127.0.0.1:5000 -> 127.0.0.1
        # For hostname: localhost:5000 -> localhost
        if host.startswith('['):
            # IPv6 address with brackets
            hostname = host.split(']')[0][1:]  # Remove brackets
        else:
            # IPv4 or hostname
            hostname = host.split(':')[0]
        # For development, accept localhost-like addresses
        # WebAuthn treats localhost, 127.0.0.1, and [::1] as secure contexts
        return hostname
    
    # Fallback to configured RP_ID
    return RP_ID

# Web UI Routes
@app.route('/login', methods=['GET'])
def login():
    # Check if this is initial setup (no users exist)
    is_setup = db.count_users() == 0
    
    # Check if we're in the setup window
    in_setup_window = is_in_setup_window() if is_setup else False
    
    # If setup required but window expired, show warning
    setup_expired = is_setup and not in_setup_window
    
    return render_template('login.html', 
                          is_setup=is_setup, 
                          in_setup_window=in_setup_window,
                          setup_expired=setup_expired)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@app.context_processor
def inject_version():
    return dict(version=get_version())

# WebAuthn routes
@app.route('/auth/register/begin', methods=['POST'])
def register_begin():
    # Only allow registration during setup window if no users exist
    if db.count_users() == 0 and not is_in_setup_window():
        return jsonify({"error": "Setup window expired. Please restart the application."}), 410
    
    # Rate limit: 10 attempts per minute per IP for WebAuthn
    if not check_webauthn_rate_limit(request.remote_addr):
        return jsonify({"error": "Too many attempts. Please try again later."}), 429
    
    data = request.json
    username = data.get('username')
    
    if not username:
        return jsonify({"error": "Username required"}), 400
    
    # Check if user already exists
    existing_user = db.get_user_by_username(username)
    if existing_user:
        return jsonify({"error": "Username already exists"}), 400
    
    # Generate temporary user ID for this registration attempt
    # We'll create the actual user only after successful verification
    temp_user_id = secrets.randbelow(9000000) + 1000000
    user_id_bytes = temp_user_id.to_bytes(4, byteorder='big')
    
    # Get dynamic RP_ID and origin for this request
    rp_id = get_expected_rp_id()
    origin = get_expected_origin()
    
    # Generate registration options
    registration_options = generate_registration_options(
        rp_id=rp_id,
        rp_name=RP_NAME,
        user_id=user_id_bytes,
        user_name=username,
        user_display_name=username,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED
        ),
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ]
    )
    
    # Store challenge, username, and context in session for verification
    session['registration_challenge'] = registration_options.challenge.hex()
    session['registration_username'] = username
    session['registration_rp_id'] = rp_id
    session['registration_origin'] = origin
    
    # Convert to JSON-serializable format
    options_json = options_to_json(registration_options)
    return jsonify(json.loads(options_json))

@app.route('/auth/register/complete', methods=['POST'])
def register_complete():
    data = request.json
    credential = data.get('credential')
    
    if not credential:
        return jsonify({"error": "Credential required"}), 400
    
    challenge = session.get('registration_challenge')
    username = session.get('registration_username')
    rp_id = session.get('registration_rp_id')
    origin = session.get('registration_origin')
    
    if not challenge or not username or not rp_id or not origin:
        # Log what's missing for debugging (server-side only)
        missing = []
        if not challenge: missing.append('challenge')
        if not username: missing.append('username')
        if not rp_id: missing.append('rp_id')
        if not origin: missing.append('origin')
        logger.warning("Registration failed: Missing session data: %s", ', '.join(missing))
        # Return generic error to client
        return jsonify({"error": "Invalid or expired session. Please try again."}), 400
    
    try:
        # Verify the registration response
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=bytes.fromhex(challenge),
            expected_rp_id=rp_id,
            expected_origin=origin,
        )
        
        # Create user only after successful verification
        user_id = db.add_user(username)
        
        # Store credential
        db.add_credential(
            user_id=user_id,
            credential_id=verification.credential_id.hex(),
            public_key=verification.credential_public_key.hex()
        )
        
        # Log the user in
        user = db.get_user(user_id)
        login_user(User(user['id'], user['username']))
        
        # Clear session
        session.pop('registration_challenge', None)
        session.pop('registration_username', None)
        session.pop('registration_rp_id', None)
        session.pop('registration_origin', None)
        
        return jsonify({"success": True})
        
    except Exception as e:
        # Clear session on error
        session.pop('registration_challenge', None)
        session.pop('registration_username', None)
        session.pop('registration_rp_id', None)
        session.pop('registration_origin', None)
        return jsonify({"error": str(e)}), 400

@app.route('/auth/login/begin', methods=['POST'])
def login_begin():
    data = request.json
    username = data.get('username')
    
    if not username:
        return jsonify({"error": "Username required"}), 400
    
    # Rate limit: 10 attempts per minute per IP for WebAuthn
    if not check_webauthn_rate_limit(request.remote_addr):
        return jsonify({"error": "Too many attempts. Please try again later."}), 429
    
    # Check if user exists
    user = db.get_user_by_username(username)
    if not user:
        return jsonify({"error": "Authentication failed"}), 400
    
    # Get user credentials
    credentials = db.get_credentials_for_user(user['id'])
    if not credentials:
        return jsonify({"error": "Authentication failed"}), 400
    
    # Get dynamic RP_ID and origin for this request
    rp_id = get_expected_rp_id()
    origin = get_expected_origin()
    
    # Generate authentication options
    allow_credentials = [
        PublicKeyCredentialDescriptor(id=bytes.fromhex(cred['credential_id']))
        for cred in credentials
    ]
    
    authentication_options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.PREFERRED
    )
    
    # Store challenge, user_id, and context in session for verification
    session['authentication_challenge'] = authentication_options.challenge.hex()
    session['authentication_user_id'] = user['id']
    session['authentication_rp_id'] = rp_id
    session['authentication_origin'] = origin
    
    # Convert to JSON-serializable format
    options_json = options_to_json(authentication_options)
    return jsonify(json.loads(options_json))

@app.route('/auth/login/complete', methods=['POST'])
def login_complete():
    data = request.json
    credential = data.get('credential')
    
    if not credential:
        return jsonify({"error": "Credential required"}), 400
    
    challenge = session.get('authentication_challenge')
    user_id = session.get('authentication_user_id')
    rp_id = session.get('authentication_rp_id')
    origin = session.get('authentication_origin')
    
    if not challenge or not user_id or not rp_id or not origin:
        # Log what's missing for debugging (server-side only)
        missing = []
        if not challenge: missing.append('challenge')
        if not user_id: missing.append('user_id')
        if not rp_id: missing.append('rp_id')
        if not origin: missing.append('origin')
        logger.warning("Authentication failed: Missing session data: %s", ', '.join(missing))
        # Return generic error to client
        return jsonify({"error": "Invalid or expired session. Please try again."}), 400
    
    try:
        # Convert credential ID from base64 URL-safe to hex to match database storage
        # The credential['rawId'] is base64 URL-safe encoded
        cred_id_base64 = credential.get('rawId', '')
        # Decode using urlsafe_b64decode which handles padding automatically
        cred_id_bytes = base64.urlsafe_b64decode(cred_id_base64 + '==')  # Add padding for safety
        cred_id_hex = cred_id_bytes.hex()
        
        # Get credential from database
        db_credential = db.get_credential_by_id(cred_id_hex)
        
        if not db_credential or db_credential['user_id'] != user_id:
            logger.warning("Credential lookup failed: cred_id_hex=%s, db_credential=%s", cred_id_hex, db_credential)
            return jsonify({"error": "Invalid credential"}), 400
        
        # Verify the authentication response
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=bytes.fromhex(challenge),
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=bytes.fromhex(db_credential['public_key']),
            credential_current_sign_count=db_credential['sign_count']
        )
        
        # Update sign count using the hex credential ID
        db.update_credential_sign_count(cred_id_hex, verification.new_sign_count)
        
        # Log the user in
        user = db.get_user(user_id)
        login_user(User(user['id'], user['username']))
        
        # Clear session
        session.pop('authentication_challenge', None)
        session.pop('authentication_user_id', None)
        session.pop('authentication_rp_id', None)
        session.pop('authentication_origin', None)
        
        return jsonify({"success": True})
        
    except Exception as e:
        # Clear session on error
        session.pop('authentication_challenge', None)
        session.pop('authentication_user_id', None)
        session.pop('authentication_rp_id', None)
        session.pop('authentication_origin', None)
        return jsonify({"error": str(e)}), 400

@app.route('/auth/login/password', methods=['POST'])
def login_password():
    """Handle username/password login."""
    # Check rate limit (5 attempts per minute)
    if not check_rate_limit(request.remote_addr):
        return jsonify({"error": "Too many login attempts. Please try again in a minute."}), 429

    data = request.get_json(silent=True) or request.form
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
        
    user = db.get_user_by_username(username)
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401
        
    pwhash = user.get('password_hash')
    if not pwhash or not check_password_hash(pwhash, password):
        return jsonify({"error": "Invalid credentials"}), 401
        
    # Check if 2FA is enabled
    if user.get('totp_secret') and pyotp:
        session['pre_2fa_user_id'] = user['id']
        return jsonify({"require_2fa": True})
        
    login_user(User(user['id'], user['username']))
    
    # Advise setup if not enabled
    return jsonify({"success": True, "setup_2fa": True})

@app.before_request
def check_2fa_enforcement():
    """Enforce 2FA globally if enabled."""
    if current_user.is_authenticated:
        # Skip for static resources and auth-related routes to prevent lockout loops
        if request.path.startswith('/static') or \
           request.path.startswith('/auth') or \
           request.path == '/logout' or \
           request.path == '/settings':
            return

        # Skip API routes (handled by their own auth decorators usually)
        if request.path.startswith('/api'):
            return

        enforce = db.get_setting('ENFORCE_2FA') == '1'
        user = db.get_user(current_user.id)
        
        # If enforced and no TOTP secret, redirect to settings
        if enforce and user and not user.get('totp_secret'):
            flash('⚠️ Two-Factor Authentication is enforced globally. Please set it up immediately to continue.', 'error')
            return redirect(url_for('settings'))

@app.route('/auth/login/2fa', methods=['POST'])
def login_2fa():
    """Verify 2FA code after password check."""
    if not pyotp:
        return jsonify({"error": "2FA support not available"}), 501
        
    user_id = session.get('pre_2fa_user_id')
    if not user_id:
        return jsonify({"error": "Session expired, please login again"}), 400
        
    # Rate limit: 5 attempts per 5 minutes per user
    if not check_2fa_rate_limit(str(user_id)):
        return jsonify({"error": "Too many 2FA attempts. Please wait 5 minutes before trying again."}), 429
        
    data = request.get_json(silent=True) or request.form
    code = data.get('code')
    
    if not code:
        return jsonify({"error": "Code required"}), 400
        
    user = db.get_user(user_id)
    if not user or not user.get('totp_secret'):
        return jsonify({"error": "User invalid"}), 400
        
    totp = pyotp.TOTP(user['totp_secret'])
    if totp.verify(code):
        # Clear rate limit on successful auth
        r = get_redis()
        if r:
            try:
                r.delete(f"rate_limit:2fa:{user_id}")
            except redis.RedisError:
                pass
        login_user(User(user['id'], user['username']))
        session.pop('pre_2fa_user_id', None)
        return jsonify({"success": True})
    
    # Check Recovery Codes
    unused_codes = db.get_unused_recovery_codes(user['id'])
    for rc in unused_codes:
        if check_password_hash(rc['code_hash'], code):
            db.mark_recovery_code_used(rc['id'])
            login_user(User(user['id'], user['username']))
            session.pop('pre_2fa_user_id', None)
            return jsonify({"success": True, "message": "Logged in with recovery code"})
    
    return jsonify({"error": "Invalid authentication code"}), 400

@app.route('/auth/password/change', methods=['POST'])
@login_required
def change_password():
    """Change password for the current user."""
    data = request.get_json(silent=True) or request.form
    new_password = data.get('new_password')
    
    if not new_password:
        return jsonify({"error": "New password required"}), 400
        
    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    
    # Password complexity requirements
    errors = []
    if not re.search(r'[A-Z]', new_password):
        errors.append("at least one uppercase letter")
    if not re.search(r'[a-z]', new_password):
        errors.append("at least one lowercase letter")
    if not re.search(r'[0-9]', new_password):
        errors.append("at least one number")
    if not re.search(r'[!@#$%^&*(),.?\":{}|<>]', new_password):
        errors.append("at least one special character (!@#$%^&*(),.?\":{}|<>)")
    if errors:
        return jsonify({"error": f"Password must contain {', '.join(errors)}"}), 400
        
    pwhash = generate_password_hash(new_password)
    try:
        db.update_user_password(current_user.id, pwhash)
        return jsonify({"success": True, "message": "Password updated successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/auth/passkey/add/begin', methods=['POST'])
@login_required
def add_passkey_begin():
    """Begin registration of a new passkey for logged-in user."""
    user = db.get_user(current_user.id)
    
    rp_id = get_expected_rp_id()
    origin = get_expected_origin()
    
    # Get existing credentials to exclude them
    existing_credentials = db.get_credentials_for_user(user['id'])
    exclude_credentials = [
        PublicKeyCredentialDescriptor(id=bytes.fromhex(cred['credential_id']))
        for cred in existing_credentials
    ]
    
    registration_options = generate_registration_options(
        rp_id=rp_id,
        rp_name=RP_NAME,
        user_id=str(user['id']).encode(),
        user_name=user['username'],
        user_display_name=user['username'],
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED
        ),
        exclude_credentials=exclude_credentials,
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ]
    )
    
    session['add_passkey_challenge'] = registration_options.challenge.hex()
    session['add_passkey_rp_id'] = rp_id
    session['add_passkey_origin'] = origin
    
    return jsonify(json.loads(options_to_json(registration_options)))

@app.route('/auth/passkey/add/complete', methods=['POST'])
@login_required
def add_passkey_complete():
    """Complete registration of a new passkey."""
    data = request.json
    credential = data.get('credential')
    
    if not credential:
        return jsonify({"error": "Credential required"}), 400
        
    challenge = session.get('add_passkey_challenge')
    rp_id = session.get('add_passkey_rp_id')
    origin = session.get('add_passkey_origin')
    
    if not challenge or not rp_id or not origin:
        return jsonify({"error": "Invalid or expired session"}), 400
        
    try:
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=bytes.fromhex(challenge),
            expected_rp_id=rp_id,
            expected_origin=origin,
        )
        
        db.add_credential(
            user_id=current_user.id,
            credential_id=verification.credential_id.hex(),
            public_key=verification.credential_public_key.hex()
        )
        
        # Clear session
        session.pop('add_passkey_challenge', None)
        session.pop('add_passkey_rp_id', None)
        session.pop('add_passkey_origin', None)
        
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/auth/passkey/delete/<credential_id>', methods=['POST'])
@login_required
def delete_passkey(credential_id):
    # Verify ownership
    cred = db.get_credential_by_id(credential_id)
    if not cred or cred['user_id'] != current_user.id:
        return jsonify({"error": "Credential not found or access denied"}), 404
    
    try:
        db.delete_credential(credential_id)
        return jsonify({"success": True})
    except Exception as e:
        print(f"Error deleting credential: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/auth/2fa/setup/begin', methods=['POST'])
@login_required
def setup_2fa_begin():
    """Generate TOTP secret and QR code."""
    if not pyotp or not qrcode:
        return jsonify({"error": "2FA libraries not installed"}), 501
        
    # Generate secret
    secret = pyotp.random_base32()
    session['totp_setup_secret'] = secret
    
    # Generate URI
    user = db.get_user(current_user.id)
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user['username'], issuer_name="Traefik Control")
    
    # Generate QR Code
    img = qrcode.make(uri)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return jsonify({
        "secret": secret,
        "qr_code": f"data:image/png;base64,{img_str}"
    })

@app.route('/auth/2fa/setup/complete', methods=['POST'])
@login_required
def setup_2fa_complete():
    """Verify and save TOTP secret."""
    if not pyotp:
        return jsonify({"error": "2FA support not available"}), 501
        
    data = request.get_json(silent=True)
    code = data.get('code')
    secret = session.get('totp_setup_secret')
    
    if not code or not secret:
        return jsonify({"error": "Invalid request"}), 400
        
    totp = pyotp.TOTP(secret)
    if totp.verify(code):
        db.update_user_totp(current_user.id, secret)
        session.pop('totp_setup_secret', None)
        return jsonify({"success": True})
    
    return jsonify({"error": "Invalid code"}), 400

@app.route('/auth/2fa/disable', methods=['POST'])
@login_required
def disable_2fa():
    """Disable 2FA for current user. Requires password verification."""
    data = request.get_json(silent=True) or request.form
    password = data.get('password')
    
    if not password:
        return jsonify({"error": "Password required to disable 2FA"}), 400
    
    user = db.get_user(current_user.id)
    if not user or not user.get('password_hash'):
        return jsonify({"error": "User account invalid"}), 400
    
    if not check_password_hash(user['password_hash'], password):
        return jsonify({"error": "Incorrect password"}), 403
    
    db.update_user_totp(current_user.id, None)
    return jsonify({"success": True})

@app.route('/auth/2fa/recovery-codes/generate', methods=['POST'])
@login_required
def generate_recovery_codes():
    """Generate new recovery codes."""
    # Delete existing codes
    db.delete_all_recovery_codes(current_user.id)
    
    codes = []
    # Generate 10 codes, 16 chars hex (~64 bits entropy each)
    for _ in range(10):
        code = secrets.token_hex(8)
        codes.append(code)
        # Hash and store
        db.add_recovery_code(current_user.id, generate_password_hash(code))
    
    return jsonify({"codes": codes})

@app.route('/')
def index():
    # Allow access during setup window if no users exist
    if db.count_users() == 0 and is_in_setup_window():
        return redirect(url_for('login'))
    
    # Otherwise require login
    if not current_user.is_authenticated:
        return login_manager.unauthorized()
    
    # Check if user needs onboarding
    user = db.get_user(current_user.id)
    if user and not user.get('onboarding_completed'):
        return redirect(url_for('onboarding'))
    
    services = db.get_all_services()
    
    # Inject health status
    for service in services:
        if service['enabled']:
            service['healthy'] = HEALTH_STATUS_CACHE.get(service['id'], True)
            
    settings = db.get_all_settings()
    
    # Get firewall status
    firewall_enabled = True
    rule_info = check_unifi_rule()
    if rule_info and rule_info.get("enabled") is False:
        firewall_enabled = False
        
    return render_template('index.html', services=services, settings=settings, firewall_enabled=firewall_enabled)

@app.route('/onboarding', methods=['GET'])
@login_required
def onboarding():
    """Show onboarding wizard for new users"""
    user = db.get_user(current_user.id)
    if user and user.get('onboarding_completed'):
        # Already completed onboarding, redirect to home
        return redirect(url_for('index'))
    
    settings = db.get_all_settings()
    return render_template('onboarding.html', settings=settings)

# Whitelist of settings that can be modified via web UI
# This prevents unauthorized modification of internal settings
ALLOWED_USER_SETTINGS = {
    'CF_API_TOKEN', 'CF_ZONE_ID', 'DOMAIN_ROOT', 'ORIGIN_RULE_NAME',
    'REDIS_HOST', 'REDIS_PORT', 'REDIS_PASS',
    'UNIFI_HOST', 'UNIFI_USER', 'UNIFI_PASS', 'UNIFI_RULE_NAME',
    'UNIFI_VERIFY_SSL',
    'FIREWALL_TYPE', 'UNIFI_IP_GROUP_NAME', 'UNIFI_PORT_GROUP_NAME',
    'TRAEFIK_LAN_CIDR',
    'HEALTH_CHECK_INTERVAL', 'HEALTH_CHECK_TIMEOUT',
    'PORT_ROTATION_INTERVAL',
    'DISCORD_WEBHOOK_URL', 'NOTIFY_EVENTS_HEALTH', 'NOTIFY_EVENTS_SYSTEM',
    'ENFORCE_2FA',
    'ROUTING_MODE',
    'VPS_HOST', 'VPS_SSH_USER', 'VPS_SSH_PORT', 'VPS_SSH_KEY',
    'WG_CLIENT_ADDRESS', 'WG_PRIVATE_KEY', 'WG_SERVER_ENDPOINT',
    'WG_SERVER_PUBLIC_KEY', 'WG_ALLOWED_IPS',
    'MQTT_ENABLED', 'MQTT_HOST', 'MQTT_PORT', 'MQTT_USER', 'MQTT_PASS', 'MQTT_DISCOVERY_PREFIX',
}

@app.route('/onboarding/complete', methods=['POST'])
@login_required
def onboarding_complete():
    """Complete onboarding and save all settings"""
    try:
        # Only save whitelisted settings
        saved_count = 0
        rejected_count = 0
        for key in request.form:
            if key in ALLOWED_USER_SETTINGS:
                db.set_setting(key, request.form[key])
                saved_count += 1
            else:
                logger.warning("Security: Rejected attempt to set disallowed setting '%s' via onboarding", key)
                rejected_count += 1
        
        # Mark onboarding as completed
        db.update_user_onboarding_status(current_user.id, True)
        
        if rejected_count > 0:
            flash(f'Setup completed! Saved {saved_count} settings. ({rejected_count} invalid settings were ignored)', 'warning')
        else:
            flash('Setup completed successfully!', 'success')
        return redirect(url_for('index'))
    except Exception as e:
        print(f"⚠️ Unexpected error in onboarding_complete: {str(e)}")
        flash('An unexpected error occurred during setup. Please try again.', 'error')
        return redirect(url_for('onboarding'))

@app.route('/services/new', methods=['GET', 'POST'])
@login_required
def new_service():
    if request.method == 'POST':
        try:
            # Validate all inputs
            name = validate_display_name(request.form['name'])
            router_name = validate_router_name(request.form['router_name'])
            service_name = validate_service_name(request.form['service_name'])
            target_url = validate_target_url(request.form['target_url'])
            subdomain_prefix = validate_subdomain_prefix(request.form['subdomain_prefix'])
                
            random_suffix = 1 if request.form.get('random_suffix') else 0
            show_regex = 1 if request.form.get('show_regex') else 0
            routing_mode = request.form.get('routing_mode', 'unifi')
            
            new_id = db.add_service(
                name=name,
                router_name=router_name,
                service_name=service_name,
                target_url=target_url,
                subdomain_prefix=subdomain_prefix,
                random_suffix=random_suffix,
                show_regex=show_regex,
                routing_mode=routing_mode
            )
            # Update MQTT
            new_service = db.get_service(new_id)
            if new_service:
                mqtt_manager.publish_discovery(new_service)
                
            flash('Service added successfully!', 'success')
            return redirect(url_for('index'))
        except ValueError as e:
            # Expected validation errors - safe to show
            flash(f'Validation Error: {str(e)}', 'error')
        except Exception as e:
            # Unexpected errors - log but don't expose details
            print(f"⚠️ Unexpected error in new_service: {str(e)}")
            flash('An unexpected error occurred while creating the service. Please check the logs.', 'error')
    
    return render_template('service_form.html', service=None)

@app.route('/services/<int:service_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_service(service_id):
    service = db.get_service(service_id)
    if not service:
        flash('Service not found', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        try:
            # Validate all inputs
            name = validate_display_name(request.form['name'])
            router_name = validate_router_name(request.form['router_name'])
            service_name = validate_service_name(request.form['service_name'])
            target_url = validate_target_url(request.form['target_url'])
            subdomain_prefix = validate_subdomain_prefix(request.form['subdomain_prefix'])

            random_suffix = 1 if request.form.get('random_suffix') else 0
            show_regex = 1 if request.form.get('show_regex') else 0
            routing_mode = request.form.get('routing_mode', 'unifi')
            
            db.update_service(
                service_id,
                name=name,
                router_name=router_name,
                service_name=service_name,
                target_url=target_url,
                subdomain_prefix=subdomain_prefix,
                random_suffix=random_suffix,
                show_regex=show_regex,
                routing_mode=routing_mode
            )
            
            # Update MQTT
            updated_service = db.get_service(service_id)
            if updated_service:
                mqtt_manager.publish_discovery(updated_service)
            
            # If service is active, refresh the external configuration (Redis, DNS, etc.)
            if service.get('enabled'):
                print(f"🔄 Service '{service['name']}' is active, refreshing configuration...")
                turn_on_service(service_id, force=True)
                
            flash('Service updated successfully!', 'success')
            return redirect(url_for('index'))
        except ValueError as e:
            # Expected validation errors - safe to show
            flash(f'Validation Error: {str(e)}', 'error')
        except Exception as e:
            # Unexpected errors - log but don't expose details
            print(f"⚠️ Unexpected error in edit_service: {str(e)}")
            flash('An unexpected error occurred while updating the service. Please check the logs.', 'error')
    
    return render_template('service_form.html', service=service)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        try:
            # Only save whitelisted settings
            saved_count = 0
            rejected_count = 0
            mqtt_changed = False
            for key in request.form:
                if key == 'csrf_token':
                    continue
                    
                if key in ALLOWED_USER_SETTINGS:
                    value = request.form[key]
                    
                    # Basic Validation
                    if key == 'WG_CLIENT_ADDRESS' and value:
                        if '/' not in value:
                            flash(f'Error saving {key}: Must be in CIDR format (e.g. 10.0.0.2/24)', 'error')
                            continue
                    
                    if key == 'WG_SERVER_ENDPOINT' and value:
                        if ':' not in value:
                            flash(f'Error saving {key}: Must be in IP:Port format', 'error')
                            continue

                    db.set_setting(key, value)
                    if key.startswith("MQTT_"):
                        mqtt_changed = True
                    saved_count += 1
                else:
                    logger.warning("Security: Rejected attempt to set disallowed setting '%s' via settings page", key)
                    rejected_count += 1
            
            if mqtt_changed:
                try:
                    mqtt_manager.reload()
                except Exception as e:
                    print(f"⚠️ Failed to reload MQTT: {e}")
            
            if rejected_count > 0:
                flash(f'Settings saved! Updated {saved_count} settings. ({rejected_count} invalid settings were ignored)', 'warning')
            else:
                flash('Settings saved successfully!', 'success')
            return redirect(url_for('settings'))
        except Exception as e:
            print(f"⚠️ Unexpected error in settings: {str(e)}")
            flash('An unexpected error occurred while saving settings. Please try again.', 'error')
    
    settings = db.get_all_settings()
    
    # Add user info for credential management
    user = db.get_user(current_user.id)
    has_password = bool(user.get('password_hash'))
    credentials = db.get_credentials_for_user(current_user.id)
    has_2fa = bool(user.get('totp_secret'))
    unused_recovery_codes = len(db.get_unused_recovery_codes(current_user.id))

    # Data for API Keys
    api_keys = db.get_api_keys_for_user(current_user.id)

    # Data for System Info
    version = get_version()
    uptime_seconds = int(time.time() - STARTUP_TIME)
    
    # Format uptime
    days, remainder = divmod(uptime_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    uptime_str = f"{days}d {hours}h {minutes}m {seconds}s"
    
    db_stats = db.get_db_stats()
    
    # Format DB size
    size = db_stats.get('size_bytes', 0)
    db_size_str = "0 B"
    if size > 0:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                db_size_str = f"{size:.2f} {unit}"
                break
            size /= 1024
        else:
            db_size_str = f"{size:.2f} TB"
    
    return render_template('settings.html', 
                          settings=settings, 
                          has_password=has_password, 
                          credentials=credentials, 
                          has_2fa=has_2fa, 
                          recovery_codes_count=unused_recovery_codes,
                          api_keys=api_keys,
                          version=version,
                          uptime=uptime_str,
                          db_stats=db_stats,
                          db_size=db_size_str)

# API Routes
@app.route('/healthz', methods=['GET'])
def health_check():
    """Health check endpoint for load balancers, Docker, and monitoring.

    Returns 200 with component status, or 503 if critical components are down.
    No authentication required (for infrastructure probes).
    """
    health = {"status": "healthy"}
    overall_healthy = True

    # Database connectivity
    try:
        with db.get_db() as conn:
            conn.execute("SELECT 1")
        health["database"] = "ok"
    except Exception as e:
        health["database"] = f"error: {e}"
        overall_healthy = False

    # Redis connectivity
    r = get_redis()
    if r:
        try:
            r.ping()
            health["redis"] = "ok"
        except Exception as e:
            health["redis"] = f"error: {e}"
            # Redis is non-critical; don't fail the health check
    else:
        health["redis"] = "unavailable"

    # MQTT status
    if mqtt_manager:
        if mqtt_manager.client:
            try:
                health["mqtt"] = "connected" if mqtt_manager.client.is_connected() else "disconnected"
            except Exception:
                health["mqtt"] = "error"
        else:
            health["mqtt"] = "not_connected"

    health["status"] = "healthy" if overall_healthy else "degraded"
    status_code = 200 if overall_healthy else 503

    return jsonify(health), status_code

@app.route('/api/status', methods=['GET'])
@api_key_or_login_required
def api_status():
    return jsonify(get_status())

@app.route('/api/firewall-status', methods=['GET'])
@api_key_or_login_required
def api_firewall_status():
    firewall_status = "UNKNOWN"
    firewall_port = None
    rule_info = check_unifi_rule()
    if rule_info:
        if rule_info["enabled"] is True:
            firewall_status = "OPEN"
        elif rule_info["enabled"] is False:
            firewall_status = "CLOSED"
        firewall_port = rule_info.get("port")
    return jsonify({"status": firewall_status, "port": firewall_port})

@app.route('/api/services/<int:service_id>/on', methods=['POST'])
@api_key_or_login_required
def api_turn_on(service_id):
    force = False
    if request.is_json:
        data = request.get_json(silent=True)
        if data:
            force = data.get('force', False)
    
    result = turn_on_service(service_id, force=force)
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result)

@app.route('/api/services/<int:service_id>/off', methods=['POST'])
@api_key_or_login_required
def api_turn_off(service_id):
    result = turn_off_service(service_id)
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result)

@app.route('/api/services/<int:service_id>/rotate', methods=['POST'])
@api_key_or_login_required
def api_rotate(service_id):
    result = rotate_service(service_id)
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result)

@app.route('/api/services/<int:service_id>/status', methods=['GET'])
@api_key_or_login_required
def api_service_status(service_id):
    result = get_service_status(service_id)
    if result is None:
        return jsonify({"error": "Service not found"}), 404
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result)

@app.route('/api/services/<int:service_id>/repair', methods=['POST'])
@api_key_or_login_required
def api_repair_service(service_id):
    """Repair service configuration by syncing database config to Redis/Traefik"""
    service = db.get_service(service_id)
    if not service:
        return jsonify({"error": "Service not found"}), 404
    
    # Only repair enabled services
    if not service['enabled']:
        return jsonify({"error": "Service must be enabled to repair"}), 400
    
    r = get_redis()
    if not r:
        return jsonify({"error": "Redis connection failed"}), 400
    
    # Check what's currently in Redis
    current_rule = r.get(f"traefik/http/routers/{service['router_name']}/rule")
    if not current_rule:
        return jsonify({"error": "Service is not active in Traefik"}), 400
    
    # Get actual vs expected values
    actual_target_url = r.get(f"traefik/http/services/{service['service_name']}/loadbalancer/servers/0/url")
    expected_target_url = service['target_url']
    
    if actual_target_url == expected_target_url:
        return jsonify({"message": "Service configuration is already correct", "target_url": expected_target_url})
    
    # Repair: Update Redis with correct target URL from database
    r.set(f"traefik/http/services/{service['service_name']}/loadbalancer/servers/0/url", expected_target_url)
    
    print(f"🔧 Repaired {service['name']}: {actual_target_url} → {expected_target_url}")
    
    return jsonify({
        "message": "Service configuration repaired successfully",
        "old_target_url": actual_target_url,
        "new_target_url": expected_target_url
    })

@app.route('/api/services/<int:service_id>/diagnose', methods=['GET'])
@api_key_or_login_required
def api_diagnose_service(service_id):
    """Diagnose service configuration and connectivity issues"""
    service = db.get_service(service_id)
    if not service:
        return jsonify({"error": "Service not found"}), 404
    
    diagnostics = {
        "service": service,
        "checks": {}
    }
    
    # Check Redis connection
    r = get_redis()
    if not r:
        diagnostics["checks"]["redis"] = {"status": "fail", "message": "Redis connection failed"}
        return jsonify(diagnostics), 400
    else:
        diagnostics["checks"]["redis"] = {"status": "ok", "message": "Redis connection successful"}
    
    # Check if service is enabled
    if not service['enabled']:
        diagnostics["checks"]["enabled"] = {"status": "info", "message": "Service is disabled"}
        return jsonify(diagnostics)
    
    diagnostics["checks"]["enabled"] = {"status": "ok", "message": "Service is enabled"}
    
    # Check Traefik router configuration
    current_rule = r.get(f"traefik/http/routers/{service['router_name']}/rule")
    if not current_rule:
        diagnostics["checks"]["traefik_router"] = {
            "status": "fail", 
            "message": "Router not found in Traefik/Redis"
        }
    else:
        hostname = current_rule.replace("Host(`", "").replace("`)", "")
        diagnostics["checks"]["traefik_router"] = {
            "status": "ok",
            "message": "Router configured correctly",
            "hostname": hostname
        }
    
    # Check Traefik service configuration
    actual_target_url = r.get(f"traefik/http/services/{service['service_name']}/loadbalancer/servers/0/url")
    expected_target_url = service['target_url']
    
    if not actual_target_url:
        diagnostics["checks"]["traefik_service"] = {
            "status": "fail",
            "message": "Service backend not configured in Traefik"
        }
    elif actual_target_url != expected_target_url:
        diagnostics["checks"]["traefik_service"] = {
            "status": "warning",
            "message": "Service backend URL mismatch",
            "expected": expected_target_url,
            "actual": actual_target_url
        }
    else:
        diagnostics["checks"]["traefik_service"] = {
            "status": "ok",
            "message": "Service backend configured correctly",
            "target_url": actual_target_url
        }
    
    # Check firewall status
    rule_info = check_unifi_rule()
    if rule_info is None:
        diagnostics["checks"]["firewall"] = {
            "status": "info",
            "message": "Firewall control not configured"
        }
    elif rule_info.get("enabled"):
        diagnostics["checks"]["firewall"] = {
            "status": "ok",
            "message": "Firewall rule is enabled",
            "port": rule_info.get("port")
        }
    else:
        diagnostics["checks"]["firewall"] = {
            "status": "warning",
            "message": "Firewall rule is disabled",
            "port": rule_info.get("port")
        }
    
    # Check DNS record
    if service.get('current_hostname'):
        domain_root = get_setting("DOMAIN_ROOT", required=False)
        if domain_root:
            records = cf_request("GET", f"dns_records?type=A&name={service['current_hostname']}")
            
            if records and records.get('result'):
                dns_record = records['result'][0]
                diagnostics["checks"]["dns"] = {
                    "status": "ok",
                    "message": "DNS record exists",
                    "name": dns_record['name'],
                    "content": dns_record['content'],
                    "proxied": dns_record['proxied']
                }
            else:
                diagnostics["checks"]["dns"] = {
                    "status": "fail",
                    "message": "DNS record not found in Cloudflare",
                    "expected_name": service['current_hostname']
                }
        else:
            diagnostics["checks"]["dns"] = {
                "status": "info",
                "message": "Cannot check DNS - DOMAIN_ROOT not configured"
            }
    else:
        diagnostics["checks"]["dns"] = {
            "status": "info",
            "message": "No current hostname - service may not have been activated yet"
        }
    
    # Check Cloudflare Origin Rule
    if service.get('current_hostname'):
        origin_rule_name = get_setting("ORIGIN_RULE_NAME", required=False) or "Service Rotation"
        
        ruleset_data = cf_request("GET", "rulesets/phases/http_request_origin/entrypoint")
        if ruleset_data:
            rules = ruleset_data.get('result', {}).get('rules', [])
            target_rule = next((r for r in rules if r.get('description') == origin_rule_name), None)
            
            if target_rule:
                # Check if hostname is in expression
                expression = target_rule.get('expression', '')
                hostname = service['current_hostname']
                
                if f'"{hostname}"' in expression:
                    port = target_rule.get('action_parameters', {}).get('origin', {}).get('port')
                    diagnostics["checks"]["origin_rule"] = {
                        "status": "ok",
                        "message": "Origin rule exists and includes hostname",
                        "port": port,
                        "enabled": target_rule.get('enabled')
                    }
                else:
                    diagnostics["checks"]["origin_rule"] = {
                        "status": "warning",
                        "message": "Origin rule exists but hostname missing from expression",
                        "expression": expression
                    }
            else:
                diagnostics["checks"]["origin_rule"] = {
                    "status": "warning",
                    "message": "Origin rule not found",
                    "expected_description": origin_rule_name
                }
        else:
            diagnostics["checks"]["origin_rule"] = {
                "status": "fail",
                "message": "Cannot retrieve origin rules from Cloudflare"
            }
    
    # Check backend host connectivity
    target_url = service['target_url']
    try:
        # Parse URL to validate it
        parsed_url = urlparse(target_url)
        
        # Basic SSRF protection: only allow http/https schemes
        # Note: Checking internal IPs (e.g., 192.168.x.x) is the intended use case
        # as this application manages access to internal backend services
        if parsed_url.scheme not in ['http', 'https']:
            diagnostics["checks"]["backend_host"] = {
                "status": "info",
                "message": f"Skipping connectivity check for non-HTTP(S) URL",
                "target": target_url
            }
        else:
            response = requests.get(target_url, timeout=5, allow_redirects=True)
            
            # Categorize responses more accurately
            if 200 <= response.status_code < 300:
                # 2xx: Success - host is responding correctly
                diagnostics["checks"]["backend_host"] = {
                    "status": "ok",
                    "message": "Backend host is responding",
                    "target": target_url,
                    "status_code": response.status_code
                }
            elif 300 <= response.status_code < 400:
                # 3xx: Redirects (kept for clarity, though allow_redirects=True means this won't trigger)
                diagnostics["checks"]["backend_host"] = {
                    "status": "ok",
                    "message": "Backend host is responding (redirect)",
                    "target": target_url,
                    "status_code": response.status_code
                }
            elif 400 <= response.status_code < 500:
                # 4xx: Client errors - host is reachable but may have config issues
                diagnostics["checks"]["backend_host"] = {
                    "status": "warning",
                    "message": f"Backend host returned client error (HTTP {response.status_code})",
                    "target": target_url,
                    "status_code": response.status_code
                }
            else:
                # 5xx: Server errors - host is reachable but has internal errors
                diagnostics["checks"]["backend_host"] = {
                    "status": "warning",
                    "message": f"Backend host returned server error (HTTP {response.status_code})",
                    "target": target_url,
                    "status_code": response.status_code
                }
    except requests.exceptions.Timeout:
        diagnostics["checks"]["backend_host"] = {
            "status": "fail",
            "message": "Backend host connection timed out",
            "target": target_url
        }
    except requests.exceptions.ConnectionError as e:
        diagnostics["checks"]["backend_host"] = {
            "status": "fail",
            "message": "Cannot connect to backend host",
            "target": target_url,
            "error": str(e)
        }
    except Exception as e:
        diagnostics["checks"]["backend_host"] = {
            "status": "fail",
            "message": "Error checking backend host",
            "target": target_url,
            "error": str(e)
        }

    # Add firewall group tests
    firewall_group_results = _test_service_firewall(service_id)
    if firewall_group_results:
        if "error" in firewall_group_results:
            diagnostics["checks"]["firewall_groups"] = {"status": "fail", "message": firewall_group_results["error"]}
        elif "info" in firewall_group_results:
            # Don't show info message if service is disabled, as it's redundant
            if not (service and not service['enabled'] and "Service is disabled" in firewall_group_results["info"]):
                 diagnostics["checks"]["firewall_groups"] = {"status": "info", "message": firewall_group_results["info"]}
        else:
            if firewall_group_results.get("ip_check"):
                diagnostics["checks"]["firewall_ip_group"] = firewall_group_results["ip_check"]
            if firewall_group_results.get("port_check"):
                diagnostics["checks"]["firewall_port_group"] = firewall_group_results["port_check"]

    return jsonify(diagnostics)

@app.route('/api/services/<int:service_id>', methods=['DELETE'])
@api_key_or_login_required
def api_delete_service(service_id):
    service = db.get_service(service_id)
    if not service:
        return jsonify({"error": "Service not found"}), 404
    
    # If service is enabled, turn it off first
    if service['enabled']:
        turn_off_service(service_id)
    
    db.delete_service(service_id)
    # Update MQTT
    mqtt_manager.remove_discovery(service_id)
    return jsonify({"message": "Service deleted successfully"})

@app.route('/api/logs', methods=['GET'])
@api_key_or_login_required
def api_get_logs():
    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r', encoding='utf-8') as f:
                content = f.read()
            return jsonify({"logs": content})
        return jsonify({"logs": "Log file empty or not found."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/health/check', methods=['POST'])
@api_key_or_login_required
def api_trigger_health_check():
    """Trigger an immediate health check."""
    perform_health_check()
    # Return the full status so the UI can update dynamically
    return jsonify(get_status())

def turn_on_all(actor="System"):
    """Turn on all configured services."""
    services = db.get_all_services()
    results = []
    for service in services:
        if not service['enabled']:
            result = turn_on_service(service['id'], actor=actor)
            results.append(result)
    return results

def turn_off_all(actor="System"):
    """Turn off all configured services."""
    services = db.get_all_services()
    results = []
    for service in services:
        if service['enabled']:
            result = turn_off_service(service['id'], actor=actor)
            results.append(result)
    return results

@app.route('/api/services/all/on', methods=['POST'])
@api_key_or_login_required
def api_turn_on_all():
    results = turn_on_all(actor=g.actor if hasattr(g, 'actor') else "API")
    return jsonify({"results": results})

@app.route('/api/services/all/off', methods=['POST'])
@api_key_or_login_required
def api_turn_off_all():
    results = turn_off_all(actor=g.actor if hasattr(g, 'actor') else "API")
    return jsonify({"results": results})

@app.route('/api/sync-firewall', methods=['POST'])
@api_key_or_login_required
def api_sync_firewall():
    try:
        sync_unifi_groups()
        return jsonify({"message": "Firewall sync triggered"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/firewall/rotate', methods=['POST'])
@api_key_or_login_required
def api_rotate_firewall_port():
    """Manually trigger a firewall port rotation."""
    result = rotate_firewall_port(actor=g.actor if hasattr(g, 'actor') else "API")
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result)

@app.route('/api/users/<username>/reset-password', methods=['POST'])
@api_key_or_login_required
def api_reset_password(username):
    """Reset password for a user and show it in logs."""
    # Check rate limit (5 attempts per minute)
    if not check_rate_limit(request.remote_addr):
        return jsonify({"error": "Too many attempts. Please try again in a minute."}), 429

    user = db.get_user_by_username(username)
    if not user:
        return jsonify({"error": "User not found"}), 404
        
    # Generate random password meeting complexity requirements
    alphabet = string.ascii_letters + string.digits + '!@#$%^&*'
    password = ''.join(secrets.choice(alphabet) for i in range(12))
    
    pwhash = generate_password_hash(password)
    try:
        db.update_user_password(user['id'], pwhash)
        print(f"\n🔐 PASSWORD RESET FOR USER: {username}")
        print(f"   New Password: {'*' * len(password)} (length={len(password)})")
        print(f"   ⚠️ Password NOT logged for security. Return it to the admin via a secure channel.\n")
        return jsonify({"message": "Password reset successfully. Check logs for the new password.", "password": password})
    except Exception as e:
        print(f"❌ Error resetting password: {e}")
        return jsonify({"error": "Failed to save password"}), 500

@app.route('/api/notifications/test', methods=['POST'])
@login_required
def api_test_notification():
    """Send a test notification to Discord."""
    data = request.get_json(silent=True) or {}
    webhook_url = data.get('webhook_url') or get_setting("DISCORD_WEBHOOK_URL", required=False)
    
    if not webhook_url:
        return jsonify({"error": "No Webhook URL provided"}), 400
        
    send_discord_notification("🔔 **Test Notification**\nTraefik Route Control is connected to Discord!", title="System Info", webhook_url=webhook_url, msg_type='test')
    return jsonify({"success": True})

@app.route('/api/settings/backup', methods=['GET'])
@login_required
def api_backup_settings():
    """Download current settings as JSON."""
    settings = db.get_all_settings()
    json_str = json.dumps(settings, indent=2)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"traefik_control_backup_{timestamp}.json"
    
    response = make_response(json_str)
    response.headers['Content-Type'] = 'application/json'
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    return response

@app.route('/api/settings/restore', methods=['POST'])
@login_required
def api_restore_settings():
    """Restore settings from JSON file."""
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
        
    if file:
        try:
            data = json.load(file)
            if not isinstance(data, dict):
                 return jsonify({"error": "Invalid JSON format: expected a dictionary"}), 400
            
            count = 0
            rejected_count = 0
            for key, value in data.items():
                if key not in ALLOWED_USER_SETTINGS:
                    logger.warning("Security: Rejected attempt to restore disallowed setting '%s' via backup restore", key)
                    rejected_count += 1
                    continue
                db.set_setting(key, str(value))
                count += 1
            
            msg = f"Restored {count} settings successfully"
            if rejected_count > 0:
                msg += f" ({rejected_count} sensitive settings were skipped)"
            
            return jsonify({"success": True, "message": msg})
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid JSON file"}), 400
        except Exception as e:
            return jsonify({"error": str(e)}), 500

@app.route('/api/settings', methods=['POST'])
@login_required
def api_save_setting():
    """Save a single setting."""
    data = request.get_json()
    if not data or 'key' not in data or 'value' not in data:
        return jsonify({"error": "Invalid request data"}), 400
    
    key = data['key']
    if key not in ALLOWED_USER_SETTINGS:
        logger.warning("Security: Rejected attempt to set disallowed setting '%s' via API", key)
        return jsonify({"error": "Setting not allowed to be modified via API"}), 403
    
    try:
        db.set_setting(key, data['value'])
        return jsonify({"message": f"Setting '{key}' saved successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/test/mqtt', methods=['POST'])
@login_required
def test_mqtt_connection_route():
    try:
        data = request.json
        host = data.get('host')
        port = int(data.get('port', 1883))
        username = data.get('username')
        password = data.get('password')
        
        if not host:
            return jsonify({"error": "Host is required"}), 400
            
        import paho.mqtt.client as mqtt
        
        # Create a temporary client for testing
        client = mqtt.Client()
        if username:
            client.username_pw_set(username, password)
            
        # Try to connect
        client.connect(host, port, 5)
        client.loop_start()
        time.sleep(1) # Give it a moment
        
        if client.is_connected():
            client.disconnect()
            return jsonify({"message": "MQTT Connection Successful!"})
        else:
            return jsonify({"error": "Could not connect to MQTT Broker"}), 400
            
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/test/redis', methods=['POST'])
@login_required
def api_test_redis():
    data = request.get_json()
    host = data.get('host')
    port = data.get('port')
    password = data.get('password')
    
    try:
        r = redis.Redis(host=host, port=port, password=password, socket_timeout=5)
        r.ping()
        return jsonify({"message": "Redis connection successful!"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/test/redis/clear', methods=['POST'])
@login_required
def api_clear_redis_routes():
    """Clear all Traefik route entries from Redis."""
    r = get_redis()
    if not r:
        return jsonify({"error": "Redis connection failed"}), 500
    
    try:
        # Find all keys starting with traefik/
        keys = r.keys("traefik/*")
        if keys:
            # redis-py delete needs positional arguments
            r.delete(*keys)
            return jsonify({"message": f"Successfully cleared {len(keys)} Traefik entries from Redis"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/test/vps-ssh', methods=['POST'])
@login_required
def test_vps_ssh():
    """Test VPS SSH connection"""
    data = request.json
    host = data.get('host')
    user = data.get('user')
    port = data.get('port', 22)
    key = data.get('key')
    
    if not all([host, user, key]):
        return jsonify({"error": "Missing required fields"}), 400
        
    success, message = routing.VPSManager.test_connection(host, user, port, key)
    
    if success:
        return jsonify({"message": message})
    else:
        return jsonify({"error": message}), 500

@app.route('/api/test/unifi', methods=['POST'])
@login_required
def api_test_unifi():
    """Test UniFi connection with provided credentials."""
    data = request.get_json(silent=True) or {}
    host = data.get('host')
    user = data.get('user')
    passw = data.get('pass')
    
    if not all([host, user, passw]):
        return jsonify({"error": "Host, Username, and Password are required"}), 400
        
    base_url = f"https://{host}"
    session = requests.Session()
    session.verify = False
    
    try:
        resp = login_unifi_with_retry(session, base_url, user, passw)
        if resp and resp.status_code == 200:
            logout_unifi(session, base_url)
            return jsonify({"success": True, "message": "UniFi connection successful!"})
        else:
            status = resp.status_code if resp else "unknown"
            return jsonify({"error": f"Login failed (HTTP {status})"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/test/cloudflare', methods=['POST'])
@login_required
def api_test_cloudflare():
    """Test Cloudflare connection with provided credentials."""
    data = request.get_json(silent=True) or {}
    token = data.get('token')
    zone_id = data.get('zone_id')
    
    if not token or not zone_id:
        return jsonify({"error": "Token and Zone ID are required"}), 400
        
    try:
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        # Verify token and zone access by fetching zone details
        url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}"
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                zone_name = result.get('result', {}).get('name', 'Unknown')
                return jsonify({"success": True, "message": f"Connection successful! Zone: {zone_name}"})
            else:
                errors = result.get('errors', [])
                error_msg = errors[0].get('message') if errors else "Unknown Cloudflare error"
                return jsonify({"error": f"Cloudflare Error: {error_msg}"}), 400
        else:
            return jsonify({"error": f"Connection failed: HTTP {response.status_code}"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# Legacy API endpoints for backward compatibility
@app.route('/api/turn_on', methods=['POST'])
@api_key_or_login_required
def api_legacy_turn_on():
    services = db.get_all_services()
    if not services:
        return jsonify({"error": "No services configured"}), 400
    result = turn_on_service(services[0]['id'])
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result)

@app.route('/api/turn_off', methods=['POST'])
@api_key_or_login_required
def api_legacy_turn_off():
    services = db.get_all_services()
    if not services:
        return jsonify({"error": "No services configured"}), 400
    result = turn_off_service(services[0]['id'])
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result)

# API Key Management Routes
@app.route('/api-keys/create', methods=['POST'])
@login_required
def create_api_key():
    """Create a new API key"""
    try:
        # Handle JSON or Form
        if request.is_json:
            name = request.json.get('name', 'API Key')
        else:
            name = request.form.get('name', 'API Key')
        
        # Generate a random API key (32 bytes = 64 hex characters)
        api_key = secrets.token_hex(32)
        
        # Hash the key for storage
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        # Store in database
        db.add_api_key(current_user.id, key_hash, name)
        
        # If JSON request, return JSON
        if request.is_json:
            return jsonify({"success": True, "api_key": api_key, "name": name})
        
        # Store temporarily in session to show on redirect (only shown once)
        session['new_api_key'] = api_key
        
        return redirect(url_for('settings'))
    except Exception as e:
        if request.is_json:
            return jsonify({"error": str(e)}), 400
        flash(f'Error creating API key: {str(e)}', 'error')
        return redirect(url_for('settings'))

@app.route('/api-keys/<int:key_id>/delete', methods=['POST'])
@login_required
def delete_api_key_route(key_id):
    """Delete an API key"""
    try:
        # Verify the key belongs to the current user
        keys = db.get_api_keys_for_user(current_user.id)
        if not any(k['id'] == key_id for k in keys):
            flash('API key not found', 'error')
            return redirect(url_for('settings'))
        
        db.delete_api_key(key_id)
        flash('API key deleted successfully', 'success')
        return redirect(url_for('settings'))
    except Exception as e:
        flash(f'Error deleting API key: {str(e)}', 'error')
        return redirect(url_for('settings'))

@app.route('/api/system', methods=['GET'])
@api_key_or_login_required
def api_system_info():
    """Get system information."""
    uptime_seconds = int(time.time() - STARTUP_TIME)
    return jsonify({
        "version": get_version(),
        "uptime_seconds": uptime_seconds,
        "database": db.get_db_stats()
    })

def handle_mqtt_command(service_id, action):
    """Callback for MQTT state changes."""
    with app.app_context():
        if service_id == "global":
            if action == "ALL_ON":
                turn_on_all(actor="MQTT")
            elif action == "ALL_OFF":
                turn_off_all(actor="MQTT")
            elif action == "ROTATE_PORT":
                rotate_firewall_port(actor="MQTT")
        else:
            if action == "ON":
                turn_on_service(service_id, actor="MQTT")
            elif action == "OFF":
                turn_off_service(service_id, actor="MQTT")
            elif action == "ROTATE":
                rotate_service(service_id, actor="MQTT")

# Initialize MQTT
mqtt_manager.command_callback = handle_mqtt_command
try:
    mqtt_manager.start()
except Exception as e:
    print(f"⚠️ Failed to start MQTT manager: {e}")

# Register signal handlers for graceful shutdown
signal.signal(signal.SIGTERM, request_shutdown)
signal.signal(signal.SIGINT, request_shutdown)

# Start background threads if running via Gunicorn/WSGI (imported module)
# Uses gthread worker with 1 worker + 4 threads for concurrent request handling.
# Background threads are safe here since there's only one worker process.
if __name__ != "__main__":
    try:
        start_health_check_thread()
        start_port_rotation_thread()
    except Exception as e:
        print(f"⚠️ Failed to start background tasks: {e}")

if __name__ == "__main__":
    # Ensure environment is migrated/setup before any action
    migrate_env_to_db()

    # Start background threads (also handled if imported via Gunicorn above, but repeated here for direct run)
    start_health_check_thread()
    start_port_rotation_thread()
    
    print(f"🚀 Starting Web UI on http://{API_HOST}:{API_PORT}")
    print(f"   Configure settings and services at http://{API_HOST}:{API_PORT}/settings")
    app.run(host=API_HOST, port=API_PORT, debug=False)
