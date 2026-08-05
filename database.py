#!/usr/bin/env python3
import sqlite3
import os
from contextlib import contextmanager

# Use /app/data for Docker volume mounting, fall back to current directory
DATA_DIR = os.environ.get('DATA_DIR', '/app/data' if os.path.exists('/app/data') else os.path.dirname(__file__))
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "config.db")

def init_db():
    """Initialize the database schema."""
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                router_name TEXT NOT NULL UNIQUE,
                service_name TEXT NOT NULL,
                target_url TEXT NOT NULL,
                subdomain_prefix TEXT NOT NULL,
                random_suffix INTEGER DEFAULT 1,
                enabled INTEGER DEFAULT 0,
                current_hostname TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS webauthn_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                credential_id TEXT NOT NULL UNIQUE,
                public_key TEXT NOT NULL,
                sign_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        """)
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                key_hash TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        """)
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Check current schema version
        cursor = conn.execute("SELECT MAX(version) as version FROM schema_version")
        row = cursor.fetchone()
        current_version = row['version'] if row['version'] else 0
        
        # Wrap all migrations in a transaction for atomicity
        conn.execute("BEGIN IMMEDIATE")
        
        try:
            # Migration 1: Add hass_entity_id column if not exists
            if current_version < 1:
                cursor = conn.execute("PRAGMA table_info(services)")
                columns = [row[1] for row in cursor.fetchall()]
                if 'hass_entity_id' not in columns:
                    conn.execute("ALTER TABLE services ADD COLUMN hass_entity_id TEXT")
                conn.execute("INSERT INTO schema_version (version) VALUES (1)")
            
            # Migration 2: Add onboarding_completed column to users table
            if current_version < 2:
                cursor = conn.execute("PRAGMA table_info(users)")
                columns = [row[1] for row in cursor.fetchall()]
                if 'onboarding_completed' not in columns:
                    conn.execute("ALTER TABLE users ADD COLUMN onboarding_completed INTEGER DEFAULT 0")
                conn.execute("INSERT INTO schema_version (version) VALUES (2)")
            
            # Migration 3: Create api_keys table
            if current_version < 3:
                cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='api_keys'")
                if not cursor.fetchone():
                    conn.execute("""
                        CREATE TABLE api_keys (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id INTEGER NOT NULL,
                            key_hash TEXT NOT NULL UNIQUE,
                            name TEXT NOT NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            last_used_at TIMESTAMP,
                            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                        )
                    """)
                conn.execute("INSERT INTO schema_version (version) VALUES (3)")
            
            # Migration 4: Add current_port column to services table
            if current_version < 4:
                cursor = conn.execute("PRAGMA table_info(services)")
                columns = [row[1] for row in cursor.fetchall()]
                if 'current_port' not in columns:
                    conn.execute("ALTER TABLE services ADD COLUMN current_port INTEGER")
                conn.execute("INSERT INTO schema_version (version) VALUES (4)")
            
            # Migration 5: Add password_hash column to users table
            if current_version < 5:
                cursor = conn.execute("PRAGMA table_info(users)")
                columns = [row[1] for row in cursor.fetchall()]
                if 'password_hash' not in columns:
                    conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
                conn.execute("INSERT INTO schema_version (version) VALUES (5)")
            
            # Migration 6: Add totp_secret column to users table
            if current_version < 6:
                cursor = conn.execute("PRAGMA table_info(users)")
                columns = [row[1] for row in cursor.fetchall()]
                if 'totp_secret' not in columns:
                    conn.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")
                conn.execute("INSERT INTO schema_version (version) VALUES (6)")
            
            # Migration 7: Create recovery_codes table
            if current_version < 7:
                cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='recovery_codes'")
                if not cursor.fetchone():
                    conn.execute("""
                        CREATE TABLE recovery_codes (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id INTEGER NOT NULL,
                            code_hash TEXT NOT NULL,
                            used INTEGER DEFAULT 0,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                        )
                    """)
                conn.execute("INSERT INTO schema_version (version) VALUES (7)")
            
            # Migration 8: Add random_suffix column to services table
            if current_version < 8:
                cursor = conn.execute("PRAGMA table_info(services)")
                columns = [row[1] for row in cursor.fetchall()]
                if 'random_suffix' not in columns:
                    conn.execute("ALTER TABLE services ADD COLUMN random_suffix INTEGER DEFAULT 1")
                conn.execute("INSERT INTO schema_version (version) VALUES (8)")
            
            # Migration 9: Add show_regex column to services table
            if current_version < 9:
                cursor = conn.execute("PRAGMA table_info(services)")
                columns = [row[1] for row in cursor.fetchall()]
                if 'show_regex' not in columns:
                    conn.execute("ALTER TABLE services ADD COLUMN show_regex INTEGER DEFAULT 1")
                conn.execute("INSERT INTO schema_version (version) VALUES (9)")
            
            # Migration 10: Add routing_mode column to services table
            if current_version < 10:
                cursor = conn.execute("PRAGMA table_info(services)")
                columns = [row[1] for row in cursor.fetchall()]
                if 'routing_mode' not in columns:
                    conn.execute("ALTER TABLE services ADD COLUMN routing_mode TEXT DEFAULT 'unifi'")
                conn.execute("INSERT INTO schema_version (version) VALUES (10)")
            
            # Migration 11: Initialize ENFORCE_2FA setting with default value
            if current_version < 11:
                cursor = conn.execute("SELECT key FROM settings WHERE key = 'ENFORCE_2FA'")
                if not cursor.fetchone():
                    conn.execute("INSERT INTO settings (key, value) VALUES ('ENFORCE_2FA', '0')")
                conn.execute("INSERT INTO schema_version (version) VALUES (11)")
            
            conn.commit()
        except Exception:
            conn.rollback()
            raise

def _configure_connection(conn):
    """Apply standard pragmas to a new SQLite connection."""
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")

@contextmanager
def get_db():
    """Context manager for database connections."""
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    _configure_connection(conn)
    try:
        yield conn
    finally:
        conn.close()

# Service CRUD operations
def get_all_services():
    """Get all services."""
    with get_db() as conn:
        cursor = conn.execute("SELECT * FROM services ORDER BY name")
        return [dict(row) for row in cursor.fetchall()]

def get_service(service_id):
    """Get a specific service by ID."""
    with get_db() as conn:
        cursor = conn.execute("SELECT * FROM services WHERE id = ?", (service_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

def get_service_by_router_name(router_name):
    """Get a specific service by router name."""
    with get_db() as conn:
        cursor = conn.execute("SELECT * FROM services WHERE router_name = ?", (router_name,))
        row = cursor.fetchone()
        return dict(row) if row else None

def add_service(name, router_name, service_name, target_url, subdomain_prefix, random_suffix=1, show_regex=1, routing_mode='unifi'):
    """Add a new service."""
    with get_db() as conn:
        cursor = conn.execute("""
            INSERT INTO services (name, router_name, service_name, target_url, subdomain_prefix, random_suffix, show_regex, routing_mode)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (name, router_name, service_name, target_url, subdomain_prefix, random_suffix, show_regex, routing_mode))
        conn.commit()
        return cursor.lastrowid

def update_service(service_id, name, router_name, service_name, target_url, subdomain_prefix, random_suffix=1, show_regex=1, routing_mode='unifi'):
    """Update an existing service."""
    with get_db() as conn:
        conn.execute("""
            UPDATE services 
            SET name = ?, router_name = ?, service_name = ?, target_url = ?, 
                subdomain_prefix = ?, random_suffix = ?, show_regex = ?, routing_mode = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (name, router_name, service_name, target_url, subdomain_prefix, random_suffix, show_regex, routing_mode, service_id))
        conn.commit()

def delete_service(service_id):
    """Delete a service."""
    with get_db() as conn:
        conn.execute("DELETE FROM services WHERE id = ?", (service_id,))
        conn.commit()

def update_service_status(service_id, enabled, current_hostname=None, current_port=None):
    """Update service enabled status, current hostname, and current port."""
    with get_db() as conn:
        conn.execute("""
            UPDATE services 
            SET enabled = ?, current_hostname = ?, current_port = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (1 if enabled else 0, current_hostname, current_port, service_id))
        conn.commit()

# Settings CRUD operations
def get_setting(key, default=None):
    """Get a setting value."""
    with get_db() as conn:
        cursor = conn.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row['value'] if row else default

def set_setting(key, value):
    """Set a setting value."""
    with get_db() as conn:
        conn.execute("""
            INSERT INTO settings (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = CURRENT_TIMESTAMP
        """, (key, value, value))
        conn.commit()

def delete_setting(key):
    """Delete a setting."""
    with get_db() as conn:
        conn.execute("DELETE FROM settings WHERE key = ?", (key,))
        conn.commit()

def get_all_settings():
    """Get all settings as a dictionary."""
    with get_db() as conn:
        cursor = conn.execute("SELECT key, value FROM settings")
        return {row['key']: row['value'] for row in cursor.fetchall()}

# User CRUD operations
def get_user(user_id):
    """Get a specific user by ID."""
    with get_db() as conn:
        cursor = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

def get_user_by_username(username):
    """Get a specific user by username."""
    with get_db() as conn:
        cursor = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        return dict(row) if row else None

def get_all_users():
    """Get all users."""
    with get_db() as conn:
        cursor = conn.execute("SELECT * FROM users ORDER BY username")
        return [dict(row) for row in cursor.fetchall()]

def add_user(username):
    """Add a new user."""
    with get_db() as conn:
        cursor = conn.execute("INSERT INTO users (username) VALUES (?)", (username,))
        conn.commit()
        return cursor.lastrowid

def delete_user(user_id):
    """Delete a user."""
    with get_db() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()

def update_user_onboarding_status(user_id, completed=True):
    """Update user's onboarding completion status."""
    with get_db() as conn:
        conn.execute("""
            UPDATE users 
            SET onboarding_completed = ?
            WHERE id = ?
        """, (1 if completed else 0, user_id))
        conn.commit()

def update_user_password(user_id, password_hash):
    """Update user's password hash."""
    with get_db() as conn:
        conn.execute("""
            UPDATE users 
            SET password_hash = ?
            WHERE id = ?
        """, (password_hash, user_id))
        conn.commit()

def update_user_totp(user_id, totp_secret):
    """Update user's TOTP secret."""
    with get_db() as conn:
        conn.execute("""
            UPDATE users 
            SET totp_secret = ?
            WHERE id = ?
        """, (totp_secret, user_id))
        conn.commit()

def count_users():
    """Count total users."""
    with get_db() as conn:
        cursor = conn.execute("SELECT COUNT(*) FROM users")
        return cursor.fetchone()[0]

# WebAuthn credential operations
def add_credential(user_id, credential_id, public_key):
    """Add a new WebAuthn credential."""
    with get_db() as conn:
        cursor = conn.execute("""
            INSERT INTO webauthn_credentials (user_id, credential_id, public_key)
            VALUES (?, ?, ?)
        """, (user_id, credential_id, public_key))
        conn.commit()
        return cursor.lastrowid

def get_credentials_for_user(user_id):
    """Get all credentials for a user."""
    with get_db() as conn:
        cursor = conn.execute("SELECT * FROM webauthn_credentials WHERE user_id = ?", (user_id,))
        return [dict(row) for row in cursor.fetchall()]

def get_credential_by_id(credential_id):
    """Get a credential by credential_id."""
    with get_db() as conn:
        cursor = conn.execute("SELECT * FROM webauthn_credentials WHERE credential_id = ?", (credential_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

def update_credential_sign_count(credential_id, sign_count):
    """Update the sign count for a credential."""
    with get_db() as conn:
        conn.execute("""
            UPDATE webauthn_credentials 
            SET sign_count = ?
            WHERE credential_id = ?
        """, (sign_count, credential_id))
        conn.commit()

def delete_credential(credential_id):
    """Delete a credential."""
    with get_db() as conn:
        conn.execute("DELETE FROM webauthn_credentials WHERE credential_id = ?", (credential_id,))
        conn.commit()

# Recovery Code operations
def add_recovery_code(user_id, code_hash):
    """Add a single recovery code hash."""
    with get_db() as conn:
        conn.execute("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)", (user_id, code_hash))
        conn.commit()

def get_unused_recovery_codes(user_id):
    """Get all unused recovery codes for a user."""
    with get_db() as conn:
        cursor = conn.execute("SELECT * FROM recovery_codes WHERE user_id = ? AND used = 0", (user_id,))
        return [dict(row) for row in cursor.fetchall()]

def mark_recovery_code_used(code_id):
    """Mark a recovery code as used."""
    with get_db() as conn:
        conn.execute("UPDATE recovery_codes SET used = 1 WHERE id = ?", (code_id,))
        conn.commit()

def delete_all_recovery_codes(user_id):
    """Delete all recovery codes for a user (used when regenerating)."""
    with get_db() as conn:
        conn.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user_id,))
        conn.commit()

# API Key operations
def add_api_key(user_id, key_hash, name):
    """Add a new API key."""
    with get_db() as conn:
        cursor = conn.execute("""
            INSERT INTO api_keys (user_id, key_hash, name)
            VALUES (?, ?, ?)
        """, (user_id, key_hash, name))
        conn.commit()
        return cursor.lastrowid

def get_api_keys_for_user(user_id):
    """Get all API keys for a user."""
    with get_db() as conn:
        cursor = conn.execute("SELECT id, name, created_at, last_used_at FROM api_keys WHERE user_id = ?", (user_id,))
        return [dict(row) for row in cursor.fetchall()]

def get_api_key_by_hash(key_hash):
    """Get an API key by its hash."""
    with get_db() as conn:
        cursor = conn.execute("SELECT * FROM api_keys WHERE key_hash = ?", (key_hash,))
        row = cursor.fetchone()
        return dict(row) if row else None

def update_api_key_last_used(key_hash):
    """Update the last used timestamp for an API key."""
    with get_db() as conn:
        conn.execute("""
            UPDATE api_keys 
            SET last_used_at = CURRENT_TIMESTAMP
            WHERE key_hash = ?
        """, (key_hash,))
        conn.commit()

def delete_api_key(key_id):
    """Delete an API key."""
    with get_db() as conn:
        conn.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
        conn.commit()

def get_db_stats():
    """Get database statistics."""
    stats = {}
    with get_db() as conn:
        stats['services'] = conn.execute("SELECT COUNT(*) FROM services").fetchone()[0]
        stats['users'] = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        stats['credentials'] = conn.execute("SELECT COUNT(*) FROM webauthn_credentials").fetchone()[0]
        stats['api_keys'] = conn.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0]
        
    if os.path.exists(DB_PATH):
        stats['size_bytes'] = os.path.getsize(DB_PATH)
    else:
        stats['size_bytes'] = 0
        
    return stats
