"""Unit tests for settings endpoints in RouteGhost."""
import io
import json
import os
import sys
import tempfile
import shutil

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(scope="session", autouse=True)
def _setup_test_env():
    os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
    os.environ.setdefault("CF_API_TOKEN", "test")
    os.environ.setdefault("CF_ZONE_ID", "test")
    os.environ.setdefault("DOMAIN_ROOT", "test.example.com")
    yield
    data_dir = os.environ.get("DATA_DIR")
    if data_dir and os.path.isdir(data_dir):
        shutil.rmtree(data_dir, ignore_errors=True)


@pytest.fixture(scope="session")
def app():
    from main import app as flask_app
    flask_app.config["TESTING"] = True
    flask_app.config["WTF_CSRF_ENABLED"] = False
    flask_app.config["SESSION_COOKIE_SECURE"] = False
    yield flask_app


@pytest.fixture(autouse=True)
def _clear_rate_limits():
    from main import LOGIN_ATTEMPTS
    LOGIN_ATTEMPTS.clear()
    yield
    LOGIN_ATTEMPTS.clear()


class CSRFBypassClient:
    def __init__(self, app):
        self._client = app.test_client()

    def _add_bypass(self, kwargs):
        headers = kwargs.pop("headers", None) or {}
        headers["X-API-Key"] = "test-bypass-key"
        kwargs["headers"] = headers
        return kwargs

    def post(self, *args, **kwargs):
        return self._client.post(*args, **self._add_bypass(kwargs))

    def get(self, *args, **kwargs):
        return self._client.get(*args, **kwargs)

    def put(self, *args, **kwargs):
        return self._client.put(*args, **self._add_bypass(kwargs))

    def delete(self, *args, **kwargs):
        return self._client.delete(*args, **self._add_bypass(kwargs))


@pytest.fixture
def client(app):
    return CSRFBypassClient(app)


@pytest.fixture
def db(app):
    import database as _db
    return _db


def _create_test_user(db_mod, username="testsettings", password="TestPass1!"):
    from werkzeug.security import generate_password_hash as _gph
    user_id = db_mod.add_user(username)
    db_mod.update_user_password(user_id, _gph(password))
    return user_id


def _login(client, username="testsettings", password="TestPass1!"):
    """Log in as a user and return the response."""
    return client.post("/auth/login/password",
                       json={"username": username, "password": password})


# ---------------------------------------------------------------------------
# POST /api/settings — single setting save
# ---------------------------------------------------------------------------
class TestAPISaveSetting:
    @pytest.fixture(autouse=True)
    def setup_user(self, db, client):
        _create_test_user(db)
        _login(client)
        yield
        try:
            user = db.get_user_by_username("testsettings")
            if user:
                db.delete_user(user["id"])
        except Exception:
            pass

    def test_save_allowed_setting(self, client):
        resp = client.post("/api/settings",
                           json={"key": "DOMAIN_ROOT", "value": "new.example.com"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert "saved" in data["message"].lower()

    def test_save_rejects_disallowed_key(self, client):
        resp = client.post("/api/settings",
                           json={"key": "SECRET_KEY", "value": "pwned"})
        assert resp.status_code == 403
        assert "not allowed" in resp.get_json()["error"].lower()

    def test_save_missing_key_field(self, client):
        resp = client.post("/api/settings", json={"value": "x"})
        assert resp.status_code == 400
        assert "invalid" in resp.get_json()["error"].lower()

    def test_save_missing_value_field(self, client):
        resp = client.post("/api/settings", json={"key": "DOMAIN_ROOT"})
        assert resp.status_code == 400

    def test_save_empty_body(self, client):
        resp = client.post("/api/settings", json={})
        assert resp.status_code == 400

    def test_save_no_body(self, client):
        resp = client.post("/api/settings",
                           headers={"Content-Type": "application/json"})
        assert resp.status_code == 400

    def test_save_unauthenticated(self, app):
        """Unauthenticated request gets redirected or 401."""
        c = CSRFBypassClient(app)
        resp = c.post("/api/settings",
                      json={"key": "DOMAIN_ROOT", "value": "x"})
        # Flask-Login redirects to login or returns 401 for API
        assert resp.status_code in (302, 401)

    def test_persists_setting(self, client, db):
        client.post("/api/settings",
                    json={"key": "REDIS_HOST", "value": "redis-test"})
        val = db.get_setting("REDIS_HOST")
        assert val == "redis-test"

    def test_rejects_all_critical_settings(self, client):
        critical = ["SECRET_KEY", "DATABASE_PATH", "DATA_DIR"]
        for key in critical:
            resp = client.post("/api/settings",
                               json={"key": key, "value": "bad"})
            assert resp.status_code == 403, f"Key '{key}' should be rejected"


# ---------------------------------------------------------------------------
# POST /api/settings/restore — restore from JSON file
# ---------------------------------------------------------------------------
class TestAPISettingsRestore:
    @pytest.fixture(autouse=True)
    def setup_user(self, db, client):
        _create_test_user(db, username="restorer")
        client.post("/auth/login/password",
                    json={"username": "restorer", "password": "TestPass1!"})
        yield
        try:
            user = db.get_user_by_username("restorer")
            if user:
                db.delete_user(user["id"])
        except Exception:
            pass

    def _make_file(self, data):
        """Create a file-like object from a dict."""
        content = json.dumps(data)
        return (io.BytesIO(content.encode()), "backup.json")

    def test_restore_valid_settings(self, client):
        f = self._make_file({"DOMAIN_ROOT": "restored.example.com"})
        resp = client.post("/api/settings/restore",
                           data={"file": f},
                           content_type="multipart/form-data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert "1 settings" in data["message"]

    def test_restore_rejects_disallowed_key(self, client):
        f = self._make_file({
            "DOMAIN_ROOT": "ok.com",
            "FLASK_SECRET_KEY": "stolen",
        })
        resp = client.post("/api/settings/restore",
                           data={"file": f},
                           content_type="multipart/form-data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "1 sensitive" in data["message"] or "skipped" in data["message"]

    def test_restore_no_file(self, client):
        resp = client.post("/api/settings/restore",
                           data={},
                           content_type="multipart/form-data")
        assert resp.status_code == 400
        assert "file" in resp.get_json()["error"].lower()

    def test_restore_empty_filename(self, client):
        f = (io.BytesIO(b"{}"), "")
        resp = client.post("/api/settings/restore",
                           data={"file": f},
                           content_type="multipart/form-data")
        assert resp.status_code == 400

    def test_restore_invalid_json(self, client):
        f = (io.BytesIO(b"not json at all"), "bad.json")
        resp = client.post("/api/settings/restore",
                           data={"file": f},
                           content_type="multipart/form-data")
        assert resp.status_code == 400
        assert "invalid" in resp.get_json()["error"].lower()

    def test_restore_non_dict_json(self, client):
        f = (io.BytesIO(b'["array", "not", "dict"]'), "list.json")
        resp = client.post("/api/settings/restore",
                           data={"file": f},
                           content_type="multipart/form-data")
        assert resp.status_code == 400
        assert "dictionary" in resp.get_json()["error"]

    def test_restore_multiple_settings(self, client, db):
        f = self._make_file({
            "REDIS_HOST": "redis-new",
            "REDIS_PORT": "6380",
        })
        resp = client.post("/api/settings/restore",
                           data={"file": f},
                           content_type="multipart/form-data")
        assert resp.status_code == 200
        assert db.get_setting("REDIS_HOST") == "redis-new"
        assert db.get_setting("REDIS_PORT") == "6380"


# ---------------------------------------------------------------------------
# GET /api/settings/backup
# ---------------------------------------------------------------------------
class TestAPISettingsBackup:
    @pytest.fixture(autouse=True)
    def setup_user(self, db, client):
        _create_test_user(db, username="backuper")
        client.post("/auth/login/password",
                    json={"username": "backuper", "password": "TestPass1!"})
        yield
        try:
            user = db.get_user_by_username("backuper")
            if user:
                db.delete_user(user["id"])
        except Exception:
            pass

    def test_backup_returns_json(self, client):
        resp = client.get("/api/settings/backup")
        assert resp.status_code == 200
        assert resp.headers["Content-Type"] == "application/json"
        data = resp.get_json()
        assert isinstance(data, dict)

    def test_backup_has_content_disposition(self, client):
        resp = client.get("/api/settings/backup")
        cd = resp.headers.get("Content-Disposition", "")
        assert "attachment" in cd
        assert "backup_" in cd
        assert cd.endswith(".json")


# ---------------------------------------------------------------------------
# POST /settings — form-based settings page
# ---------------------------------------------------------------------------
class TestFormSettings:
    @pytest.fixture(autouse=True)
    def setup_user(self, db, client):
        _create_test_user(db, username="formuser")
        client.post("/auth/login/password",
                    json={"username": "formuser", "password": "TestPass1!"})
        yield
        try:
            user = db.get_user_by_username("formuser")
            if user:
                db.delete_user(user["id"])
        except Exception:
            pass

    def test_form_save_allowed(self, client, db):
        resp = client.post("/settings",
                           data={"DOMAIN_ROOT": "form.example.com"},
                           follow_redirects=False)
        assert resp.status_code in (302, 200)
        assert db.get_setting("DOMAIN_ROOT") == "form.example.com"

    def test_form_rejects_disallowed(self, client, db):
        resp = client.post("/settings",
                           data={"SECRET_KEY": "hacked"},
                           follow_redirects=False)
        assert resp.status_code in (302, 200)
        assert db.get_setting("SECRET_KEY") is None

    def test_form_skips_csrf_token(self, client):
        resp = client.post("/settings",
                           data={"csrf_token": "dummy", "DOMAIN_ROOT": "ok.com"},
                           follow_redirects=False)
        assert resp.status_code in (302, 200)

    def test_form_wg_client_address_validation(self, client, db):
        """WG_CLIENT_ADDRESS without '/' is rejected."""
        resp = client.post("/settings",
                           data={"WG_CLIENT_ADDRESS": "10.0.0.2"},
                           follow_redirects=False)
        assert resp.status_code in (302, 200)
        assert db.get_setting("WG_CLIENT_ADDRESS") != "10.0.0.2"

    def test_form_wg_client_address_valid(self, client, db):
        resp = client.post("/settings",
                           data={"WG_CLIENT_ADDRESS": "10.0.0.2/24"},
                           follow_redirects=False)
        assert resp.status_code in (302, 200)
        assert db.get_setting("WG_CLIENT_ADDRESS") == "10.0.0.2/24"

    def test_form_wg_server_endpoint_validation(self, client, db):
        """WG_SERVER_ENDPOINT without ':' is rejected."""
        resp = client.post("/settings",
                           data={"WG_SERVER_ENDPOINT": "1.2.3.4"},
                           follow_redirects=False)
        assert resp.status_code in (302, 200)
        assert db.get_setting("WG_SERVER_ENDPOINT") != "1.2.3.4"

    def test_form_wg_server_endpoint_valid(self, client, db):
        resp = client.post("/settings",
                           data={"WG_SERVER_ENDPOINT": "1.2.3.4:51820"},
                           follow_redirects=False)
        assert resp.status_code in (302, 200)
        assert db.get_setting("WG_SERVER_ENDPOINT") == "1.2.3.4:51820"


# ---------------------------------------------------------------------------
# Whitelist completeness
# ---------------------------------------------------------------------------
class TestWhitelistIntegrity:
    def test_critical_settings_not_in_whitelist(self):
        """Ensure security-critical keys are never in ALLOWED_USER_SETTINGS."""
        from main import ALLOWED_USER_SETTINGS
        forbidden = {"SECRET_KEY", "DATABASE_PATH", "DATA_DIR", "FLASK_SECRET_KEY"}
        overlap = forbidden & ALLOWED_USER_SETTINGS
        assert not overlap, f"Forbidden keys in whitelist: {overlap}"

    def test_allowed_settings_count(self):
        from main import ALLOWED_USER_SETTINGS
        assert len(ALLOWED_USER_SETTINGS) >= 30, "Whitelist should have ≥30 entries"
