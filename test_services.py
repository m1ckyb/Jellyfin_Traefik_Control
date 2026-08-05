"""Integration tests for service CRUD, enable/disable, and API endpoints."""
import hashlib
import os
import sys
import tempfile
import shutil
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

TEST_API_KEY = "test-bypass-key"
TEST_API_KEY_HASH = hashlib.sha256(TEST_API_KEY.encode()).hexdigest()


@pytest.fixture(scope="session", autouse=True)
def _setup_test_env():
    os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
    os.environ.setdefault("CF_API_TOKEN", "test-token")
    os.environ.setdefault("CF_ZONE_ID", "test-zone")
    os.environ.setdefault("DOMAIN_ROOT", "test.example.com")
    os.environ.setdefault("REDIS_HOST", "localhost")
    os.environ.setdefault("REDIS_PORT", "6379")
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
        headers["X-API-Key"] = TEST_API_KEY
        kwargs["headers"] = headers
        return kwargs

    def post(self, *args, **kwargs):
        return self._client.post(*args, **self._add_bypass(kwargs))

    def get(self, *args, **kwargs):
        return self._client.get(*args, **self._add_bypass(kwargs))

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


def _create_test_user(db_mod, username="svcuser", password="TestPass1!"):
    from werkzeug.security import generate_password_hash as _gph
    user_id = db_mod.add_user(username)
    db_mod.update_user_password(user_id, _gph(password))
    db_mod.add_api_key(user_id, TEST_API_KEY_HASH, f"test-key-{username}")
    return user_id


def _login(client, username="svcuser", password="TestPass1!"):
    return client.post("/auth/login/password",
                       json={"username": username, "password": password})


def _create_service(db_mod, name="Test Service", target_url="http://192.168.1.10:8080"):
    """Insert a test service directly into the database."""
    return db_mod.add_service(
        name=name,
        router_name=f"router-{name.lower().replace(' ', '-')}",
        service_name=f"svc-{name.lower().replace(' ', '-')}",
        target_url=target_url,
        subdomain_prefix=f"sub-{name.lower().replace(' ', '-')}",
        random_suffix=1,
        show_regex=1,
        routing_mode="unifi",
    )


def _mock_redis():
    """Create a mock Redis client."""
    r = MagicMock()
    r.get.return_value = None
    r.set.return_value = True
    r.delete.return_value = True
    return r


# ---------------------------------------------------------------------------
# Database-level service CRUD
# ---------------------------------------------------------------------------
class TestServiceDatabaseCRUD:
    def test_add_and_get_service(self, db):
        svc_id = _create_service(db)
        svc = db.get_service(svc_id)
        assert svc is not None
        assert svc["name"] == "Test Service"
        assert svc["enabled"] == 0
        assert svc["routing_mode"] == "unifi"
        db.delete_service(svc_id)

    def test_get_all_services(self, db):
        ids = [_create_service(db, name=f"Svc-{i}") for i in range(3)]
        all_svcs = db.get_all_services()
        svc_ids = [s["id"] for s in all_svcs]
        for sid in ids:
            assert sid in svc_ids
        for sid in ids:
            db.delete_service(sid)

    def test_update_service(self, db):
        svc_id = _create_service(db, name="Original")
        db.update_service(svc_id, "Updated", "new-router", "new-svc",
                          "http://10.0.0.1:3000", "new-prefix", 0, 0, "vps")
        svc = db.get_service(svc_id)
        assert svc["name"] == "Updated"
        assert svc["routing_mode"] == "vps"
        assert svc["target_url"] == "http://10.0.0.1:3000"
        db.delete_service(svc_id)

    def test_update_service_status_enable(self, db):
        svc_id = _create_service(db, name="Toggle Me")
        assert db.get_service(svc_id)["enabled"] == 0
        db.update_service_status(svc_id, True, "sub-toggleme.test.example.com", 9001)
        svc = db.get_service(svc_id)
        assert svc["enabled"] == 1
        assert svc["current_hostname"] == "sub-toggleme.test.example.com"
        assert svc["current_port"] == 9001
        db.delete_service(svc_id)

    def test_update_service_status_disable(self, db):
        svc_id = _create_service(db, name="Disable Me")
        db.update_service_status(svc_id, True, "host.test.example.com", 9002)
        db.update_service_status(svc_id, False, None, None)
        svc = db.get_service(svc_id)
        assert svc["enabled"] == 0
        assert svc["current_hostname"] is None
        assert svc["current_port"] is None
        db.delete_service(svc_id)

    def test_delete_service(self, db):
        svc_id = _create_service(db, name="Delete Me")
        assert db.get_service(svc_id) is not None
        db.delete_service(svc_id)
        assert db.get_service(svc_id) is None

    def test_get_nonexistent_service(self, db):
        assert db.get_service(999999) is None


# ---------------------------------------------------------------------------
# API: GET /api/services/<id>/status
# ---------------------------------------------------------------------------
class TestServiceStatusAPI:
    @pytest.fixture(autouse=True)
    def setup(self, db, client):
        _create_test_user(db)
        self._svc_id = _create_service(db, name="StatusTest")
        yield
        db.delete_service(self._svc_id)
        try:
            user = db.get_user_by_username("svcuser")
            if user:
                db.delete_user(user["id"])
        except Exception:
            pass

    @patch("main.get_redis")
    def test_status_offline(self, mock_get_redis, client):
        mock_get_redis.return_value = _mock_redis()
        resp = client.get(f"/api/services/{self._svc_id}/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "OFFLINE"

    @patch("main.get_redis")
    def test_status_online(self, mock_get_redis, client, db):
        r = _mock_redis()
        r.get.return_value = "Host(`sub-statustest.test.example.com`)"
        mock_get_redis.return_value = r
        db.update_service_status(self._svc_id, True, "sub-statustest.test.example.com", 9050)
        resp = client.get(f"/api/services/{self._svc_id}/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ONLINE"
        assert "hostname" in data

    @patch("main.get_redis")
    def test_status_redis_unavailable(self, mock_get_redis, client):
        mock_get_redis.return_value = None
        resp = client.get(f"/api/services/{self._svc_id}/status")
        assert resp.status_code == 400
        assert "redis" in resp.get_json()["error"].lower()

    def test_status_nonexistent(self, client):
        resp = client.get("/api/services/999999/status")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# API: DELETE /api/services/<id>
# ---------------------------------------------------------------------------
class TestServiceDeleteAPI:
    @pytest.fixture(autouse=True)
    def setup(self, db, client):
        _create_test_user(db, username="deluser")
        yield
        try:
            user = db.get_user_by_username("deluser")
            if user:
                db.delete_user(user["id"])
        except Exception:
            pass

    def test_delete_existing(self, client, db):
        svc_id = _create_service(db, name="DeleteAPI")
        resp = client.delete(f"/api/services/{svc_id}")
        assert resp.status_code == 200
        assert "deleted" in resp.get_json()["message"].lower()
        assert db.get_service(svc_id) is None

    def test_delete_nonexistent(self, client):
        resp = client.delete("/api/services/999999")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# API: POST /api/services/<id>/on  (mocked turn_on_service)
# ---------------------------------------------------------------------------
class TestServiceEnableAPI:
    @pytest.fixture(autouse=True)
    def setup(self, db, client):
        _create_test_user(db, username="enableuser")
        self._svc_id = _create_service(db, name="EnableTest")
        yield
        try:
            db.delete_service(self._svc_id)
        except Exception:
            pass
        try:
            user = db.get_user_by_username("enableuser")
            if user:
                db.delete_user(user["id"])
        except Exception:
            pass

    @patch("main.turn_on_service")
    def test_enable_offline_service(self, mock_on, client, db):
        mock_on.return_value = {"message": "EnableTest enabled", "url": "https://sub-enabletest.test.example.com", "port": 9050}
        resp = client.post(f"/api/services/{self._svc_id}/on",
                           json={"force": True})
        assert resp.status_code == 200
        mock_on.assert_called_once_with(self._svc_id, force=True)

    def test_enable_nonexistent(self, client):
        resp = client.post("/api/services/999999/on", json={})
        assert resp.status_code in (400, 404)

    @patch("main.turn_on_service")
    def test_enable_already_enabled_idempotent(self, mock_on, client, db):
        mock_on.return_value = {"message": "EnableTest is already online", "url": "https://existing.test.example.com", "port": 9099}
        resp = client.post(f"/api/services/{self._svc_id}/on", json={})
        assert resp.status_code == 200
        mock_on.assert_called_once_with(self._svc_id, force=False)

    @patch("main.turn_on_service")
    def test_enable_error_returns_400(self, mock_on, client):
        mock_on.return_value = {"error": "WireGuard failed: timeout"}
        resp = client.post(f"/api/services/{self._svc_id}/on", json={})
        assert resp.status_code == 400
        assert "wireguard" in resp.get_json()["error"].lower()


# ---------------------------------------------------------------------------
# API: POST /api/services/<id>/off  (mocked)
# ---------------------------------------------------------------------------
class TestServiceDisableAPI:
    @pytest.fixture(autouse=True)
    def setup(self, db, client):
        _create_test_user(db, username="disableuser")
        self._svc_id = _create_service(db, name="DisableTest")
        yield
        try:
            db.delete_service(self._svc_id)
        except Exception:
            pass
        try:
            user = db.get_user_by_username("disableuser")
            if user:
                db.delete_user(user["id"])
        except Exception:
            pass

    @patch("main.turn_off_service")
    def test_disable_enabled_service(self, mock_off, client, db):
        mock_off.return_value = {"message": "DisableTest disabled successfully"}
        resp = client.post(f"/api/services/{self._svc_id}/off", json={})
        assert resp.status_code == 200
        mock_off.assert_called_once_with(self._svc_id)

    def test_disable_nonexistent(self, client):
        resp = client.post("/api/services/999999/off", json={})
        assert resp.status_code in (400, 404)


# ---------------------------------------------------------------------------
# API: POST /api/services/all/on and /off  (bulk, mocked)
# ---------------------------------------------------------------------------
class TestBulkServiceAPI:
    @pytest.fixture(autouse=True)
    def setup(self, db, client):
        _create_test_user(db, username="bulkuser")
        self._ids = [
            _create_service(db, name="Bulk-A"),
            _create_service(db, name="Bulk-B"),
        ]
        yield
        for sid in self._ids:
            try:
                db.delete_service(sid)
            except Exception:
                pass
        try:
            user = db.get_user_by_username("bulkuser")
            if user:
                db.delete_user(user["id"])
        except Exception:
            pass

    @patch("main.turn_on_all")
    def test_bulk_enable(self, mock_on_all, client, db):
        mock_on_all.return_value = [{"message": f"Enabled Bulk-{'AB'[i]}"} for i in range(2)]
        resp = client.post("/api/services/all/on", json={})
        assert resp.status_code == 200
        mock_on_all.assert_called_once()

    @patch("main.turn_off_all")
    def test_bulk_disable(self, mock_off_all, client, db):
        mock_off_all.return_value = [{"message": f"Disabled Bulk-{'AB'[i]}"} for i in range(2)]
        resp = client.post("/api/services/all/off", json={})
        assert resp.status_code == 200
        mock_off_all.assert_called_once()


# ---------------------------------------------------------------------------
# Web UI: POST /services/new
# ---------------------------------------------------------------------------
class TestNewServiceForm:
    @pytest.fixture(autouse=True)
    def setup(self, db, client):
        _create_test_user(db, username="formuser")
        _login(client, username="formuser")
        yield
        try:
            user = db.get_user_by_username("formuser")
            if user:
                db.delete_user(user["id"])
        except Exception:
            pass
        for svc in db.get_all_services():
            if "Form" in (svc.get("name") or ""):
                db.delete_service(svc["id"])

    @patch("main.mqtt_manager")
    def test_create_service_valid(self, mock_mqtt, client, db):
        resp = client.post("/services/new", data={
            "name": "Form Service",
            "router_name": "form-router",
            "service_name": "form-svc",
            "target_url": "http://192.168.1.100:8080",
            "subdomain_prefix": "form",
            "random_suffix": "on",
            "show_regex": "on",
            "routing_mode": "unifi",
        }, follow_redirects=False)
        assert resp.status_code in (302, 200)
        svcs = [s for s in db.get_all_services() if s["name"] == "Form Service"]
        assert len(svcs) == 1

    def test_create_service_validation_error(self, client, db):
        resp = client.post("/services/new", data={
            "name": "",
            "router_name": "x",
            "service_name": "x",
            "target_url": "http://x:1",
            "subdomain_prefix": "x",
            "routing_mode": "unifi",
        }, follow_redirects=False)
        assert resp.status_code in (302, 200)


# ---------------------------------------------------------------------------
# API auth enforcement
# ---------------------------------------------------------------------------
class TestServiceAPIAuth:
    def test_unauthenticated_on(self, app):
        c = CSRFBypassClient(app)
        resp = c.post("/api/services/1/on", json={})
        assert resp.status_code in (302, 401)

    def test_unauthenticated_off(self, app):
        c = CSRFBypassClient(app)
        resp = c.post("/api/services/1/off", json={})
        assert resp.status_code in (302, 401)

    def test_unauthenticated_delete(self, app):
        c = CSRFBypassClient(app)
        resp = c.delete("/api/services/1")
        assert resp.status_code in (302, 401)

    def test_unauthenticated_status(self, app):
        c = CSRFBypassClient(app)
        resp = c.get("/api/services/1/status")
        assert resp.status_code in (302, 401)

    def test_unauthenticated_bulk_on(self, app):
        c = CSRFBypassClient(app)
        resp = c.post("/api/services/all/on", json={})
        assert resp.status_code in (302, 401)

    def test_unauthenticated_bulk_off(self, app):
        c = CSRFBypassClient(app)
        resp = c.post("/api/services/all/off", json={})
        assert resp.status_code in (302, 401)


class TestHealthCheck:
    """Tests for the /healthz endpoint."""

    def test_health_check_returns_200(self, app):
        c = CSRFBypassClient(app)
        resp = c.get("/healthz")
        assert resp.status_code == 200

    def test_health_check_returns_json(self, app):
        c = CSRFBypassClient(app)
        resp = c.get("/healthz")
        data = resp.get_json()
        assert data is not None
        assert "status" in data

    def test_health_check_database_ok(self, app):
        c = CSRFBypassClient(app)
        resp = c.get("/healthz")
        data = resp.get_json()
        assert data["database"] == "ok"

    def test_health_check_no_auth_required(self, app):
        """Health check should be accessible without authentication."""
        c = app.test_client()
        resp = c.get("/healthz")
        assert resp.status_code == 200

    def test_health_check_returns_request_id(self, app):
        """All responses should include an X-Request-ID header."""
        c = CSRFBypassClient(app)
        resp = c.get("/healthz")
        assert "X-Request-ID" in resp.headers
        assert len(resp.headers["X-Request-ID"]) == 8
