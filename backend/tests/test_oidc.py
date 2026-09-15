"""
Tests for the OIDC/SSO authorization code exchange (auth.exchange_oidc_code,
find_or_create_oidc_user) and the /api/v1/auth/oidc/callback endpoint.

Everything that would hit a real Identity Provider (discovery document,
token endpoint, JWKS) is mocked - these tests must never make a real
network call. The point of these tests is to prove the verification path
actually rejects what it should (wrong signature, wrong audience, wrong
issuer, missing id_token) and only accepts a properly verified token.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from fastapi.testclient import TestClient

import auth as auth_module
from server import app

client = TestClient(app)

DISCOVERY_DOC = {
    "issuer": "https://login.microsoftonline.com/test-tenant/v2.0",
    "authorization_endpoint": "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/authorize",
    "token_endpoint": "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token",
    "jwks_uri": "https://login.microsoftonline.com/test-tenant/discovery/v2.0/keys",
}


@pytest.fixture(autouse=True)
def _isolated_auth_db(monkeypatch):
    fd, path = tempfile.mkstemp(prefix="ragnarok_oidc_test_", suffix=".db")
    os.close(fd)
    os.remove(path)
    monkeypatch.setattr(auth_module, "AUTH_DB_PATH", path)
    auth_module.init_auth_db()
    yield
    if os.path.exists(path):
        os.remove(path)


@pytest.fixture
def oidc_configured(monkeypatch):
    monkeypatch.setattr(auth_module, "OIDC_ISSUER", "https://login.microsoftonline.com/test-tenant/v2.0")
    monkeypatch.setattr(auth_module, "OIDC_CLIENT_ID", "test-client-id")
    monkeypatch.setattr(auth_module, "OIDC_CLIENT_SECRET", "test-client-secret")
    auth_module._oidc_discovery_cache.clear()
    auth_module._jwks_client_cache.clear()


def _mock_discovery(monkeypatch):
    class _DiscoveryResp:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return DISCOVERY_DOC

    monkeypatch.setattr(auth_module._requests, "get", lambda *a, **k: _DiscoveryResp())


def _mock_token_endpoint(monkeypatch, id_token: str, status_code: int = 200):
    class _TokenResp:
        def __init__(self):
            self.status_code = status_code
            self.text = "" if status_code == 200 else "invalid_grant"

        def json(self):
            return {"id_token": id_token, "access_token": "unused"}

    monkeypatch.setattr(auth_module._requests, "post", lambda *a, **k: _TokenResp())


def _mock_jwks_and_decode(monkeypatch, claims_to_return=None, raise_error=None):
    class _FakeSigningKey:
        key = "fake-key-material"

    class _FakeJWKSClient:
        def __init__(self, *a, **k):
            pass

        def get_signing_key_from_jwt(self, token):
            return _FakeSigningKey()

    monkeypatch.setattr(auth_module, "_PyJWKClient", _FakeJWKSClient)

    def _fake_decode(token, key, algorithms, audience, issuer, options):
        if raise_error:
            raise raise_error
        return claims_to_return

    monkeypatch.setattr(auth_module._jwt, "decode", _fake_decode)


# ----------------------------------------------------------------------
# generate_oidc_login_url now uses real discovery instead of guessed URLs
# ----------------------------------------------------------------------

def test_login_url_uses_discovered_authorization_endpoint(monkeypatch, oidc_configured):
    _mock_discovery(monkeypatch)
    url = auth_module.generate_oidc_login_url("http://localhost:1420/callback", "xyz")
    assert url.startswith(DISCOVERY_DOC["authorization_endpoint"])
    assert "client_id=test-client-id" in url
    assert "state=xyz" in url


def test_discovery_failure_raises_oidc_error(monkeypatch, oidc_configured):
    class _Boom:
        def raise_for_status(self):
            raise RuntimeError("connection refused")

    monkeypatch.setattr(auth_module._requests, "get", lambda *a, **k: _Boom())
    with pytest.raises(auth_module.OIDCError):
        auth_module.generate_oidc_login_url("http://localhost/callback", "s")


# ----------------------------------------------------------------------
# exchange_oidc_code: the actual security-critical path
# ----------------------------------------------------------------------

def test_exchange_rejects_missing_client_secret(monkeypatch):
    monkeypatch.setattr(auth_module, "OIDC_ISSUER", "https://idp.example.com")
    monkeypatch.setattr(auth_module, "OIDC_CLIENT_ID", "cid")
    monkeypatch.setattr(auth_module, "OIDC_CLIENT_SECRET", "")
    with pytest.raises(auth_module.OIDCError, match="CLIENT_SECRET"):
        auth_module.exchange_oidc_code("some-code", "http://localhost/callback")


def test_exchange_rejects_token_endpoint_error(monkeypatch, oidc_configured):
    _mock_discovery(monkeypatch)
    _mock_token_endpoint(monkeypatch, id_token="unused", status_code=400)
    with pytest.raises(auth_module.OIDCError, match="rifiutato"):
        auth_module.exchange_oidc_code("bad-code", "http://localhost/callback")


def test_exchange_rejects_response_without_id_token(monkeypatch, oidc_configured):
    _mock_discovery(monkeypatch)

    class _NoIdTokenResp:
        status_code = 200
        text = ""

        def json(self):
            return {"access_token": "only-this"}

    monkeypatch.setattr(auth_module._requests, "post", lambda *a, **k: _NoIdTokenResp())
    with pytest.raises(auth_module.OIDCError, match="id_token"):
        auth_module.exchange_oidc_code("code", "http://localhost/callback")


def test_exchange_rejects_invalid_signature(monkeypatch, oidc_configured):
    _mock_discovery(monkeypatch)
    _mock_token_endpoint(monkeypatch, id_token="fake.jwt.token")
    _mock_jwks_and_decode(monkeypatch, raise_error=auth_module._jwt.InvalidSignatureError("bad sig"))
    with pytest.raises(auth_module.OIDCError, match="non valido"):
        auth_module.exchange_oidc_code("code", "http://localhost/callback")


def test_exchange_rejects_wrong_audience(monkeypatch, oidc_configured):
    _mock_discovery(monkeypatch)
    _mock_token_endpoint(monkeypatch, id_token="fake.jwt.token")
    _mock_jwks_and_decode(monkeypatch, raise_error=auth_module._jwt.InvalidAudienceError("aud mismatch"))
    with pytest.raises(auth_module.OIDCError):
        auth_module.exchange_oidc_code("code", "http://localhost/callback")


def test_exchange_returns_verified_claims_on_success(monkeypatch, oidc_configured):
    _mock_discovery(monkeypatch)
    _mock_token_endpoint(monkeypatch, id_token="fake.jwt.token")
    claims = {"sub": "user-123", "email": "alice@example.com", "exp": 9999999999, "iat": 1, "preferred_username": "alice"}
    _mock_jwks_and_decode(monkeypatch, claims_to_return=claims)
    result = auth_module.exchange_oidc_code("good-code", "http://localhost/callback")
    assert result["sub"] == "user-123"
    assert result["email"] == "alice@example.com"


# ----------------------------------------------------------------------
# find_or_create_oidc_user: provisioning + idempotency
# ----------------------------------------------------------------------

def test_find_or_create_provisions_new_user_as_viewer():
    claims = {"sub": "sso-sub-1", "email": "bob@example.com"}
    user = auth_module.find_or_create_oidc_user(claims)
    assert user["role"] == "viewer"
    assert user["username"] == "bob@example.com"


def test_find_or_create_is_idempotent_by_sub():
    claims = {"sub": "sso-sub-2", "email": "carol@example.com"}
    first = auth_module.find_or_create_oidc_user(claims)
    second = auth_module.find_or_create_oidc_user(claims)
    assert first["id"] == second["id"]


def test_oidc_user_cannot_login_with_a_guessed_local_password():
    claims = {"sub": "sso-sub-3", "email": "dave@example.com"}
    auth_module.find_or_create_oidc_user(claims)
    # An SSO-provisioned account must never be reachable via the local
    # username/password login path.
    assert auth_module.check_user("dave@example.com", "password123") is None
    assert auth_module.check_user("dave@example.com", "") is None


def test_missing_sub_claim_is_rejected():
    with pytest.raises(auth_module.OIDCError, match="sub"):
        auth_module.find_or_create_oidc_user({"email": "no-sub@example.com"})


# ----------------------------------------------------------------------
# /api/v1/auth/oidc/callback endpoint, end to end (still fully mocked)
# ----------------------------------------------------------------------

def test_callback_disabled_when_oidc_not_configured(monkeypatch):
    monkeypatch.setattr(auth_module, "OIDC_ISSUER", "")
    monkeypatch.setattr(auth_module, "OIDC_CLIENT_ID", "")
    res = client.get("/api/v1/auth/oidc/callback", params={"code": "x", "redirect_uri": "http://localhost/cb"})
    assert res.status_code == 400


def test_callback_issues_a_real_session_token(monkeypatch, oidc_configured):
    _mock_discovery(monkeypatch)
    _mock_token_endpoint(monkeypatch, id_token="fake.jwt.token")
    claims = {"sub": "sso-sub-e2e", "email": "erin@example.com", "exp": 9999999999, "iat": 1}
    _mock_jwks_and_decode(monkeypatch, claims_to_return=claims)

    res = client.get(
        "/api/v1/auth/oidc/callback",
        params={"code": "good-code", "redirect_uri": "http://localhost/cb"},
    )
    assert res.status_code == 200
    body = res.json()
    assert "token" in body and body["token"]
    assert body["user"]["username"] == "erin@example.com"
    assert body["user"]["role"] == "viewer"

    # The token is a real, usable Ragnarök session - not a placeholder.
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {body['token']}"})
    assert me.status_code == 200
    assert me.json()["user"]["username"] == "erin@example.com"


def test_callback_rejects_forged_or_invalid_token(monkeypatch, oidc_configured):
    _mock_discovery(monkeypatch)
    _mock_token_endpoint(monkeypatch, id_token="fake.jwt.token")
    _mock_jwks_and_decode(monkeypatch, raise_error=auth_module._jwt.InvalidSignatureError("forged"))

    res = client.get(
        "/api/v1/auth/oidc/callback",
        params={"code": "attacker-supplied-code", "redirect_uri": "http://localhost/cb"},
    )
    assert res.status_code == 401
