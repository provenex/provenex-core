"""Tests for provenex.integrations.identity.from_jwt.

We mint a real Ed25519... wait, JWT signing is RSA / ECDSA / HMAC; no
Ed25519 in PyJWT's standard set. Use RS256 with a generated key so the
test exercises the real signature-verification path without a network
JWKS fetch.

We monkeypatch PyJWKClient.get_signing_key_from_jwt to return the
generated public key so the from_jwt code path runs end-to-end
without hitting an external IdP.
"""

from __future__ import annotations

import datetime as _dt

import pytest

pytest.importorskip("jwt")
pytest.importorskip("cryptography")


@pytest.fixture
def rsa_signer():
    """Return (private_key_pem, public_key_pem) for the test."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def _make_token(priv_pem: bytes, claims: dict) -> str:
    import jwt

    return jwt.encode(claims, priv_pem, algorithm="RS256")


def test_jwt_maps_standard_claims_to_request_context(rsa_signer, monkeypatch):
    from provenex.integrations.identity import from_jwt
    from cryptography.hazmat.primitives import serialization

    priv_pem, pub_pem = rsa_signer
    pub_key = serialization.load_pem_public_key(pub_pem)

    claims = {
        "sub": "user-uuid-1",
        "preferred_username": "alice@acme.com",
        "email": "alice@acme.com",
        "groups": ["analysts", "eu-team"],
        "locale": "en-EU",
        "scp": "retrieval profile",
        "iss": "https://acme.okta.com/oauth2/default",
        "aud": "api://default",
        "exp": _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(hours=1),
        "iat": _dt.datetime.now(_dt.timezone.utc),
    }
    token = _make_token(priv_pem, claims)

    # Stub out PyJWKClient so we don't hit the network.
    class _Key:
        key = pub_key

    class _StubJWKClient:
        def __init__(self, *_a, **_kw):
            pass

        def get_signing_key_from_jwt(self, _token):
            return _Key()

    monkeypatch.setattr("jwt.PyJWKClient", _StubJWKClient)

    rc = from_jwt(
        token,
        jwks_uri="https://stub/.well-known/jwks.json",
        audience="api://default",
        issuer="https://acme.okta.com/oauth2/default",
    )
    assert rc.caller["id"] == "user-uuid-1"
    assert rc.caller["username"] == "alice@acme.com"
    assert rc.caller["email"] == "alice@acme.com"
    assert rc.caller["groups"] == ["analysts", "eu-team"]
    assert rc.jurisdiction == "en-EU"
    # First scope token -> purpose.
    assert rc.purpose == "retrieval"
    assert rc.timestamp.endswith("Z")


def test_jwt_rejects_wrong_audience(rsa_signer, monkeypatch):
    """An audience mismatch must raise; we don't silently accept."""
    import jwt as pyjwt
    from cryptography.hazmat.primitives import serialization

    from provenex.integrations.identity import from_jwt

    priv_pem, pub_pem = rsa_signer
    pub_key = serialization.load_pem_public_key(pub_pem)

    claims = {
        "sub": "u1",
        "iss": "https://idp/",
        "aud": "api://intended",
        "exp": _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(hours=1),
    }
    token = _make_token(priv_pem, claims)

    class _Key:
        key = pub_key

    class _StubJWKClient:
        def __init__(self, *_a, **_kw):
            pass

        def get_signing_key_from_jwt(self, _token):
            return _Key()

    monkeypatch.setattr("jwt.PyJWKClient", _StubJWKClient)
    with pytest.raises(pyjwt.exceptions.InvalidAudienceError):
        from_jwt(
            token,
            jwks_uri="https://stub/keys",
            audience="api://different",
            issuer="https://idp/",
        )


def test_custom_claim_map_overrides_defaults(rsa_signer, monkeypatch):
    """Azure AD-style claim map maps 'oid' -> caller.id, 'tid' -> caller.tenant."""
    from cryptography.hazmat.primitives import serialization

    from provenex.integrations.identity import from_jwt

    priv_pem, pub_pem = rsa_signer
    pub_key = serialization.load_pem_public_key(pub_pem)

    claims = {
        "sub": "ignored-because-overridden",
        "oid": "azure-object-id-1",
        "tid": "tenant-id-1",
        "iss": "https://login.microsoftonline.com/<tid>/v2.0",
        "aud": "api://app",
        "exp": _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(hours=1),
    }
    token = _make_token(priv_pem, claims)

    class _Key:
        key = pub_key

    class _StubJWKClient:
        def __init__(self, *_a, **_kw):
            pass

        def get_signing_key_from_jwt(self, _token):
            return _Key()

    monkeypatch.setattr("jwt.PyJWKClient", _StubJWKClient)
    rc = from_jwt(
        token,
        jwks_uri="https://stub/keys",
        audience="api://app",
        issuer="https://login.microsoftonline.com/<tid>/v2.0",
        claim_map={
            "oid": "caller.id",
            "tid": "caller.tenant",
        },
    )
    assert rc.caller["id"] == "azure-object-id-1"
    assert rc.caller["tenant"] == "tenant-id-1"
