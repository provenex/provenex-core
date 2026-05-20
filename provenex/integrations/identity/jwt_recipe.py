"""Generic JWT -> RequestContext extractor.

Designed to work with any OIDC-style identity provider (Okta, Auth0,
Azure AD, Google Cloud IAM, AWS IAM Identity Center, custom). The
recipe is:

    1. Verify the JWT signature against the provider's JWKS endpoint
       using :mod:`PyJWT`'s :class:`PyJWKClient`.
    2. Validate ``iss`` (issuer) and ``aud`` (audience).
    3. Map standard claims to :class:`RequestContext` fields with a
       per-deployment claim-map that the operator can override.

The operator owns the claim map — provider-specific claim names
(``preferred_username``, ``locale``, ``oid``, ``roles``, ``groups``)
vary; the helper just does the dispatch.

The mapped result is a vanilla :class:`provenex.RequestContext` that
:func:`provenex.verify_chunks` / :func:`provenex.verify_chunks_async`
accept directly.

Install the optional dep::

    pip install "provenex-core[identity]"  # pulls in PyJWT[crypto]
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, Optional

from ...policy.evaluator import RequestContext


def _require_jwt():
    try:
        import jwt  # noqa: F401
        from jwt import PyJWKClient  # noqa: F401
    except ImportError as exc:  # pragma: no cover - import guard
        raise ImportError(
            "from_jwt requires the 'identity' extra. "
            'Install with: pip install "provenex-core[identity]"'
        ) from exc


# Default claim map: standard OIDC claim names mapped to
# RequestContext attributes. Override per-IdP via ``claim_map=``.
_DEFAULT_CLAIM_MAP: Dict[str, str] = {
    # caller.id
    "sub": "caller.id",
    "preferred_username": "caller.username",
    "email": "caller.email",
    # caller.role(s)
    "role": "caller.role",
    "roles": "caller.roles",
    "groups": "caller.groups",
    # jurisdiction / locale
    "locale": "jurisdiction",
    # purpose / scope: many IdPs use 'scope' (space-separated) or
    # 'scp' (Azure AD); operators usually want one specific scope.
    "scope": "purpose",
    "scp": "purpose",
}


def from_jwt(
    token: str,
    *,
    jwks_uri: str,
    audience: str,
    issuer: str,
    algorithms: Iterable[str] = ("RS256", "RS384", "ES256", "ES384"),
    claim_map: Optional[Dict[str, str]] = None,
    extra_purpose: Optional[str] = None,
    now: Optional[Callable[[], datetime]] = None,
) -> RequestContext:
    """Verify a JWT and map its claims to a :class:`RequestContext`.

    Args:
        token: The raw JWT (e.g. from the ``Authorization: Bearer`` header).
        jwks_uri: The IdP's JWKS endpoint. Cached by ``PyJWKClient``;
            in long-running servers, hoist construction of the
            ``PyJWKClient`` out of the per-request path.
        audience: Expected ``aud`` claim.
        issuer: Expected ``iss`` claim.
        algorithms: Allowed signing algorithms. Defaults cover the
            common asymmetric set. Reject ``HS256`` unless you really
            mean to use a shared-secret IdP.
        claim_map: Optional override of the default claim->RequestContext
            mapping. Format is ``{jwt_claim_name: "caller.field" | "jurisdiction" | "purpose"}``.
            ``caller.*`` values are nested under ``RequestContext.caller``.
        extra_purpose: Optional constant to append to the derived
            purpose (e.g. ``"retrieval"``); useful when the JWT scope
            represents permissions broadly and the call site adds the
            specific intent.
        now: Optional callable returning the current ``datetime`` used
            for the receipt's ``request.timestamp``. Defaults to
            ``datetime.now(timezone.utc)``. Inject for deterministic
            tests.

    Returns:
        A :class:`RequestContext` ready to pass into ``verify_chunks(...)``
        or ``admission_check(...)``.

    Raises:
        jwt.exceptions.InvalidTokenError: For any verification failure
            (expired, bad signature, wrong audience, wrong issuer, etc.).
    """
    _require_jwt()
    import jwt
    from jwt import PyJWKClient

    jwks_client = PyJWKClient(jwks_uri)
    signing_key = jwks_client.get_signing_key_from_jwt(token).key
    claims = jwt.decode(
        token,
        signing_key,
        algorithms=list(algorithms),
        audience=audience,
        issuer=issuer,
    )

    mapping = dict(_DEFAULT_CLAIM_MAP)
    if claim_map:
        mapping.update(claim_map)

    caller: Dict[str, Any] = {}
    jurisdiction: Optional[str] = None
    purpose: Optional[str] = None

    for claim_name, target in mapping.items():
        if claim_name not in claims:
            continue
        value = claims[claim_name]
        if target.startswith("caller."):
            field = target.split(".", 1)[1]
            caller[field] = value
        elif target == "jurisdiction":
            jurisdiction = str(value) if value is not None else None
        elif target == "purpose":
            # Some IdPs deliver scope as a space-separated string;
            # pick the first non-empty token unless the operator
            # has overridden with extra_purpose.
            if isinstance(value, str):
                tokens = value.split()
                purpose = tokens[0] if tokens else None
            else:
                purpose = str(value)
        # else: silently ignore unknown targets so the claim map can
        # carry extension keys for app-specific downstream use.

    if extra_purpose:
        purpose = extra_purpose if purpose is None else f"{purpose}:{extra_purpose}"

    ts_fn = now or (lambda: datetime.now(timezone.utc))
    timestamp = ts_fn().strftime("%Y-%m-%dT%H:%M:%SZ")

    return RequestContext(
        caller=caller,
        jurisdiction=jurisdiction,
        purpose=purpose,
        timestamp=timestamp,
    )
