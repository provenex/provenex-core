"""Azure AD (Entra ID) -> Provenex RequestContext example.

Same shape as ``okta_request_context.py`` but using Azure AD's claim
conventions. Azure AD differs from Okta in a few places:

  * Issuer is ``https://login.microsoftonline.com/<tenant>/v2.0`` (v2
    endpoint; v1 issuers don't match the same convention).
  * Audience is your app's Application (client) ID, e.g.
    ``api://abc...``.
  * Groups appear under ``groups`` only when configured on the app
    registration (token configuration → group claims).
  * The ``oid`` claim (Object ID) is the stable per-user identifier
    you want for ``caller.id``; ``sub`` is opaque per-app and not a
    durable user identifier in Entra.
  * Scopes appear under ``scp`` (delegated) or ``roles`` (app-only).

Setup
-----

::

    pip install "provenex-core[identity,server]"

Then export::

    AZURE_AD_TENANT_ID=<tenant-uuid>
    AZURE_AD_AUDIENCE=api://<app-id>

This module reads those and assembles the issuer + JWKS URIs
automatically.
"""

from __future__ import annotations

import os

from fastapi import Header, HTTPException

from provenex.integrations.identity import from_jwt


TENANT_ID = os.environ["AZURE_AD_TENANT_ID"]
AUDIENCE = os.environ["AZURE_AD_AUDIENCE"]

ISSUER = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
JWKS_URI = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"


# Override the default claim map for Azure AD's conventions: use 'oid'
# as caller.id (the durable user identifier in Entra), and use 'tid'
# as a tenant tag on caller (useful for multi-tenant deployments).
_CLAIM_MAP = {
    "oid": "caller.id",
    "tid": "caller.tenant",
    "preferred_username": "caller.username",
    "email": "caller.email",
    "roles": "caller.roles",
    "groups": "caller.groups",
    "scp": "purpose",
}


async def azure_ad_request_context(
    authorization: str = Header(...),
):
    """FastAPI dependency: validate Azure AD JWT, return RequestContext."""
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Bearer token required")
    token = authorization.split(" ", 1)[1]
    try:
        return from_jwt(
            token,
            jwks_uri=JWKS_URI,
            audience=AUDIENCE,
            issuer=ISSUER,
            claim_map=_CLAIM_MAP,
        )
    except Exception as exc:
        raise HTTPException(401, f"Invalid Azure AD token: {exc}") from exc
