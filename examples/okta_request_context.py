"""Okta -> Provenex RequestContext example.

Drop-in FastAPI dependency that pulls the Authorization bearer JWT,
verifies it against Okta's JWKS, and produces a Provenex
:class:`RequestContext`. Pass the result directly to
``verify_chunks_async`` / ``admission_check``.

Setup
-----

::

    pip install "provenex-core[identity,server]"

Configure your Okta app with an OIDC API access policy. Note your:

  * Authorization server URL (``https://<org>.okta.com/oauth2/<server>``)
  * Audience (``api://<api>`` or your custom audience)

Then export those as env vars and use this dependency in your routes::

    from fastapi import Depends, FastAPI
    from examples.okta_request_context import okta_request_context

    app = FastAPI()

    @app.post("/v1/verify")
    async def verify(
        body: dict,
        rc = Depends(okta_request_context),
    ):
        result = await verify_chunks_async(
            chunks=body["chunks"],
            index=...,
            signer=...,
            request_context=rc,
        )
        ...

The provenex.integrations.identity.from_jwt helper does the JWKS
fetch + signature verification + claim extraction; this file is the
~30-line FastAPI wiring around it.

Claim conventions
-----------------

Okta's defaults:

  * ``sub``: user UUID → ``caller.id``
  * ``preferred_username``: human-readable username → ``caller.username``
  * ``email`` → ``caller.email``
  * ``groups``: list of group memberships → ``caller.groups`` (only when
    the access token's claim set explicitly includes ``groups``; configure
    on the access policy if you want this)
  * ``locale``: e.g. ``"en-US"`` → ``jurisdiction`` (rough proxy; in
    production set jurisdiction from a custom claim populated from
    your HR system)
  * ``scp``: space-separated scopes → first scope is mapped to
    ``purpose``

Override any of these via the ``claim_map=`` argument to
:func:`provenex.integrations.identity.from_jwt`.
"""

from __future__ import annotations

import os

from fastapi import Header, HTTPException

from provenex.integrations.identity import from_jwt


OKTA_ISSUER = os.environ["OKTA_ISSUER"]  # e.g. https://acme.okta.com/oauth2/default
OKTA_AUDIENCE = os.environ.get("OKTA_AUDIENCE", "api://default")
OKTA_JWKS_URI = OKTA_ISSUER.rstrip("/") + "/v1/keys"


async def okta_request_context(
    authorization: str = Header(...),
):
    """FastAPI dependency: validate Okta JWT, return RequestContext."""
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Bearer token required")
    token = authorization.split(" ", 1)[1]
    try:
        return from_jwt(
            token,
            jwks_uri=OKTA_JWKS_URI,
            audience=OKTA_AUDIENCE,
            issuer=OKTA_ISSUER,
            # Okta scopes land under 'scp' rather than 'scope' in
            # access tokens; the default claim_map already covers
            # both, but it's worth being explicit for an example.
        )
    except Exception as exc:
        raise HTTPException(401, f"Invalid Okta token: {exc}") from exc
