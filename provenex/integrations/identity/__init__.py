"""Identity-provider recipes that build a :class:`RequestContext`.

Designed to plug into the request-handling layer of an app (FastAPI
dependency, Starlette middleware, Django middleware, plain
``before_request`` hook) so the verify / admit calls downstream see a
populated ``RequestContext`` with caller / jurisdiction / role.

This module ships *recipes*, not products. Each provider has its own
JWKS endpoint and claim conventions; the helpers here are short,
opinionated, and easy to read so an operator can copy and adapt them
to local conventions.

Currently:

    * :func:`from_jwt` - generic JWT extractor that maps standard
      claims to ``RequestContext`` fields.

Examples
--------

A working Okta-flavoured example lives at
``examples/okta_request_context.py``; an Azure AD one at
``examples/azure_ad_request_context.py``.
"""

from .jwt_recipe import from_jwt

__all__ = ["from_jwt"]
