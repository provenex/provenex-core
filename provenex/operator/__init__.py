"""Kubernetes operator for the Provenex Policy CRD.

A small ``kopf``-based operator that reconciles ``Policy`` custom
resources (``policies.provenex.io/v1``) into the ConfigMap each verify
pod reads. Lives in its own subpackage so importing ``provenex`` does
not pull in the Kubernetes client.

Install
-------
``pip install "provenex-core[operator]"``

Run
---
::

    kopf run -m provenex.operator.main --standalone --verbose

See [deploy/operator/](../../deploy/operator/) for the CRD manifest
and the operator Deployment.
"""

from __future__ import annotations

from typing import Dict, Optional


def _check_owner_collision(
    existing_annotations: Optional[Dict[str, str]],
    policy_name: str,
    target_cm: str,
) -> Optional[str]:
    """Decide whether the ConfigMap is owned by a different Policy.

    Returns a rejection message when the existing ConfigMap was
    annotated as owned by a Policy whose name differs from
    ``policy_name``; otherwise ``None`` (safe to overwrite).

    The helper is pure (no kubernetes-client dependency) so it can be
    unit-tested without the operator extras installed.
    """
    if existing_annotations is None:
        return None
    owner = existing_annotations.get("provenex.io/source-policy")
    if owner is None or owner == policy_name:
        return None
    return (
        f"ConfigMap/{target_cm} is already owned by Policy/{owner}; "
        f"refusing to overwrite. Use a different spec.targetConfigMap "
        f"or delete Policy/{owner} first."
    )
