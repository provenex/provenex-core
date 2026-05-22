"""kopf operator: reconcile Policy CRs into the ConfigMap verify pods read.

Behaviour
---------

For each ``policies.provenex.io/v1`` ``Policy`` resource the operator
sees:

    1. Parse + validate ``spec.policy`` via :class:`provenex.Policy`.
    2. Compute the deterministic ``policy_version_hash`` for the parsed
       policy (the same hash that the verify pods will record on every
       receipt issued under this policy).
    3. Create or update the ConfigMap named by ``spec.targetConfigMap``,
       writing the validated YAML under ``data[<spec.fileName>]`` and
       annotating it with the computed hash plus the owning Policy CR.
    4. Patch ``status`` on the Policy CR (Accepted/Rejected, the hash,
       the observed generation).

The operator never deletes a ConfigMap. Removing a Policy CR removes
the ownership annotation; cleanup is intentional (operators may need
the ConfigMap to stick around long enough for verify pods to roll over).

Out of scope
------------

- Multi-namespace fan-out
- Per-tenant routing (Phase 3.2 handles that on the server side)
- Drift webhook (Phase 3.3 is the index-side detector)
"""

from __future__ import annotations

from typing import Any, Dict

try:  # optional dep
    import kopf  # type: ignore
    import kubernetes  # type: ignore
except ImportError as _exc:  # pragma: no cover - operator extras not installed
    raise ImportError(
        "provenex.operator requires the [operator] extra. "
        'Install with: pip install "provenex-core[operator]"'
    ) from _exc


_GROUP = "provenex.io"
_VERSION = "v1"
_PLURAL = "policies"


@kopf.on.create(_GROUP, _VERSION, _PLURAL)
@kopf.on.update(_GROUP, _VERSION, _PLURAL)
def reconcile_policy(
    spec: Dict[str, Any],
    name: str,
    namespace: str,
    meta: Dict[str, Any],
    logger,
    **_: Any,
) -> Dict[str, Any]:
    """Reconcile one Policy CR into its ConfigMap.

    Returns the dict that ``kopf`` patches onto ``status``. On
    validation failure we still return Rejected status (and don't
    touch the ConfigMap), so the operator surfaces the error in
    ``kubectl describe`` without paging.
    """
    import tempfile

    from provenex.policy.unified import Policy
    from provenex.policy.evaluator import compute_policy_version_hash

    body = spec.get("policy", "")
    target_cm = spec.get("targetConfigMap", "provenex-policy")
    file_name = spec.get("fileName", "policy.yaml")
    if not body or not target_cm:
        return {
            "phase": "Rejected",
            "message": "spec.policy and spec.targetConfigMap are required",
        }

    try:
        # Policy.from_yaml only accepts a file path; write to a tmpfile.
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=True
        ) as tf:
            tf.write(body)
            tf.flush()
            policy = Policy.from_yaml(tf.name)
    except Exception as exc:
        logger.warning("Policy %s/%s rejected: %s", namespace, name, exc)
        return {
            "phase": "Rejected",
            "message": f"validation failed: {exc}",
            "observedGeneration": meta.get("generation"),
        }

    policy_hash = compute_policy_version_hash(policy)

    core = kubernetes.client.CoreV1Api()
    cm_body = kubernetes.client.V1ConfigMap(
        metadata=kubernetes.client.V1ObjectMeta(
            name=target_cm,
            namespace=namespace,
            annotations={
                "provenex.io/source-policy": name,
                "provenex.io/policy-version-hash": policy_hash,
            },
        ),
        data={file_name: body},
    )

    # Collision check: if the target ConfigMap exists and was created
    # by a DIFFERENT Policy CR (per the source-policy annotation),
    # refuse to overwrite. Without this guard the second Policy would
    # silently overwrite the first, leaving verify pods enforcing
    # whichever policy reconciled last.
    from . import _check_owner_collision

    try:
        existing = core.read_namespaced_config_map(target_cm, namespace)
    except kubernetes.client.exceptions.ApiException as exc:
        if exc.status == 404:
            existing = None
        else:
            raise
    existing_annotations = (
        getattr(existing.metadata, "annotations", None)
        if existing is not None
        else None
    )
    collision_msg = _check_owner_collision(
        existing_annotations, policy_name=name, target_cm=target_cm
    )
    if collision_msg is not None:
        logger.warning(
            "Policy %s/%s rejected: %s", namespace, name, collision_msg
        )
        return {
            "phase": "Rejected",
            "message": collision_msg,
            "observedGeneration": meta.get("generation"),
        }

    try:
        core.replace_namespaced_config_map(target_cm, namespace, cm_body)
    except kubernetes.client.exceptions.ApiException as exc:
        if exc.status == 404:
            core.create_namespaced_config_map(namespace, cm_body)
        else:
            raise

    logger.info(
        "Policy %s/%s applied to ConfigMap %s (hash=%s)",
        namespace, name, target_cm, policy_hash[:12],
    )
    return {
        "phase": "Accepted",
        "message": f"Accepted by ConfigMap/{target_cm}",
        "policyVersionHash": policy_hash,
        "observedGeneration": meta.get("generation"),
    }
