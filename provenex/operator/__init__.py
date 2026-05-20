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
