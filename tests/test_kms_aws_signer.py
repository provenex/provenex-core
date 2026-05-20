"""AwsKmsSigner integration test against a moto-mocked KMS.

Skipped if ``moto`` isn't installed (it's a test-only dep; ``[dev]``
pulls it in). Exercises the full round-trip: create a KMS RSA key in
the mock, build the signer, sign a payload, verify offline via the
adapter's verify() (which uses the cached public key, no KMS round
trip).
"""

from __future__ import annotations

import pytest

moto = pytest.importorskip("moto")
pytest.importorskip("boto3")
pytest.importorskip("cryptography")


@pytest.fixture
def aws_rsa_key():
    """Stand up a mock AWS KMS RSA_3072 key for SIGN_VERIFY."""
    import boto3
    from moto import mock_aws

    with mock_aws():
        client = boto3.client("kms", region_name="us-east-1")
        resp = client.create_key(
            KeyUsage="SIGN_VERIFY",
            KeySpec="RSA_3072",
        )
        key_id = resp["KeyMetadata"]["KeyId"]
        yield key_id, client


def test_signs_and_verifies_offline(aws_rsa_key):
    from provenex.kms.aws import AwsKmsSigner
    from provenex.kms.common import ALGORITHM_RSA_PSS_SHA256

    key_id, client = aws_rsa_key
    signer = AwsKmsSigner(key_id=key_id, client=client)

    assert signer.algorithm == ALGORITHM_RSA_PSS_SHA256

    payload = b"provenex receipt canonical payload"
    signature = signer.sign(payload)
    # Round-trip: the cached public key verifies what the KMS sign produced.
    assert signer.verify(payload, signature) is True
    # Sanity: a tampered payload fails verification.
    assert signer.verify(payload + b"X", signature) is False


def test_refuses_symmetric_key():
    """A symmetric (ENCRYPT_DECRYPT) key has no SIGN_VERIFY usage."""
    import boto3
    from moto import mock_aws

    from provenex.kms.aws import AwsKmsSigner
    from provenex.kms.common import KMSConfigurationError

    with mock_aws():
        client = boto3.client("kms", region_name="us-east-1")
        resp = client.create_key(KeyUsage="ENCRYPT_DECRYPT")
        with pytest.raises(KMSConfigurationError):
            AwsKmsSigner(key_id=resp["KeyMetadata"]["KeyId"], client=client)


def test_refuses_unsupported_key_spec():
    """An ECC key spec is rejected today (RSA-PSS or Ed25519 only)."""
    import boto3
    from moto import mock_aws

    from provenex.kms.aws import AwsKmsSigner
    from provenex.kms.common import KMSConfigurationError

    with mock_aws():
        client = boto3.client("kms", region_name="us-east-1")
        resp = client.create_key(KeyUsage="SIGN_VERIFY", KeySpec="ECC_NIST_P256")
        with pytest.raises(KMSConfigurationError):
            AwsKmsSigner(key_id=resp["KeyMetadata"]["KeyId"], client=client)


def test_receipt_canonical_payload_signs_and_verifies(aws_rsa_key):
    """End-to-end: sign a real receipt canonical payload, verify it.

    This is the path the verify pods exercise: build a receipt, finalize
    with the AwsKmsSigner, then ship the receipt JSON to an auditor who
    only has the public key.
    """
    import json

    from provenex.core.receipt import ReceiptBuilder
    from provenex.kms.aws import AwsKmsSigner

    key_id, client = aws_rsa_key
    signer = AwsKmsSigner(key_id=key_id, client=client)

    builder = ReceiptBuilder()
    receipt = builder.finalize(output_text="", signer=signer)
    rec_dict = receipt.to_dict()

    # Reconstruct the canonical payload the signer hashed and re-verify
    # via the public key (cached on the signer).
    payload_dict = dict(rec_dict)
    payload_dict.pop("signature", None)
    payload = json.dumps(
        payload_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    assert signer.verify(payload, rec_dict["signature"]["value"]) is True
    assert rec_dict["signature"]["algorithm"] == "rsa-pss-sha256"
