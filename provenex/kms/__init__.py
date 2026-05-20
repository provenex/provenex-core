"""KMS / HSM signer adapters (optional extras).

Each adapter implements :class:`provenex.core.receipt.ReceiptSigner` so
the signing key never has to leave its KMS / HSM and the verify pods
stay key-material-free. The receipt-format ``signature.algorithm``
discriminator is set by each adapter so an auditor reading the receipt
knows which verification path to take.

Install
-------
- ``pip install "provenex-core[kms-aws]"`` for AWS KMS
- ``pip install "provenex-core[kms-gcp]"`` for Google Cloud KMS
- ``pip install "provenex-core[kms-azure]"`` for Azure Key Vault
- ``pip install "provenex-core[pkcs11]"`` for a customer-owned HSM

Algorithm support matrix
------------------------

+-------------+-----------+-------------------+------------------------+
| Adapter     | Ed25519   | RSASSA-PSS-SHA256 | Notes                  |
+=============+===========+===================+========================+
| AWS KMS     | yes (jun  | yes               | use Ed25519 by default |
|             | 2024+)    |                   | per key spec           |
+-------------+-----------+-------------------+------------------------+
| GCP KMS     | yes       | yes               | preferred path is      |
|             |           |                   | Ed25519                |
+-------------+-----------+-------------------+------------------------+
| Azure Key   | not GA    | yes               | RSA-PSS is the         |
| Vault       |           |                   | production path        |
+-------------+-----------+-------------------+------------------------+
| PKCS#11 HSM | depends   | yes (universal)   | whatever the           |
|             | on token  |                   | underlying token       |
|             |           |                   | exposes                |
+-------------+-----------+-------------------+------------------------+

The four adapters expose the same shape so callers can swap them in
config. None of them require holding the private key in-process; all
signing operations call out to the KMS / HSM.
"""

from .common import KMSConfigurationError

__all__ = ["KMSConfigurationError"]
