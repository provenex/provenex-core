"""Example: configuring verification policies for different threat models.

Three scenarios:
    1. Development mode  — flag everything, block nothing. Lets the team see
       what would happen in production.
    2. Production mode   — block unauthorized and tampered, flag everything
       else. The reasonable default for most enterprise RAG.
    3. High-assurance    — block every non-VERIFIED outcome. Used in
       customer-facing answers where any deviation is unacceptable.
"""

from __future__ import annotations

from provenex.policy.policy import VerificationPolicy


DEV_POLICY = VerificationPolicy(
    block_stale=False,
    block_unauthorized=False,
    block_unverified=False,
    block_tampered=False,
    # Flag everything so the team can see issues in the receipt.
    flag_stale=True,
    flag_unauthorized=True,
    flag_unverified=True,
    flag_tampered=True,
)


PROD_POLICY = VerificationPolicy(
    block_stale=False,           # legal/research teams want to see old precedent
    block_unauthorized=True,     # never serve content the user can't access
    block_unverified=False,      # tolerate non-Provenex chunks (transitional)
    block_tampered=True,         # alarm condition
    flag_stale=True,
    flag_unauthorized=True,
    flag_unverified=True,
    flag_tampered=True,
)


HIGH_ASSURANCE_POLICY = VerificationPolicy(
    block_stale=True,
    block_unauthorized=True,
    block_unverified=True,       # every chunk MUST come through Provenex
    block_tampered=True,
    flag_stale=True,
    flag_unauthorized=True,
    flag_unverified=True,
    flag_tampered=True,
)


if __name__ == "__main__":
    for name, p in [
        ("dev", DEV_POLICY),
        ("prod", PROD_POLICY),
        ("high-assurance", HIGH_ASSURANCE_POLICY),
    ]:
        print(f"\n{name}:")
        print(f"  block_stale         = {p.block_stale}")
        print(f"  block_unauthorized  = {p.block_unauthorized}")
        print(f"  block_unverified    = {p.block_unverified}")
        print(f"  block_tampered      = {p.block_tampered}")
