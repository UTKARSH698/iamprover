"""Cross-account trust analysis over role trust policies.

A role's trust policy (`AssumeRolePolicyDocument`) names the principals allowed
to assume it. We flag every Allow-to-assume that reaches OUTSIDE the role's own
account — a specific external account, or `*` (any principal, anywhere) — since
those are the cross-account attack surface. A finding is "guarded" when a
recognized scoping condition is present (ExternalId, org id, source account,
principal ARN); guarded external trust is usually intentional, unguarded is not.

This is structural, not an SMT query: trust-policy principals are concrete ARNs
or `*` (IAM forbids ARN wildcards here), so no solver search is needed. Service
and federated principals are out of scope for cross-account *account* trust.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch

from iamprover.model import Account, Statement

_ASSUME_ACTIONS = (
    "sts:assumerole",
    "sts:assumerolewithsaml",
    "sts:assumerolewithwebidentity",
    "sts:*",
    "*",
)
_GUARD_KEYS = {
    "sts:externalid",
    "aws:principalorgid",
    "aws:principalorgpaths",
    "aws:sourceaccount",
    "aws:sourcearn",
    "aws:principalarn",
}


@dataclass
class TrustFinding:
    role_arn: str
    trusted: str  # the external principal ARN, or "*"
    public: bool  # trusted == "*"
    guarded: bool  # a recognized scoping condition is present
    guard_keys: list[str] = field(default_factory=list)


def _allows_assume(stmt: Statement) -> bool:
    if stmt.effect != "Allow":
        return False
    return any(
        fnmatch(action.lower(), pattern)
        for action in stmt.actions
        for pattern in _ASSUME_ACTIONS
    )


def _account_of(principal: str) -> str | None:
    if principal.startswith("arn:"):
        parts = principal.split(":")
        return parts[4] if len(parts) >= 5 and parts[4] else None
    return None


def analyze_trust(account: Account, trusted_accounts: set[str] | None = None) -> list[TrustFinding]:
    trusted_accounts = trusted_accounts or set()
    findings: list[TrustFinding] = []

    for principal in account.principals:
        if principal.trust_policy is None:
            continue
        role_account = principal.account_id
        for stmt in principal.trust_policy.statements:
            if not _allows_assume(stmt):
                continue
            guard_keys = sorted(
                {c.key for c in stmt.conditions if c.key.lower() in _GUARD_KEYS}
            )
            guarded = bool(guard_keys)
            for trusted in stmt.principals:
                if trusted == "*":
                    findings.append(
                        TrustFinding(principal.arn, "*", True, guarded, guard_keys)
                    )
                    continue
                trusted_account = _account_of(trusted)
                if trusted_account is None:
                    continue  # service/federated principal — out of scope
                if trusted_account == role_account or trusted_account in trusted_accounts:
                    continue  # same-account or explicitly allowlisted
                findings.append(
                    TrustFinding(principal.arn, trusted, False, guarded, guard_keys)
                )

    return findings
