from __future__ import annotations

from dataclasses import dataclass, field

ANONYMOUS_ARN = "anonymous"


@dataclass
class Condition:
    operator: str  # e.g. "StringEquals", "Bool", "IpAddress"
    key: str  # e.g. "aws:SourceIp"
    values: list[str]


@dataclass
class Statement:
    effect: str  # "Allow" | "Deny"
    actions: list[str] = field(default_factory=list)
    not_actions: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    not_resources: list[str] = field(default_factory=list)
    conditions: list[Condition] = field(default_factory=list)
    principals: list[str] = field(default_factory=list)  # resource-based policies only


@dataclass
class Policy:
    name: str
    statements: list[Statement]


@dataclass
class Principal:
    arn: str
    policies: list[Policy]
    # Role trust policy (AssumeRolePolicyDocument); None for users/groups.
    trust_policy: Policy | None = None

    @property
    def account_id(self) -> str | None:
        """The 12-digit account id embedded in an `arn:aws:iam::<id>:...` ARN."""
        parts = self.arn.split(":")
        return parts[4] if len(parts) >= 5 and parts[4] else None


@dataclass
class Account:
    principals: list[Principal]
    resource_policies: list[Policy] = field(default_factory=list)

    def principal(self, arn: str) -> Principal:
        for p in self.principals:
            if p.arn == arn:
                return p
        raise KeyError(arn)
