from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Statement:
    effect: str  # "Allow" | "Deny"
    actions: list[str] = field(default_factory=list)
    not_actions: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    not_resources: list[str] = field(default_factory=list)
    has_condition: bool = False


@dataclass
class Policy:
    name: str
    statements: list[Statement]


@dataclass
class Principal:
    arn: str
    policies: list[Policy]


@dataclass
class Account:
    principals: list[Principal]

    def principal(self, arn: str) -> Principal:
        for p in self.principals:
            if p.arn == arn:
                return p
        raise KeyError(arn)
