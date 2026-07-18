"""Encode IAM Condition blocks as Z3 constraints over the request context.

Supported operators: StringEquals/NotEquals, StringLike/NotLike,
ArnEquals/ArnLike (and their Not variants), Bool, IpAddress/NotIpAddress
(IPv4). Anything else returns None ("unknown") and the caller substitutes a
sound default: True for Allow statements, False for Deny statements.
"""

from __future__ import annotations

import ipaddress

import z3

from iamprover.engine.context import SOURCE_IP_KEY, Context
from iamprover.engine.patterns import matches_any
from iamprover.model import Condition


def _cidr_term(ctx: Context, value: str) -> z3.BoolRef | None:
    try:
        network = ipaddress.IPv4Network(value, strict=False)
    except (ipaddress.AddressValueError, ValueError):
        return None  # IPv6 or malformed — unknown
    ip = ctx.source_ip()
    mask = int(network.netmask)
    return (ip & mask) == int(network.network_address)


def encode_condition(cond: Condition, ctx: Context) -> z3.BoolRef | None:
    op = cond.operator
    negated = False
    if op.startswith("StringNot") or op.startswith("ArnNot") or op == "NotIpAddress":
        negated = True

    if op in ("StringEquals", "StringNotEquals"):
        var = ctx.string(cond.key)
        term = z3.Or(*[var == z3.StringVal(v) for v in cond.values])
    elif op in ("StringLike", "StringNotLike", "ArnLike", "ArnNotLike", "ArnEquals", "ArnNotEquals"):
        term = matches_any(ctx.string(cond.key), cond.values)
    elif op == "Bool":
        var = ctx.string(cond.key)
        term = z3.Or(*[var == z3.StringVal(v.lower()) for v in cond.values])
    elif op in ("IpAddress", "NotIpAddress"):
        if cond.key.lower() != SOURCE_IP_KEY:
            return None
        terms = [_cidr_term(ctx, v) for v in cond.values]
        if any(t is None for t in terms):
            return None
        term = z3.Or(*terms)
    else:
        return None

    return z3.Not(term) if negated else term


def encode_conditions(
    conditions: list[Condition], ctx: Context, unknown_default: bool
) -> z3.BoolRef:
    terms = []
    for cond in conditions:
        term = encode_condition(cond, ctx)
        terms.append(z3.BoolVal(unknown_default) if term is None else term)
    return z3.And(*terms) if terms else z3.BoolVal(True)
