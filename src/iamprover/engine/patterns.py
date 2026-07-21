"""Compile IAM wildcard patterns (`*`, `?`) into Z3 regular expressions."""

from __future__ import annotations

import re
from functools import lru_cache

import z3

_ANY_CHAR = z3.AllChar(z3.ReSort(z3.StringSort()))
_VARIABLE_RE = re.compile(r"\$\{[^}]*\}")


def expand_variables(pattern: str) -> str:
    """Replace IAM policy variables (`${aws:username}`, `${aws:PrincipalTag/x}`,
    `${*}`, ...) with `*`.

    We cannot know a variable's runtime value, so we widen it to `*`. In a
    positive Action/Resource this over-approximates the permission (sound: no
    false negatives). Callers must NOT use this for NotAction/NotResource, where
    widening would shrink the allow set — see encoder for that handling.
    """
    return _VARIABLE_RE.sub("*", pattern)


def has_variable(text: str) -> bool:
    return "${" in text


def iam_pattern_to_re(pattern: str, case_insensitive: bool = False) -> z3.ReRef:
    if case_insensitive:
        pattern = pattern.lower()
    parts: list[z3.ReRef] = []
    literal = ""
    for ch in pattern:
        if ch in "*?":
            if literal:
                parts.append(z3.Re(z3.StringVal(literal)))
                literal = ""
            parts.append(z3.Star(_ANY_CHAR) if ch == "*" else _ANY_CHAR)
        else:
            literal += ch
    if literal:
        parts.append(z3.Re(z3.StringVal(literal)))
    if not parts:
        return z3.Re(z3.StringVal(""))
    return parts[0] if len(parts) == 1 else z3.Concat(*parts)


def matches_any(value: z3.SeqRef, patterns: list[str], case_insensitive: bool = False) -> z3.BoolRef:
    if not patterns:
        return z3.BoolVal(False)
    return z3.Or(*[z3.InRe(value, iam_pattern_to_re(p, case_insensitive)) for p in patterns])


@lru_cache(maxsize=65536)
def globs_intersect(p1: str, p2: str) -> bool:
    """True iff some string matches both IAM wildcard patterns (`*`, `?`)."""
    memo: dict[tuple[int, int], bool] = {}

    def go(i: int, j: int) -> bool:
        key = (i, j)
        if key in memo:
            return memo[key]
        if i == len(p1) and j == len(p2):
            result = True
        elif i == len(p1):
            result = all(c == "*" for c in p2[j:])
        elif j == len(p2):
            result = all(c == "*" for c in p1[i:])
        elif p1[i] == "*":
            result = go(i + 1, j) or go(i, j + 1)
        elif p2[j] == "*":
            result = go(i, j + 1) or go(i + 1, j)
        elif p1[i] == "?" or p2[j] == "?" or p1[i] == p2[j]:
            result = go(i + 1, j + 1)
        else:
            result = False
        memo[key] = result
        return result

    return go(0, 0)
