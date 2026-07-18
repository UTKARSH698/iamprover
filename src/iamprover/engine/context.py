"""Request-context variables shared across one solver query.

Every condition key becomes a free Z3 variable: the solver searches over all
possible request contexts. `aws:SourceIp` is a 32-bit bitvector so CIDR
membership is exact; every other key is a string (IAM context values are
strings; Bool conditions compare against "true"/"false").
"""

from __future__ import annotations

import ipaddress

import z3

SOURCE_IP_KEY = "aws:sourceip"


class Context:
    def __init__(self, prefix: str = "") -> None:
        # Distinct prefixes keep chain steps' contexts independent: each step is
        # a separate request, so sharing Z3 variables would under-approximate.
        self.prefix = prefix
        self.string_vars: dict[str, z3.SeqRef] = {}
        self.ip_var: z3.BitVecRef | None = None

    def string(self, key: str) -> z3.SeqRef:
        key = key.lower()
        if key not in self.string_vars:
            self.string_vars[key] = z3.String(f"{self.prefix}ctx[{key}]")
        return self.string_vars[key]

    def source_ip(self) -> z3.BitVecRef:
        if self.ip_var is None:
            self.ip_var = z3.BitVec(f"{self.prefix}ctx[{SOURCE_IP_KEY}]", 32)
        return self.ip_var

    def constrain(self, key: str, value: str) -> z3.BoolRef:
        """Pin a context key to a concrete value (invariant `where` clause)."""
        if key.lower() == SOURCE_IP_KEY:
            return self.source_ip() == int(ipaddress.IPv4Address(value))
        return self.string(key) == z3.StringVal(value)

    def assignments(self, model: z3.ModelRef) -> dict[str, str]:
        """Extract the context values the solver chose for a counterexample."""
        out: dict[str, str] = {}
        decls = {d.name() for d in model.decls()}
        for key, var in self.string_vars.items():
            if var.decl().name() in decls:
                out[key] = model[var].as_string()
        if self.ip_var is not None and self.ip_var.decl().name() in decls:
            out[SOURCE_IP_KEY] = str(ipaddress.IPv4Address(model[self.ip_var].as_long()))
        return out
