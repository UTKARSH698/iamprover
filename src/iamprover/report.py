from __future__ import annotations

import json

from iamprover.engine.solver import InvariantResult


def render_text(results: list[InvariantResult]) -> str:
    lines = []
    for res in results:
        status = "PASS" if res.passed else "FAIL"
        lines.append(f"[{status}] {res.invariant.id} — {res.invariant.description}")
        for ce in res.counterexamples:
            lines.append(f"    counterexample: {ce.principal}")
            lines.append(f"        can perform  {ce.action}")
            lines.append(f"        on resource  {ce.resource}")
    failed = sum(1 for r in results if not r.passed)
    lines.append("")
    lines.append(
        f"{len(results) - failed}/{len(results)} invariants proven"
        + (f", {failed} violated" if failed else " — no violations")
    )
    return "\n".join(lines)


def render_json(results: list[InvariantResult]) -> str:
    payload = [
        {
            "id": res.invariant.id,
            "description": res.invariant.description,
            "passed": res.passed,
            "counterexamples": [
                {"principal": ce.principal, "action": ce.action, "resource": ce.resource}
                for ce in res.counterexamples
            ],
        }
        for res in results
    ]
    return json.dumps(payload, indent=2)
