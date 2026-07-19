from __future__ import annotations

import json

from iamprover.engine.solver import InvariantResult
from iamprover.engine.trust import TrustFinding


def render_text(results: list[InvariantResult]) -> str:
    lines = []
    for res in results:
        status = "PASS" if res.passed else "FAIL"
        lines.append(f"[{status}] {res.invariant.id} — {res.invariant.description}")
        for ce in res.counterexamples:
            lines.append(f"    counterexample: {ce.principal}")
            if ce.steps:
                for n, step in enumerate(ce.steps, start=1):
                    lines.append(f"        step {n}: {step.action} on {step.resource}")
                    if step.context:
                        pairs = ", ".join(f"{k} = {v}" for k, v in sorted(step.context.items()))
                        lines.append(f"            with context {pairs}")
            else:
                lines.append(f"        can perform  {ce.action}")
                lines.append(f"        on resource  {ce.resource}")
                if ce.context:
                    pairs = ", ".join(f"{k} = {v}" for k, v in sorted(ce.context.items()))
                    lines.append(f"        with context {pairs}")
    failed = sum(1 for r in results if not r.passed)
    lines.append("")
    lines.append(
        f"{len(results) - failed}/{len(results)} invariants proven"
        + (f", {failed} violated" if failed else " — no violations")
    )
    return "\n".join(lines)


def render_trust_text(findings: list[TrustFinding]) -> str:
    if not findings:
        return "no cross-account trust findings"
    lines = []
    for f in findings:
        tag = "TRUST-INFO" if f.guarded else "TRUST-FAIL"
        who = "any principal (*)" if f.public else f.trusted
        lines.append(f"[{tag}] {f.role_arn}")
        lines.append(f"        assumable by {who}")
        if f.guarded:
            lines.append(f"        guarded by   {', '.join(f.guard_keys)}")
        else:
            lines.append("        UNGUARDED — no ExternalId / org / source-account condition")
    unguarded = sum(1 for f in findings if not f.guarded)
    lines.append("")
    lines.append(
        f"{len(findings)} cross-account trust grant(s), {unguarded} unguarded"
        if unguarded
        else f"{len(findings)} cross-account trust grant(s), all guarded"
    )
    return "\n".join(lines)


def render_trust_json(findings: list[TrustFinding]) -> str:
    return json.dumps(
        [
            {
                "role": f.role_arn,
                "trusted": f.trusted,
                "public": f.public,
                "guarded": f.guarded,
                "guard_keys": f.guard_keys,
            }
            for f in findings
        ],
        indent=2,
    )


def render_json(results: list[InvariantResult]) -> str:
    payload = [
        {
            "id": res.invariant.id,
            "description": res.invariant.description,
            "passed": res.passed,
            "counterexamples": [
                {
                    "principal": ce.principal,
                    "action": ce.action,
                    "resource": ce.resource,
                    "context": ce.context,
                    **(
                        {
                            "steps": [
                                {
                                    "action": s.action,
                                    "resource": s.resource,
                                    "context": s.context,
                                }
                                for s in ce.steps
                            ]
                        }
                        if ce.steps
                        else {}
                    ),
                }
                for ce in res.counterexamples
            ],
        }
        for res in results
    ]
    return json.dumps(payload, indent=2)
