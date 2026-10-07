"""Score iamprover results against IAM Vulnerable's scenarios.

    python score.py plan.json results-none.json results-all.json

Each scenario NAME deploys a user `NAME-user` and/or role `NAME-role` carrying
the vulnerable policy; it counts as detected if either is flagged by any
invariant. Scenarios named fp* are false-positive traps: they must NOT be
flagged. Prints a summary and a Markdown table (used in docs/VALIDATION.md).
"""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ACCOUNT = "111122223333"


def flagged_by(results_path: str) -> dict[str, set[str]]:
    flagged: dict[str, set[str]] = defaultdict(set)
    for result in json.loads(Path(results_path).read_text(encoding="utf-8")):
        for ce in result["counterexamples"]:
            flagged[ce["principal"]].add(result["id"])
    return flagged


def scenarios(plan_path: str) -> dict[str, list[str]]:
    plan = json.loads(Path(plan_path).read_text(encoding="utf-8"))
    out: dict[str, list[str]] = {}
    for rc in plan["resource_changes"]:
        if rc["type"] not in ("aws_iam_user", "aws_iam_role"):
            continue
        after = rc["change"]["after"]
        kind = "user" if rc["type"] == "aws_iam_user" else "role"
        name = after["name"]
        arn = f"arn:aws:iam::{ACCOUNT}:{kind}{after.get('path') or '/'}{name}"
        out.setdefault(re.sub(r"-(user|role)$", "", name), []).append(arn)
    return out


def main() -> None:
    # The table uses ✓ / —, which a legacy Windows console encoding can't print.
    sys.stdout.reconfigure(encoding="utf-8")
    plan_path, *result_paths = sys.argv[1:]
    labels = ["no closure", "--closure all"][: len(result_paths)]
    runs = [flagged_by(p) for p in result_paths]
    scen = scenarios(plan_path)

    rows = []
    for name, arns in sorted(scen.items(), key=lambda kv: kv[0].lower()):
        trap = name.lower().startswith("fp")
        hits = [set().union(*(run.get(a, set()) for a in arns)) for run in runs]
        rows.append((name, trap, hits))

    for i, label in enumerate(labels):
        vuln = [r for r in rows if not r[1]]
        traps = [r for r in rows if r[1]]
        detected = sum(1 for r in vuln if r[2][i])
        clean = sum(1 for r in traps if not r[2][i])
        print(f"{label}: detected {detected}/{len(vuln)} vulnerable scenarios, "
              f"{clean}/{len(traps)} false-positive traps clean")

    print("\n| Scenario | " + " | ".join(labels) + " | Caught by (with closure) |")
    print("|---|" + "---|" * len(labels) + "---|")
    for name, trap, hits in rows:
        marks = []
        for h in hits:
            if trap:
                marks.append("flagged (FP)" if h else "clean ✓")
            else:
                marks.append("✓" if h else "—")
        ids = sorted(hits[-1])
        caught = ", ".join(f"`{i}`" for i in ids[:3]) + (f" +{len(ids) - 3}" if len(ids) > 3 else "")
        print(f"| `{name}`{' (FP trap)' if trap else ''} | " + " | ".join(marks) + f" | {caught} |")


if __name__ == "__main__":
    main()
