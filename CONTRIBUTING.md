# Contributing

Contributions are welcome — the issue tracker labels
[`good first issue`](https://github.com/UTKARSH698/iamprover/labels/good%20first%20issue)
for scoped starting points.

## Setup

```bash
git clone https://github.com/UTKARSH698/iamprover
cd iamprover
pip install -e ".[dev]"
pytest          # all tests should pass before and after your change
ruff check src tests scripts
```

## The one rule: never under-approximate

iamprover's value is that a `PASS` is a proof. That only holds because every modeling gap
errs in one direction: **permissions are only ever over-approximated.**

- An unknown condition operator is treated as always-true on `Allow`, always-false on `Deny`.
- A policy variable widens to `*` in positive positions and is dropped from `Not*` positions.
- A guarded trust relationship still counts as an assume-role edge.

If your change could ever *suppress* a true violation — a false negative — it is wrong,
even if it removes noise. When in doubt, widen. See the soundness section in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Where things live

| Area | Files |
|---|---|
| IAM evaluation semantics (Z3) | `src/iamprover/engine/encoder.py`, `patterns.py`, `conditions.py`, `context.py` |
| Invariant checking / counterexamples | `src/iamprover/engine/solver.py` |
| AssumeRole reachability | `src/iamprover/engine/reachability.py` |
| Trust-policy analysis | `src/iamprover/engine/trust.py` |
| Input parsing (Terraform / GAAD / JSON) | `src/iamprover/parsers/` |
| CLI and output | `src/iamprover/cli.py`, `report.py` |

Parsers normalize shape only; anything semantic belongs in the encoder. New input formats
should produce `model.Account` and touch nothing else.

## Expectations

- Every behavior change comes with a test (`tests/` mirrors the module layout).
- Soundness-relevant changes should include a test asserting the over-approximating
  direction (see `tests/test_variables.py` for the pattern).
- Keep the pipeline stages (parse → model → encode → solve → report) separate.
- `pytest` and `ruff check` must pass; CI runs both on every PR.
