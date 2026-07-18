# iamprover

**Formally verify security invariants over AWS IAM policies — with proofs, not pattern-matching.**

Most IAM scanners grep for known misconfigurations. `iamprover` does something stronger: it encodes
IAM policy-evaluation semantics into an SMT solver ([Z3](https://github.com/Z3Prover/z3)) and
**proves** that your declared security invariants hold — or hands you a **concrete counterexample**
(principal, action, resource) showing exactly how they break.

```
[FAIL] prod-data-read-restricted — Only the data-team role may read the prod-data bucket
    counterexample: arn:aws:iam::111122223333:role/ci-runner
        can perform  s3:getobject
        on resource  arn:aws:s3:::prod-data/A

[PASS] audit-logs-untouchable — No principal may perform any S3 action on the audit-logs bucket
[PASS] no-iam-mutation — No principal may mutate IAM (privilege-escalation surface)

2/3 invariants proven, 1 violated
```

The `[PASS]` lines are not "no findings" — they are proofs over *all* possible actions and
resources, including every wildcard expansion.

## Why

Individually-correct IAM policies compose into globally-unsafe states: a broad `s3:Get*` on one
role quietly bypasses the least-privilege story your prod bucket policy tells. This tool grew out
of research on exactly that failure mode —
[*Security Invariants in Distributed Cloud Systems*](https://doi.org/10.5281/zenodo.20099386),
which model-checks how per-service security enforcement breaks under cross-service composition.
`iamprover` applies the same idea to real cloud policies: declare system-level invariants, verify
them mechanically, get violation traces when they fail.

## Install

```bash
pip install iamprover
```

## Quickstart

1. Describe your principals and their policies (or point at a Terraform plan):

```bash
iamprover verify --account examples/account.json --invariants examples/invariants.yaml
```

2. Or gate a Terraform change in CI:

```bash
terraform show -json plan > plan.json
iamprover verify --tf-plan plan.json --invariants invariants.yaml   # exit 2 on violation
```

Invariants are declared in YAML:

```yaml
invariants:
  - id: prod-data-read-restricted
    description: Only the data-team role may read objects in the prod-data bucket
    forbid:
      action: "s3:GetObject"
      resource: "arn:aws:s3:::prod-data/*"
    unless_principal:
      - "arn:aws:iam::111122223333:role/data-team"
```

## What is modeled (v0.1)

- Allow/Deny with explicit-deny-overrides-allow and default deny
- `Action` / `NotAction` / `Resource` / `NotResource` with `*` and `?` wildcards
- Case-insensitive action matching (as IAM does it)
- Invariant exemptions by exact ARN or glob

**Soundness note:** `Condition` blocks are not yet modeled — a condition-guarded Allow is treated
as always in effect. This over-approximates permissions, so iamprover may flag violations a
condition would prevent (false positives), but within the modeled fragment it will not miss one
(no false negatives). Trust the `PASS`es; investigate the `FAIL`s.

## Roadmap

- **v0.2** — `Condition` modeling (IP, MFA, principal tags subset) · managed-policy attachments in the Terraform parser · resource-based policies (bucket policies)
- **v0.3** — GitHub Action on the Marketplace · privilege-escalation chain detection (`iam:PassRole` → `lambda:CreateFunction`, `iam:CreateAccessKey`, …) as built-in invariants
- **v0.4** — live-account ingestion via `aws iam get-account-authorization-details` · cross-account trust analysis

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

Apache-2.0
