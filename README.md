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

3. Or use the GitHub Action to gate every pull request:

```yaml
- uses: hashicorp/setup-terraform@v3
- run: terraform plan -out plan && terraform show -json plan > plan.json
- uses: UTKARSH698/iamprover@v0.3.0
  with:
    tf-plan: plan.json
    invariants: invariants.yaml
    privesc: "true"                # built-in privilege-escalation invariants
    privesc-unless: "arn:aws:iam::*:role/admin-*"
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

  - id: no-passrole-lambda-escalation
    description: No single principal may both pass a role and create a Lambda
    forbid_chain:                  # fails only if ONE principal can do EVERY step
      - action: "iam:PassRole"
      - action: "lambda:CreateFunction"
```

## Privilege-escalation invariants (v0.3)

`--privesc` enables a built-in catalog of the well-known AWS IAM escalation
paths — policy-version rewrites, credential minting, policy attachment,
trust-policy rewrites, code hijacking, and the `iam:PassRole` chains into
Lambda, EC2, CloudFormation, Glue, and SageMaker:

```bash
iamprover verify --tf-plan plan.json --privesc \
    --privesc-unless "arn:aws:iam::111122223333:role/ops-admin"
```

Chains are verified compositionally: `privesc-passrole-ec2` fails only if the
solver finds a **single principal** allowed *both* `iam:PassRole` *and*
`ec2:RunInstances` (each step checked as an independent request, so condition
gates still count) — counterexamples list every step:

```
[FAIL] privesc-passrole-ec2 — Principal can launch an EC2 instance with a privileged instance profile ...
    counterexample: arn:aws:iam::111122223333:role/dev
        step 1: iam:passrole on *
        step 2: ec2:runinstances on *
```

## What is modeled (v0.3)

- Allow/Deny with explicit-deny-overrides-allow and default deny
- `Action` / `NotAction` / `Resource` / `NotResource` with `*` and `?` wildcards
- Case-insensitive action matching (as IAM does it)
- `Condition` blocks: `StringEquals/Like` (and Not/Arn variants), `Bool`, `IpAddress`/`NotIpAddress`
  (IPv4 CIDR, exact via bitvector encoding). The solver searches over all request contexts and
  counterexamples include the context (`with context aws:multifactorauthpresent = true, …`);
  invariants can pin context with a `where:` clause
- Resource-based policies (e.g. bucket policies) with `Principal: "*"` or exact ARNs, unioned with
  identity-based grants; `--check-anonymous` verifies invariants for an unauthenticated principal
  (catches public grants)
- Terraform plans: inline policies, managed policies via attachments (resolved by ARN or
  configuration reference), and `aws_s3_bucket_policy`
- Invariant exemptions by exact ARN or glob
- Multi-step `forbid_chain` invariants (one principal holding every step) and a
  built-in privilege-escalation catalog (`--privesc`)

**Soundness note:** unsupported condition operators degrade safely — treated as always-true on
Allow and always-false on Deny — so permissions are only ever over-approximated: iamprover may
flag violations a condition would prevent (false positives), but within the modeled fragment it
will not miss one (no false negatives). Trust the `PASS`es; investigate the `FAIL`s.

## Roadmap

- ~~**v0.3** — GitHub Action on the Marketplace · privilege-escalation chain detection (`iam:PassRole` → `lambda:CreateFunction`, `iam:CreateAccessKey`, …) as built-in invariants~~ ✅ shipped
- **v0.4** — live-account ingestion via `aws iam get-account-authorization-details` · cross-account trust analysis · policy variables and tag-based conditions

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

Apache-2.0
