# iamprover

**Formally verify security invariants over AWS IAM policies — with proofs, not pattern-matching.**

Most IAM scanners grep for known misconfigurations. `iamprover` does something stronger: it encodes
IAM policy-evaluation semantics into an SMT solver ([Z3](https://github.com/Z3Prover/z3)) and
**proves** that your declared security invariants hold — or hands you a **concrete counterexample**
(principal, action, resource) showing exactly how they break.

![iamprover demo](demo/demo.gif)

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

3. Or verify a **live account** — no Terraform required:

```bash
aws iam get-account-authorization-details > gaad.json
iamprover verify --gaad gaad.json --privesc --check-trust
```

4. Or use the GitHub Action to gate every pull request:

```yaml
- uses: hashicorp/setup-terraform@v3
- run: terraform plan -out plan && terraform show -json plan > plan.json
- uses: UTKARSH698/iamprover@v0.6.0
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

## Live accounts & cross-account trust (v0.4)

Point iamprover at a real account instead of a Terraform plan. `--gaad` ingests
the output of `aws iam get-account-authorization-details`, flattening group
memberships and managed-policy attachments and picking each policy's default
version:

```bash
aws iam get-account-authorization-details > gaad.json
iamprover verify --gaad gaad.json --invariants invariants.yaml --privesc
```

`--check-trust` analyzes every role's trust policy for grants that reach outside
its own account. External or public (`Principal: "*"`) assume-role grants are
flagged; a grant is "guarded" when scoped by `sts:ExternalId`,
`aws:PrincipalOrgID`, `aws:SourceAccount`, or similar. Allowlist known partners
with `--trusted-account`:

```bash
iamprover verify --gaad gaad.json --check-trust --trusted-account 444455556666
```

```
[TRUST-FAIL] arn:aws:iam::111122223333:role/partner-access
        assumable by arn:aws:iam::999988887777:root
        UNGUARDED — no ExternalId / org / source-account condition
[TRUST-INFO] arn:aws:iam::111122223333:role/vendor-scoped
        assumable by arn:aws:iam::444455556666:root
        guarded by   sts:ExternalId
```

**Policy variables** (`${aws:username}`, `${aws:PrincipalTag/team}`, …) are
widened to `*` in `Action`/`Resource` and treated as unknown in conditions —
always in the over-approximating direction, so they never hide a violation.
Tag-based condition keys are modeled as free request-context variables the
solver searches over.

## Bounding layers: permission boundaries, SCPs, RCPs (v0.5)

Identity- and resource-based policies only *grant* access; permission
boundaries, Service Control Policies (SCPs), and Resource Control Policies
(RCPs) only *bound* it — each must independently contain a matching `Allow`
or that path is closed, and an explicit `Deny` in any of them blocks access
outright. A permission boundary bounds identity-based access only; an RCP
bounds resource-based access only; an SCP bounds both, account-wide:

```bash
iamprover verify --account account.json --invariants invariants.yaml \
    --scp org-scp.json --scp ou-scp.json --rcp account-rcp.json
```

`--scp`/`--rcp` are repeatable — pass one file per applicable layer (e.g. one
per OU level) and each is treated as an independent cap, so the effective
bound is their intersection while a deny in any one of them still applies.
Permission boundaries attach per-principal: set `permission_boundary` on a
principal in an `--account` file, or they're resolved automatically from
`PermissionsBoundaryArn` when using `--gaad`. Absent any of these, evaluation
is identical to v0.4.

## Whole-system reachability: transitive AssumeRole chains (v0.6)

Every invariant above checks one principal's *direct* permissions. But a
principal with no direct access can still reach it by assuming a role that
has it: `--closure assume-role` widens every invariant to also cover
principals reachable through `sts:AssumeRole` chains, not just direct grants:

```bash
iamprover verify --gaad gaad.json --invariants invariants.yaml --closure assume-role
```

An edge exists between two principals when the source's identity policy
grants an assume-role action on the target *and* the target's trust policy
allows the source — both sides are checked independently, matching how AWS
actually evaluates `sts:AssumeRole`. Guarded trust conditions (`ExternalId`,
org id, source account) don't block the edge: a guard is a value the
assuming principal must supply, not a barrier to whether the relationship
exists, so it stays on the over-approximating side. Counterexamples show the
full chain:

```
[FAIL] no-s3-read
    counterexample: arn:aws:iam::111122223333:role/a
        step 1: sts:assumerole on arn:aws:iam::111122223333:role/b
        step 2: s3:getobject on arn:aws:s3:::prod-data/x
```

Chain length is bounded by `--max-hops` (default 4) — AWS environments rarely
need deep AssumeRole chains, so a bounded search gives predictable runtime on
large live-account graphs while still catching realistic escalation paths.
`--closure` is deliberately a mode, not a boolean, so future closure
relations (e.g. `iam:PassRole` into service execution) can be added as new
values without another flag.

## What is modeled (v0.6)

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
- Live-account ingestion (`--gaad`) with group/managed-policy flattening;
  cross-account trust analysis (`--check-trust`); policy variables and
  tag-based condition keys
- Permission boundaries (identity-path bound), SCPs (identity- and
  resource-path bound), and RCPs (resource-path bound), each as an
  independent, intersecting cap (`--scp`/`--rcp`, repeatable)
- Whole-system reachability (`--closure assume-role`): invariants extend over
  principals reachable through bounded `sts:AssumeRole` chains, not just
  direct grants, with the chain shown in the counterexample

**Soundness note:** unsupported condition operators degrade safely — treated as always-true on
Allow and always-false on Deny — so permissions are only ever over-approximated: iamprover may
flag violations a condition would prevent (false positives), but within the modeled fragment it
will not miss one (no false negatives). Trust the `PASS`es; investigate the `FAIL`s.

## Performance

A realistic 10,000-principal account — three invariants, full assume-role closure — verifies in
under 2.5 s end-to-end, thanks to a sound syntactic prefilter that skips provably-unsatisfiable
solver queries. Details, methodology, and worst-case numbers in
[`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).

## Documentation

| Doc | What's in it |
|---|---|
| [`examples/README.md`](examples/README.md) | Guided walkthrough of every example, with real output |
| [`docs/API.md`](docs/API.md) | Python API and full CLI reference |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Pipeline internals and the soundness invariant |
| [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) | Measured runtime at 100 / 1k / 10k principals |
| [`docs/COMPARISON.md`](docs/COMPARISON.md) | vs. Access Analyzer, Prowler, Checkov |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Setup, the one rule (never under-approximate), module map |

## Roadmap

- ~~**v0.3** — GitHub Action on the Marketplace · privilege-escalation chain detection (`iam:PassRole` → `lambda:CreateFunction`, `iam:CreateAccessKey`, …) as built-in invariants~~ ✅ shipped
- ~~**v0.4** — live-account ingestion via `aws iam get-account-authorization-details` · cross-account trust analysis · policy variables and tag-based conditions~~ ✅ shipped
- ~~**v0.5** — permission boundaries, SCPs, and RCPs as intersecting bounding layers~~ ✅ shipped
- ~~**v0.6** — access-analyzer-style reachability across the full principal graph (transitive `sts:AssumeRole` chains)~~ ✅ shipped
- **v0.7+** — richer closure relations beyond `sts:AssumeRole` (e.g. `iam:PassRole` into service execution), moving from a principal-to-principal graph toward a full identity/capability/resource attack graph

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src tests scripts
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the module map and contribution expectations.

## License

Apache-2.0
