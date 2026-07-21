# End-to-end walkthrough

Every command below runs offline against files in this directory — no AWS account needed.
Outputs shown are real (byte-for-byte from v0.6, minus terminal encoding).

```bash
pip install iamprover
```

## 1. Prove invariants over an account — and get a counterexample

[`account.json`](account.json) describes four principals: a `data-team` role scoped to the
prod-data bucket, a `ci-runner` role with a broad `s3:Get*`, an MFA-gated `ops-admin`, and
an `intern` user — plus a public-site bucket policy. [`invariants.yaml`](invariants.yaml) declares what should be true of
the *whole account*.

```bash
iamprover verify --account account.json --invariants invariants.yaml
```

```
[FAIL] prod-data-read-restricted — Only the data-team role may read objects in the prod-data bucket
    counterexample: arn:aws:iam::111122223333:role/ci-runner
        can perform  s3:getobject
        on resource  arn:aws:s3:::prod-data/
[PASS] audit-logs-untouchable — No principal may perform any S3 action on the audit-logs bucket
[PASS] no-iam-mutation-without-mfa — No principal may mutate IAM without MFA (privilege-escalation surface)
[PASS] prod-data-never-public — Unauthenticated principals must never reach prod-data (run with --check-anonymous)

3/4 invariants proven, 1 violated
```

Exit code is `2` — in CI, this fails the build.

Note what happened: `ci-runner`'s policy never mentions `prod-data`. Its `s3:Get*` on
`arn:aws:s3:::*` composes with nothing else to violate an invariant its author never
considered. The `[PASS]` lines are proofs over *all* actions, resources, and request
contexts in the modeled fragment — not "no findings."

## 2. Fix it with an organization-level SCP

[`scp.json`](scp.json) is a Service Control Policy with an org-wide explicit Deny on
reading prod-data. A Deny in *any* layer is global:

```bash
iamprover verify --account account.json --invariants invariants.yaml --scp scp.json
```

```
[PASS] prod-data-read-restricted — Only the data-team role may read objects in the prod-data bucket
[PASS] audit-logs-untouchable — No principal may perform any S3 action on the audit-logs bucket
[PASS] no-iam-mutation-without-mfa — No principal may mutate IAM without MFA (privilege-escalation surface)
[PASS] prod-data-never-public — Unauthenticated principals must never reach prod-data (run with --check-anonymous)

4/4 invariants proven — no violations
```

The same FAIL→PASS flip works with a permission boundary on the principal
(`permission_boundary` in the account file) or an RCP (`--rcp`).

## 3. Catch indirect access through AssumeRole chains

[`chain-account.json`](chain-account.json) has a `dev` role with **no S3 permissions at
all** — but it can assume `deploy`, which reads prod-data. Direct checking flags only
`deploy`:

```bash
iamprover verify --account chain-account.json --invariants invariants.yaml
```

Add `--closure assume-role` and `dev` is flagged too, with the full chain:

```bash
iamprover verify --account chain-account.json --invariants invariants.yaml --closure assume-role
```

```
[FAIL] prod-data-read-restricted — Only the data-team role may read objects in the prod-data bucket
    counterexample: arn:aws:iam::111122223333:role/dev
        step 1: sts:assumerole on arn:aws:iam::111122223333:role/deploy
        step 2: s3:getobject on arn:aws:s3:::prod-data/
    counterexample: arn:aws:iam::111122223333:role/deploy
        can perform  s3:getobject
        on resource  arn:aws:s3:::prod-data/
...
```

An edge requires *both* sides: the source's identity policy granting `sts:AssumeRole` on
the target *and* the target's trust policy naming the source — exactly how AWS evaluates
it. Chains are bounded by `--max-hops` (default 4).

## 4. Verify a live account

[`gaad.json`](gaad.json) is a (miniature) snapshot in the format of
`aws iam get-account-authorization-details` — users, groups, managed policies, roles.
iamprover flattens group memberships and managed attachments automatically:

```bash
aws iam get-account-authorization-details > gaad.json   # from a real account
iamprover verify --gaad gaad.json --privesc --check-trust
```

- `--privesc` runs the built-in catalog of privilege-escalation invariants (policy-version
  rewrites, credential minting, `iam:PassRole` chains into Lambda/EC2/CloudFormation/...).
- `--check-trust` flags cross-account and public assume-role grants, noting whether
  they're guarded by `sts:ExternalId` / org id / source account.

## 5. Gate a Terraform plan in CI

```bash
terraform plan -out plan && terraform show -json plan > plan.json
iamprover verify --tf-plan plan.json --invariants invariants.yaml   # exit 2 on violation
```

Or with the GitHub Action:

```yaml
- uses: UTKARSH698/iamprover@v0.6.0
  with:
    tf-plan: plan.json
    invariants: invariants.yaml
    privesc: "true"
    closure: assume-role
```

## Where to go next

- [Architecture](../docs/ARCHITECTURE.md) — how ingest → model → encode → solve fits together
- [Comparison](../docs/COMPARISON.md) — when to use this vs Access Analyzer / Prowler / Checkov
- [Python API](../docs/API.md) — use the engine as a library
- [Benchmarks](../docs/BENCHMARKS.md) — runtime at 100 / 1k / 10k principals
