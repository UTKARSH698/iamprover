# Architecture

iamprover has a deliberately small pipeline: **ingest → model → encode → solve → report**.
Every input format converges on one in-memory model, and every feature is expressed as a
constraint over that model — there is exactly one place where IAM evaluation semantics live.

```mermaid
flowchart LR
    subgraph Inputs
        TF["Terraform plan JSON<br/>(terraform show -json)"]
        GAAD["Live account snapshot<br/>(aws iam get-account-authorization-details)"]
        ACC["Account JSON<br/>(hand-written / generated)"]
        SCP["SCP / RCP documents<br/>(--scp / --rcp)"]
        INV["Invariant spec YAML<br/>+ built-in privesc catalog"]
    end

    subgraph Parsers["parsers/"]
        PT["terraform.py"]
        PA["aws.py"]
        PI["iam.py"]
    end

    MODEL["model.py<br/>Account · Principal · Policy · Statement · Condition"]

    subgraph Engine["engine/"]
        ENC["encoder.py<br/>allowed(): IAM semantics as Z3 constraints"]
        PATS["patterns.py<br/>wildcards → Z3 regex · glob intersection"]
        COND["conditions.py + context.py<br/>Condition operators · request context"]
        SOLVE["solver.py<br/>per-principal SAT check → counterexample"]
        REACH["reachability.py<br/>assume-role graph · bounded BFS (Python, not Z3)"]
        TRUST["trust.py<br/>cross-account trust findings"]
    end

    REPORT["report.py<br/>text / JSON · exit code 2 on violation"]

    TF --> PT --> MODEL
    GAAD --> PA --> MODEL
    ACC --> PI --> MODEL
    SCP --> PI
    INV --> SOLVE
    MODEL --> ENC
    PATS --> ENC
    COND --> ENC
    ENC --> SOLVE
    ENC --> REACH
    REACH --> SOLVE
    MODEL --> TRUST
    SOLVE --> REPORT
    TRUST --> REPORT
```

## The stages

### 1. Parsers (`parsers/`)

Three front-ends, one output type: `model.Account`.

- **`terraform.py`** — reads `terraform show -json plan` output: users, roles (with trust
  policies, `inline_policy`, `managed_policy_arns`), groups (flattened into members),
  inline and managed policies, and `aws_s3_bucket_policy`. Most ARNs are unknown until
  apply, so links are resolved from the plan's `configuration` block, descending into
  modules (whose references are module-local). Principals get real IAM ARNs (account id
  from `--tf-account-id` or inferred from the plan). Anything the plan cannot reveal is
  widened, never dropped: a policy whose content isn't in the plan (an AWS-managed
  policy attached by ARN, a computed document) becomes Allow `*`; a computed trust
  policy trusts the principals its expression references, the account root, and the
  compute services. Every widening is reported as a warning on stderr.
- **`aws.py`** — reads a live-account snapshot from
  `aws iam get-account-authorization-details`: flattens group memberships and
  managed-policy attachments onto each principal, picks each policy's default version,
  URL-decodes policy documents, and resolves `PermissionsBoundaryArn` to the actual
  boundary policy.
- **`iam.py`** — reads a plain account-description JSON (principals + policies), and
  standalone policy documents for `--scp`/`--rcp`.

Parsers do *no* interpretation of what a policy means — they only normalize shape.
Anything semantic belongs in the encoder.

### 2. Model (`model.py`)

Plain dataclasses, no behavior: `Account` (principals, resource policies, SCPs, RCPs),
`Principal` (identity policies, optional trust policy, optional permission boundary),
`Policy`, `Statement`, `Condition`. This is the single interface between ingestion and
verification — a new input format only has to produce these.

### 3. Encoder (`engine/encoder.py`)

The heart of the tool. `allowed(principal, action, resource, ctx, ...)` returns **one Z3
boolean constraint** that is true exactly when AWS would authorize the request, for the
modeled fragment:

```
identity_path  = identity_allow  AND boundary_allow AND scp_allow
resource_path  = resource_allow  AND rcp_allow      AND scp_allow
allowed        = (identity_path OR resource_path) AND NOT (any explicit Deny in any layer)
```

Supporting modules:

- **`patterns.py`** — compiles IAM wildcard patterns (`*`, `?`) into Z3 regular
  expressions; widens policy variables (`${aws:username}`) to `*` in positive positions;
  also provides `globs_intersect`, a pure-Python glob-intersection check used to skip
  provably-unsatisfiable solver queries.
- **`conditions.py` / `context.py`** — encode `Condition` blocks over free request-context
  variables (the solver searches over all contexts; counterexamples report the assignment).
  Unknown operators degrade in the over-approximating direction: true on Allow, false on
  Deny.

### 4. Solver (`engine/solver.py`)

For each `(principal, invariant)` pair, asserts *“the forbidden request is allowed”* and
asks Z3 for a model:

- **UNSAT** → the invariant is *proved* for that principal (over all actions, resources,
  and contexts in the modeled fragment — not merely “no findings”).
- **SAT** → the model is read back as a concrete counterexample: action, resource, and the
  request context that makes it fire. Chain invariants (`forbid_chain`) encode each step as
  an independent request and report every step.

A cheap syntactic prefilter (`globs_intersect` over the principal's Allow statements) skips
the Z3 query entirely when no statement could possibly grant the forbidden action/resource
— sound, because bounding layers and conditions can only *restrict* further.

### 5. Reachability (`engine/reachability.py`)

`--closure` extends every invariant over principals another principal can come to act
as. Traversal is **plain Python, deliberately not Z3**; Z3 only decides individual edges:

1. **Graph build** — two relations contribute edges `P → Q`:
   - `assume-role`: Q's trust policy admits P, following AWS's rules. If it names P's ARN
     (or `*`) in the same account, the trust policy alone grants the assume — only an
     explicit identity Deny can block it. If it names P's account root, or P is in
     another account, the trust only delegates and P's identity policies must also allow
     `sts:AssumeRole` on Q (checked with the same `allowed()` encoder). Built
     trust-side-out: only principals a trust policy names — or that live in an account
     whose root it names — are candidate sources, so cost scales with trust grants, not
     principal pairs.
   - `pass-role`: Q is a role whose trust policy admits a compute service (Lambda, EC2,
     CloudFormation, Glue, SageMaker, CodeBuild, Data Pipeline), P is allowed `iam:PassRole` on Q, *and* P is
     allowed that service's launch action. The two permissions are independent requests,
     and `iam:PassedToService` stays free context — both over-approximate. Only
     principals that can syntactically pass *some* role are considered as sources, and an
     exact fast path (unconditional matching Allow, no possibly-matching Deny, no
     boundary) answers the common case without a solver call.

   Each edge is labeled with the requests it costs (`sts:assumerole`, or `iam:passrole`
   followed by the launch action), and those labels become counterexample steps.
2. **Bounded BFS** — shortest chains from each source, bounded by `--max-hops`
   (default 4), with parent-pointer chain reconstruction.
3. **Evaluation** — for a principal with no direct violation, reachable targets are checked
   nearest-first; the first violating target yields a counterexample whose steps are the
   labeled hops followed by the target's violation.

Keeping graph construction, traversal, and proof evaluation separate is what let the
v0.7 `pass-role` relation slot in without touching the prover: it only adds edges.

### 6. Trust analysis (`engine/trust.py`) and reporting (`report.py`)

`--check-trust` walks role trust policies for grants reaching outside the account, and
classifies them as guarded (ExternalId / org id / source account) or unguarded.
`report.py` renders text or JSON; any violation or unguarded trust grant exits with code 2
for CI gating.

## Soundness invariant (read this before contributing)

Everything in the engine preserves one direction of error: **permissions are only ever
over-approximated.** Unknown condition operators, policy variables, guarded trust edges —
every modeling gap must widen what a principal can do, never narrow it. iamprover may
report a violation that a real condition would prevent (false positive), but within the
modeled fragment it must never miss one (no false negatives). Trust the `PASS`es;
investigate the `FAIL`s.

If a change can suppress a true violation, it is wrong, no matter how much noise it removes.
