# Python API and CLI reference

iamprover is a library first; the CLI is a thin wrapper. Everything the CLI does is
available programmatically.

## Quick example

```python
from iamprover.parsers.iam import load_account
from iamprover.invariants import load_invariants
from iamprover.engine.solver import check_all
from iamprover.engine.reachability import ReachabilityIndex

account = load_account("examples/account.json")
invariants = load_invariants("examples/invariants.yaml")

reachability = ReachabilityIndex(account, max_hops=4)   # optional: --closure assume-role
results = check_all(account, invariants, reachability)

for r in results:
    print(r.invariant.id, "PASS" if r.passed else "FAIL")
    for ce in r.counterexamples:
        print("  ", ce.principal, ce.action, ce.resource, ce.context)
        for step in ce.steps:                            # chain invariants / closure
            print("    step:", step.action, step.resource)
```

## Loading inputs (`iamprover.parsers`)

| Function | Input | Returns |
|---|---|---|
| `parsers.iam.load_account(path)` | Account-description JSON (`principals` + `resource_policies` + `scps` + `rcps`) | `Account` |
| `parsers.aws.load_gaad(path)` | `aws iam get-account-authorization-details` output | `Account` (groups/managed policies flattened, boundaries resolved) |
| `parsers.terraform.load_tf_plan(path)` | `terraform show -json plan` output | `Account` |
| `parsers.iam.load_policy_list(paths)` | Standalone policy-document JSON files | `list[Policy]` — assign to `account.scps` / `account.rcps` |
| `parsers.iam.parse_policy_document(name, document)` | One policy document `dict` | `Policy` |

## The model (`iamprover.model`)

Plain dataclasses — construct them directly to build accounts in code (this is what the
test suite and `scripts/benchmark.py` do):

```python
from iamprover.model import Account, Principal, Policy, Statement, Condition

account = Account(principals=[
    Principal(
        arn="arn:aws:iam::111122223333:role/dev",
        policies=[Policy(name="p", statements=[
            Statement(effect="Allow", actions=["s3:Get*"], resources=["arn:aws:s3:::*"]),
        ])],
        trust_policy=None,          # Policy | None (roles)
        permission_boundary=None,   # Policy | None
    ),
])
```

`Statement` fields: `effect` (`"Allow"`/`"Deny"`), `actions`, `not_actions`, `resources`,
`not_resources`, `conditions` (`list[Condition]`), `principals` (resource-based policies
only). `Condition` is `(operator, key, values)`, e.g.
`Condition("StringEquals", "aws:SourceIp", ["10.0.0.0/8"])`.

## Invariants (`iamprover.invariants`)

| Function | Purpose |
|---|---|
| `load_invariants(path)` | Parse an invariant spec YAML file |
| `parse_invariants(data)` | Same, from an already-loaded `dict` |
| `Invariant(id, description, actions, resources, chain, unless_principals, where)` | Construct directly; `chain` is `list[Step]` for multi-step invariants |
| `iamprover.privesc.load_builtin_privesc(unless_principals)` | The built-in privilege-escalation catalog as `list[Invariant]` |

## Checking (`iamprover.engine.solver`)

| Function | Purpose |
|---|---|
| `check_all(account, invariants, reachability=None)` | Check every invariant; returns `list[InvariantResult]` |
| `check_invariant(account, invariant, reachability=None)` | Check one invariant against every principal |

`InvariantResult`: `.invariant`, `.passed`, `.counterexamples` (`list[Counterexample]`).
`Counterexample`: `.principal`, `.action`, `.resource`, `.context` (request-context
assignment found by the solver), `.steps` (populated for chain invariants and closure
chains).

**PASS means proved**: Z3 showed the forbidden request unsatisfiable for that principal
over all actions, resources, and request contexts in the modeled fragment.

## Reachability (`iamprover.engine.reachability`)

| Symbol | Purpose |
|---|---|
| `ReachabilityIndex(account, max_hops=4)` | Builds the assume-role graph once; memoizes per-source BFS. Pass to `check_all`/`check_invariant` |
| `build_graph(account)` | Adjacency list `{source_arn: [target_arn, ...]}` — an edge needs both the identity-side grant and the trust-side grant |
| `shortest_chains(graph, source, max_hops)` | `{target_arn: Chain}` nearest-first; `Chain.path` is the ARN list from source to target |

## Trust analysis (`iamprover.engine.trust`)

`analyze_trust(account, trusted_accounts=None)` returns `list[TrustFinding]` — one per
external/public assume-role grant, with `.guarded` (ExternalId / org / source-account
condition present) and the guarding keys.

## Low-level encoder (`iamprover.engine.encoder`)

`allowed(principal, action, resource, ctx, resource_policies=(), scps=(), rcps=())`
returns a single Z3 `BoolRef` — true exactly when AWS would authorize the request in the
modeled fragment. `action`/`resource` are Z3 string variables (or `z3.StringVal`
constants), `ctx` is an `engine.context.Context`. Build custom analyses on top of this;
both the solver and the reachability graph do.

## Rendering (`iamprover.report`)

`render_text(results)` / `render_json(results)` and
`render_trust_text(findings)` / `render_trust_json(findings)`.

---

## CLI reference

```
iamprover verify (--account F | --tf-plan F | --gaad F) [options]
```

| Flag | Meaning |
|---|---|
| `--account F` | Account-description JSON |
| `--tf-plan F` | Terraform plan JSON (`terraform show -json plan`) |
| `--gaad F` | Live snapshot (`aws iam get-account-authorization-details`) |
| `--invariants F` | Invariant spec YAML |
| `--privesc` | Also verify the built-in privilege-escalation catalog |
| `--privesc-unless ARN_GLOB` | Exempt principals from `--privesc` (repeatable) |
| `--check-trust` | Analyze role trust policies for cross-account/public grants |
| `--trusted-account ID` | Allowlist an external account for `--check-trust` (repeatable) |
| `--check-anonymous` | Also verify invariants for an unauthenticated principal |
| `--scp F` | SCP document (repeatable; one file per OU-level layer) |
| `--rcp F` | RCP document (repeatable) |
| `--closure {none,assume-role}` | Widen invariants over a closure relation (default `none`) |
| `--max-hops N` | Chain bound for `--closure assume-role` (default 4) |
| `--format {text,json}` | Output format |

Exit codes: `0` all proven · `1` input/usage error · `2` at least one violation or
unguarded trust grant (use this to fail CI).

At least one of `--invariants`, `--privesc`, `--check-trust` is required.
