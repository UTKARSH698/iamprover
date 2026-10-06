# Validation: IAM Vulnerable

[IAM Vulnerable](https://github.com/BishopFox/iam-vulnerable) (Bishop Fox) is a Terraform
project that deploys dozens of deliberately exploitable AWS IAM privilege-escalation
paths, plus a `tool-testing` set built specifically to measure scanners: `fn*` cases
that tools commonly *miss*, and `fp*` traps that a precise tool should *not* flag.

iamprover was run against it the way a CI gate would: from a `terraform plan`, with
**no AWS account and no credentials** — nothing is deployed.

```bash
bash scripts/iam-vulnerable/run.sh    # needs git, terraform, python, iamprover
```

[`run.sh`](../scripts/iam-vulnerable/run.sh) clones the lab, plans it offline (dummy
credentials, `-refresh=false`; the lab's single AWS-calling data source is replaced by its
well-known ARN), runs `iamprover verify --tf-plan plan.json --privesc` with and without
`--closure all`, and scores the output with
[`score.py`](../scripts/iam-vulnerable/score.py).

Measured with iamprover 0.7.1, lab commit `0f29866`, Terraform 1.14.

## Results

| Category | Scenarios | Result |
|---|---|---|
| Exploitable escalation paths | 37 | **37 detected** — 35 directly, the last 2 (multi-hop AssumeRole chain) with `--closure` |
| `fn*` "tools commonly miss this" cases (included above) | 4 | **4 detected** |
| Privileged *target* roles the lab escalates into | 2 | Flagged — they hold admin directly (exempt real admins with `--privesc-unless`) |
| Scenarios with no exploitable permissions in the plan | 2 | Not flagged — correct |
| `fp*` false-positive traps | 5 | 3 clean, 2 flagged |

End-to-end on the lab (86 principals, 16 built-in invariants, `--closure all`): ~11 s.

`score.py` groups by the lab's resource names, so it prints the raw count
`detected 39/41`: the 37 escalation paths plus the 2 target roles, out of those 41
plus the 2 non-exploitable scenarios.

### The two non-findings

- **`privesc-AssumeRole-start`** — the `start-user` has no policies, and no role trusts it
  (the chain's first role trusts the operator who deploys the lab). In the lab's own
  Terraform it can do nothing, so there is nothing to find.
- **`privesc-permissive-role-trust`** — a role whose trust policy names the account root,
  but which has **no permissions**. Anyone may assume it; it grants nothing.

### The two flagged traps

Both are precision limits, and both err in the direction iamprover is built to err in —
flag rather than miss:

- **`fp4`** allows `iam:CreatePolicyVersion` only on `arn:aws:iam::aws:policy/...` —
  AWS-managed policies, which no customer can modify. IAM glob patterns can't separate
  the literal `aws` from a 12-digit account id, so the grant is treated as reaching
  customer policies too.
- **`fp5`** gates the same permission behind `DateLessThan aws:TokenIssueTime
  2020-01-01`, which no current session satisfies. Date operators aren't modeled yet,
  so the condition is treated as satisfiable.

### How closure changes the picture

Without closure, iamprover answers "what can this principal do *directly*?". The
`privesc-AssumeRole-starting` → `intermediate` → `ending` (admin) chain grants no
escalation permission at any single hop — each role can only assume the next — so it is
invisible to any per-principal check. `--closure all` follows the chain and reports it.

Closure also turns the PassRole findings from "this principal holds PassRole + a launch
permission" into the concrete path: every `privesc-passrole-*` scenario reaches the lab's
`privesc-high-priv-service-role` (`Action: *`), which is why those principals violate
every invariant once closure is on.

## What this run found in iamprover itself

The first run of this benchmark, on the released 0.7.0, parsed **zero principals** from
the plan and reported every invariant as proven. Fixed in 0.7.1:

- **Terraform parser** — links inside Terraform *modules* weren't resolved (plans leave
  ARNs unknown; the module-local references were never looked up), principals only
  existed as a side effect of a resolved attachment, and role trust policies and groups
  weren't read. All fixed; principals now carry real IAM ARNs.
- **Empty input is never a proof** — an input yielding no principals now exits `1` with
  an error instead of reporting every invariant as holding.
- **Unknowns are widened, not dropped** — a policy whose content isn't in the plan
  (e.g. an AWS-managed policy attached by ARN) is modeled as Allow `*`, with a warning.
- **AssumeRole semantics** — a same-account trust policy naming a principal's ARN grants
  the assume by itself, and an account-root grant delegates to identity policies. Both
  edges were previously missed (the AssumeRole chain above, and account-root trust).
- **Catalog coverage** — five escalation techniques the lab exercises were added:
  PassRole into CodeBuild and Data Pipeline, SageMaker training/processing jobs, and
  hijacking existing CloudFormation stacks, EC2 instances (SSM / Instance Connect), and
  SageMaker notebooks.

## Per-scenario results

| Scenario | no closure | --closure all | Caught by (with closure) |
|---|---|---|---|
| `fn1-privesc3-partial` | ✓ | ✓ | `privesc-assume-role-policy`, `privesc-cloudformation-stack-hijack`, `privesc-credential-creation` +13 |
| `fn2-exploitableResourceConstraint` | ✓ | ✓ | `privesc-policy-version` |
| `fn3-exploitableConditionConstraint` | ✓ | ✓ | `privesc-policy-version` |
| `fn4-exploitableNotAction` | ✓ | ✓ | `privesc-assume-role-policy`, `privesc-cloudformation-stack-hijack`, `privesc-credential-creation` +13 |
| `fp1-allow-and-deny` (FP trap) | clean ✓ | clean ✓ |  |
| `fp2-allow-and-deny-multiple-policies` (FP trap) | clean ✓ | clean ✓ |  |
| `fp3-deny-iam` (FP trap) | clean ✓ | clean ✓ |  |
| `fp4-nonExploitableResourceConstraint` (FP trap) | flagged (FP) | flagged (FP) | `privesc-policy-version` |
| `fp5-nonExploitableConditionConstraint` (FP trap) | flagged (FP) | flagged (FP) | `privesc-policy-version` |
| `privesc-AssumeRole-ending` | ✓ | ✓ | `privesc-assume-role-policy`, `privesc-cloudformation-stack-hijack`, `privesc-credential-creation` +13 |
| `privesc-AssumeRole-intermediate` | — | ✓ | `privesc-assume-role-policy`, `privesc-cloudformation-stack-hijack`, `privesc-credential-creation` +13 |
| `privesc-AssumeRole-start` | — | — |  |
| `privesc-AssumeRole-starting` | — | ✓ | `privesc-assume-role-policy`, `privesc-cloudformation-stack-hijack`, `privesc-credential-creation` +13 |
| `privesc-CloudFormationUpdateStack` | ✓ | ✓ | `privesc-cloudformation-stack-hijack` |
| `privesc-codeBuildCreateProjectPassRole` | ✓ | ✓ | `privesc-assume-role-policy`, `privesc-cloudformation-stack-hijack`, `privesc-credential-creation` +13 |
| `privesc-ec2InstanceConnect` | ✓ | ✓ | `privesc-instance-session-hijack` |
| `privesc-high-priv-service` | ✓ | ✓ | `privesc-assume-role-policy`, `privesc-cloudformation-stack-hijack`, `privesc-credential-creation` +13 |
| `privesc-permissive-role-trust` | — | — |  |
| `privesc-sageMakerCreateNotebookPassRole` | ✓ | ✓ | `privesc-assume-role-policy`, `privesc-cloudformation-stack-hijack`, `privesc-credential-creation` +13 |
| `privesc-sageMakerCreatePresignedNotebookURL` | ✓ | ✓ | `privesc-sagemaker-notebook-hijack` |
| `privesc-sageMakerCreateProcessingJobPassRole` | ✓ | ✓ | `privesc-assume-role-policy`, `privesc-cloudformation-stack-hijack`, `privesc-credential-creation` +13 |
| `privesc-sageMakerCreateTrainingJobPassRole` | ✓ | ✓ | `privesc-assume-role-policy`, `privesc-cloudformation-stack-hijack`, `privesc-credential-creation` +13 |
| `privesc-sre` | ✓ | ✓ | `privesc-assume-role-policy`, `privesc-cloudformation-stack-hijack`, `privesc-credential-creation` +13 |
| `privesc-ssmSendCommand` | ✓ | ✓ | `privesc-instance-session-hijack` |
| `privesc-ssmStartSession` | ✓ | ✓ | `privesc-instance-session-hijack` |
| `privesc1-CreateNewPolicyVersion` | ✓ | ✓ | `privesc-policy-version` |
| `privesc10-PutUserPolicy` | ✓ | ✓ | `privesc-policy-attachment` |
| `privesc11-PutGroupPolicy` | ✓ | ✓ | `privesc-policy-attachment` |
| `privesc12-PutRolePolicy` | ✓ | ✓ | `privesc-policy-attachment` |
| `privesc13-AddUserToGroup` | ✓ | ✓ | `privesc-policy-attachment` |
| `privesc14-UpdatingAssumeRolePolicy` | ✓ | ✓ | `privesc-assume-role-policy`, `privesc-cloudformation-stack-hijack`, `privesc-credential-creation` +13 |
| `privesc15-PassExistingRoleToNewLambdaThenInvoke` | ✓ | ✓ | `privesc-assume-role-policy`, `privesc-cloudformation-stack-hijack`, `privesc-credential-creation` +13 |
| `privesc16-PassRoleToNewLambdaThenTriggerWithNewDynamo` | ✓ | ✓ | `privesc-assume-role-policy`, `privesc-cloudformation-stack-hijack`, `privesc-credential-creation` +13 |
| `privesc17-EditExistingLambdaFunctionWithRole` | ✓ | ✓ | `privesc-lambda-code-hijack` |
| `privesc18-PassExistingRoleToNewGlueDevEndpoint` | ✓ | ✓ | `privesc-assume-role-policy`, `privesc-cloudformation-stack-hijack`, `privesc-credential-creation` +13 |
| `privesc19-UpdateExistingGlueDevEndpoint` | ✓ | ✓ | `privesc-glue-endpoint-hijack` |
| `privesc2-SetExistingDefaultPolicyVersion` | ✓ | ✓ | `privesc-policy-version` |
| `privesc20-PassExistingRoleToCloudFormation` | ✓ | ✓ | `privesc-assume-role-policy`, `privesc-cloudformation-stack-hijack`, `privesc-credential-creation` +13 |
| `privesc21-PassExistingRoleToNewDataPipeline` | ✓ | ✓ | `privesc-assume-role-policy`, `privesc-cloudformation-stack-hijack`, `privesc-credential-creation` +13 |
| `privesc3-CreateEC2WithExistingInstanceProfile` | ✓ | ✓ | `privesc-assume-role-policy`, `privesc-cloudformation-stack-hijack`, `privesc-credential-creation` +13 |
| `privesc4-CreateAccessKey` | ✓ | ✓ | `privesc-credential-creation` |
| `privesc5-CreateLoginProfile` | ✓ | ✓ | `privesc-credential-creation` |
| `privesc6-UpdateLoginProfile` | ✓ | ✓ | `privesc-credential-creation` |
| `privesc7-AttachUserPolicy` | ✓ | ✓ | `privesc-policy-attachment` |
| `privesc8-AttachGroupPolicy` | ✓ | ✓ | `privesc-policy-attachment` |
| `privesc9-AttachRolePolicy` | ✓ | ✓ | `privesc-policy-attachment` |

"Caught by" lists the invariants violated with `--closure all`; principals that reach the lab's admin role violate all 16.
