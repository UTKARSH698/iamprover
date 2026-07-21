# How iamprover relates to Access Analyzer, Prowler, and Checkov

Short version: **iamprover is complementary to all three.** They answer different
questions. Most teams that would benefit from iamprover already run one of these — keep
running it.

| | Question it answers | Method | Where it runs |
|---|---|---|---|
| **AWS IAM Access Analyzer** | "What access does this policy grant / is it broader than intended?" | Automated reasoning (Zelkova) over single policies | AWS-hosted, per-account |
| **Prowler** | "Which known misconfigurations exist in my account?" | Hundreds of curated checks against live APIs | CLI / SaaS, live account |
| **Checkov** | "Does my IaC violate known policy-as-code rules?" | Static rules over Terraform/CloudFormation/K8s | CLI / CI, pre-deploy |
| **iamprover** | "Does my *declared, system-level* security invariant provably hold across *all* principals and policies together — and if not, exactly how does it break?" | SMT solving (Z3) over the composed account model | CLI / CI, plan or live snapshot |

## What's genuinely different

**1. You declare the invariant; the tool proves it.**
Scanners ship a fixed catalog of *known-bad patterns*. iamprover verifies *your*
statements about *your* system — "only the data-team role may read the prod-data bucket",
"no single principal can both pass a role and create a Lambda" — including invariants no
generic catalog could know about.

**2. Whole-system composition, not per-policy analysis.**
Access Analyzer reasons rigorously about one policy at a time. iamprover's unit of
analysis is the *account*: identity policies, resource policies, permission boundaries,
SCPs, RCPs, and transitive `sts:AssumeRole` chains, evaluated together the way AWS
composes them. Individually-correct policies that compose into a globally-unsafe state
are exactly the failure mode it exists to catch.

**3. A PASS is a proof, not an absence of findings.**
When a scanner reports nothing, you know none of its checks fired. When iamprover reports
`PASS`, the invariant has been shown unsatisfiable over every action, resource, and
request context in the modeled fragment — including every wildcard expansion. (See the
soundness note below for the boundary of that claim.)

**4. Counterexamples, not findings.**
A `FAIL` comes with a concrete trace: principal, action, resource, the request context
that makes it fire, and — for chains — every step, including assume-role hops. You can
replay it mentally against your policies and see the hole.

**5. Open source, self-hosted, CI-native.**
No AWS account required to analyze a Terraform plan. Runs as a [GitHub Action]
(https://github.com/marketplace/actions/iamprover) that fails the PR that would break an
invariant, before deploy.

## What the others do better

Honesty matters more than marketing:

- **Coverage breadth.** Prowler has hundreds of checks across dozens of services;
  Checkov has thousands of rules across many frameworks. iamprover models IAM
  authorization deeply and nothing else. If you want "scan everything for known issues,"
  use them.
- **Services beyond IAM.** iamprover doesn't check your S3 bucket encryption, your
  security groups, or your K8s manifests.
- **Zero configuration.** Scanners are useful the minute you point them at an account.
  iamprover is most useful once you've written down invariants worth proving (though
  `--privesc` and `--check-trust` work out of the box).
- **Condition-operator completeness.** Access Analyzer's engine models IAM's condition
  semantics essentially completely. iamprover models a growing subset and treats the rest
  conservatively (see below).

## The soundness contract

Where iamprover's model is incomplete, it errs in exactly one direction: unsupported
condition operators are treated as always-true on Allow and always-false on Deny, policy
variables widen to `*`, guarded trust edges still count as edges. Permissions are only
ever **over-approximated** — you may get a false positive that a real condition would
prevent, but within the modeled fragment you will not get a false negative.

## A reasonable stack

- **Checkov / tfsec** in CI for broad IaC hygiene.
- **Prowler** scheduled against live accounts for benchmark coverage.
- **Access Analyzer** on for continuous external-access findings.
- **iamprover** in CI on every Terraform plan touching IAM, proving the handful of
  invariants that would actually be an incident if they broke — plus `--privesc` and
  `--check-trust` on a scheduled live-account snapshot.

The scanners tell you what's *misconfigured*. iamprover proves what's *safe*.
