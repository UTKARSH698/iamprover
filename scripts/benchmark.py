"""Benchmark iamprover on synthetic accounts of increasing size.

Generates deterministic synthetic accounts (a realistic mix: mostly
narrowly-scoped principals, a few wildcard-bearing ones, a sparse
assume-role graph) and times invariant checking with and without
`--closure assume-role`.

Usage:
    python scripts/benchmark.py                 # default sizes: 100 1000 10000
    python scripts/benchmark.py --sizes 100 1000
    python scripts/benchmark.py --closure-sizes 100 1000
"""

from __future__ import annotations

import argparse
import platform
import time

from iamprover.engine.reachability import ReachabilityIndex
from iamprover.engine.solver import check_all
from iamprover.invariants import Invariant, Step
from iamprover.model import Account, Policy, Principal, Statement


def make_account(n: int) -> Account:
    """n principals: ~96% narrow read-only, ~3% broad-but-safe, ~1% violating,
    plus a sparse assume-role chain every 50 principals (depth 3)."""
    principals: list[Principal] = []
    for i in range(n):
        arn = f"arn:aws:iam::111122223333:role/bench-{i}"
        if i % 100 == 7:  # ~1%: violates the prod-data invariant
            stmts = [
                Statement(
                    effect="Allow",
                    actions=["s3:*"],
                    resources=["arn:aws:s3:::*"],
                )
            ]
        elif i % 33 == 5:  # ~3%: broad list/describe, still safe
            stmts = [
                Statement(
                    effect="Allow",
                    actions=["s3:List*", "ec2:Describe*", "logs:Get*"],
                    resources=["*"],
                ),
                Statement(
                    effect="Deny",
                    actions=["s3:GetObject"],
                    resources=["arn:aws:s3:::prod-data/*"],
                ),
            ]
        else:  # narrow: own bucket + logs
            stmts = [
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject", "s3:PutObject"],
                    resources=[f"arn:aws:s3:::team-{i % 20}-bucket/*"],
                ),
                Statement(
                    effect="Allow",
                    actions=["logs:CreateLogStream", "logs:PutLogEvents"],
                    resources=["arn:aws:logs:*:111122223333:*"],
                ),
            ]
        principals.append(Principal(arn=arn, policies=[Policy(name=f"p{i}", statements=stmts)]))

    # Sparse assume-role chains: every 50th principal starts a 3-hop chain.
    for base in range(0, n - 3, 50):
        for hop in range(3):
            src, dst = principals[base + hop], principals[base + hop + 1]
            src.policies.append(
                Policy(
                    name=f"assume-{base}-{hop}",
                    statements=[
                        Statement(
                            effect="Allow",
                            actions=["sts:AssumeRole"],
                            resources=[dst.arn],
                        )
                    ],
                )
            )
            dst.trust_policy = Policy(
                name="trust",
                statements=[
                    Statement(
                        effect="Allow",
                        actions=["sts:AssumeRole"],
                        principals=[src.arn],
                    )
                ],
            )
    return Account(principals=principals)


def make_passrole_account(n: int) -> Account:
    """make_account(n) plus a Lambda execution role every 25 principals and a
    deployer with wildcard iam:PassRole + lambda:CreateFunction every 50 —
    a dense worst case for --closure pass-role (every deployer reaches every role)."""
    account = make_account(n)
    for i, p in enumerate(account.principals):
        if i % 25 == 3:
            p.trust_policy = Policy(
                name="trust",
                statements=[
                    Statement(
                        effect="Allow",
                        actions=["sts:AssumeRole"],
                        principals=["service:lambda.amazonaws.com"],
                    )
                ],
            )
        if i % 50 == 11:
            p.policies.append(
                Policy(
                    name=f"deploy-{i}",
                    statements=[
                        Statement(effect="Allow", actions=["iam:PassRole"], resources=["*"]),
                        Statement(
                            effect="Allow", actions=["lambda:CreateFunction"], resources=["*"]
                        ),
                    ],
                )
            )
    return account


INVARIANTS = [
    Invariant(
        id="prod-data-read-restricted",
        description="Only data-team may read prod-data",
        actions=["s3:GetObject"],
        resources=["arn:aws:s3:::prod-data/*"],
        unless_principals=["arn:aws:iam::111122223333:role/data-team"],
    ),
    Invariant(
        id="no-iam-mutation",
        description="No principal may mutate IAM",
        actions=["iam:Put*", "iam:Attach*", "iam:Create*"],
        resources=["*"],
    ),
    Invariant(
        id="no-passrole-lambda",
        description="No single principal may pass a role and create a Lambda",
        chain=[
            Step(actions=["iam:PassRole"], resources=["*"]),
            Step(actions=["lambda:CreateFunction"], resources=["*"]),
        ],
    ),
]


def bench(label: str, fn) -> float:
    start = time.perf_counter()
    fn()
    elapsed = time.perf_counter() - start
    print(f"  {label}: {elapsed:.2f}s")
    return elapsed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sizes", type=int, nargs="+", default=[100, 1000, 10000])
    parser.add_argument("--closure-sizes", type=int, nargs="+", default=[100, 1000])
    parser.add_argument(
        "--passrole-sizes",
        type=int,
        nargs="*",
        default=[],
        help="Also run the --closure all stress account at these sizes",
    )
    args = parser.parse_args()

    print(f"python {platform.python_version()} on {platform.system()} {platform.machine()}")
    rows = []
    for n in args.sizes:
        print(f"n={n}")
        account = make_account(n)
        direct = bench(
            "direct (3 invariants)", lambda account=account: check_all(account, INVARIANTS)
        )
        graph_t = closure_t = None
        if n in args.closure_sizes:
            index: list[ReachabilityIndex] = []
            graph_t = bench(
                "build assume-role graph",
                lambda account=account, index=index: index.append(ReachabilityIndex(account)),
            )
            closure_t = bench(
                "closure check (3 invariants)",
                lambda account=account, index=index: check_all(account, INVARIANTS, index[0]),
            )
        rows.append((n, direct, graph_t, closure_t))

    print("\n| principals | direct check | graph build | closure check |")
    print("|---|---|---|---|")
    for n, direct, graph_t, closure_t in rows:
        g = f"{graph_t:.2f}s" if graph_t is not None else "—"
        c = f"{closure_t:.2f}s" if closure_t is not None else "—"
        print(f"| {n:,} | {direct:.2f}s | {g} | {c} |")

    if args.passrole_sizes:
        print("\n| principals | --closure all graph build | closure check |")
        print("|---|---|---|")
    for n in args.passrole_sizes:
        account = make_passrole_account(n)
        start = time.perf_counter()
        index = ReachabilityIndex(account, relations=("assume-role", "pass-role"))
        graph_t = time.perf_counter() - start
        start = time.perf_counter()
        check_all(account, INVARIANTS, index)
        closure_t = time.perf_counter() - start
        print(f"| {n:,} | {graph_t:.2f}s | {closure_t:.2f}s |")


if __name__ == "__main__":
    main()
