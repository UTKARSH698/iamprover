# Benchmarks

Runtime of `check_all` over synthetic accounts of increasing size, measured with
[`scripts/benchmark.py`](../scripts/benchmark.py). Reproduce with:

```bash
python scripts/benchmark.py --sizes 100 1000 10000 --closure-sizes 100 1000 10000
```

**Setup.** Intel Core i7-9750H @ 2.60 GHz, Windows, CPython 3.11, single-threaded.
Each account is a realistic mix: ~96% narrowly-scoped principals (own-bucket S3 + logs),
~3% broad-but-safe (`s3:List*`/`ec2:Describe*` with an explicit prod Deny), ~1% actual
violators (`s3:*` on `*`), and a sparse assume-role graph (a 3-hop chain every 50
principals). Three invariants are checked: a resource-restriction invariant, an
IAM-mutation invariant, and a two-step `forbid_chain`.

## Current (main, with syntactic prefilter)

| principals | direct check (3 invariants) | assume-role graph build | closure check (3 invariants) |
|---|---|---|---|
| 100 | 0.02 s | 0.02 s | 0.01 s |
| 1,000 | 0.11 s | 0.14 s | 0.10 s |
| 10,000 | **1.01 s** | 1.34 s | **1.00 s** |

Scaling is linear in account size, and a full 10k-principal account — including building
the assume-role graph and re-checking every invariant over transitive chains — completes
in under 2.5 s total.

## Why: skipping provably-unsatisfiable solver queries

Z3 costs ~12 ms per `(principal, invariant)` query. v0.6.0 issued one query for every
pair; as of the current main, a **sound syntactic prefilter** first checks (in pure
Python) whether *any* Allow statement's Action/Resource glob patterns can even intersect
the invariant's — via an exact glob–glob intersection test
(`engine.patterns.globs_intersect`). If not, `allowed()` is provably unsatisfiable and
the query is skipped. The skip is exact, not heuristic: conditions and bounding layers
can only *restrict* a grant further, and `NotAction`/`NotResource` statements
conservatively always pass through to Z3. An equivalence check over 500 principals
confirms identical violator sets with the prefilter enabled and disabled.

Two more changes on the same theme: the assume-role graph is built trust-side-out (only
principals a trust policy names are candidate sources — cost scales with trust grants,
not principal pairs), and per-target check results are memoized during closure
evaluation (a hub role reachable from 1,000 sources is solved once, not 1,000 times).

## Worst case (v0.6.0 behavior: every pair hits Z3)

The prefilter's benefit depends on most principals syntactically lacking the forbidden
permissions — true of real accounts, where most roles never touch the invariant's
services. The adversarial worst case (every principal carries wildcard policies that
could match everything) degrades to one Z3 query per pair, i.e. exactly the v0.6.0
numbers:

| principals | direct check (3 invariants) | closure check (3 invariants) |
|---|---|---|
| 100 | 3.7 s | 4.4 s |
| 1,000 | 37.0 s | 43.0 s |
| 10,000 | 388.5 s | — |

Still linear (~13 ms × principals × invariants) — a 10k-principal, 10-invariant
worst-case run is ~20 minutes, tractable for a nightly job; the realistic case is
seconds.

## PassRole closure (v0.7)

The synthetic accounts above contain no service-trusted roles, so they say nothing about
`--closure pass-role`. A dedicated stress shape: the same 10k-principal mix, plus a Lambda
execution role every 25 principals (400 roles) and a deployer every 50 (200 principals
with **wildcard** `iam:PassRole` + `lambda:CreateFunction`) — a dense worst case where
every deployer can pass every role, giving 80,400 real edges. Reproduce with
`python scripts/benchmark.py --sizes 100 --passrole-sizes 1000 10000`.

| principals | `--closure all` graph build | closure check (3 invariants) |
|---|---|---|
| 1,000 | 0.13 s | 0.23 s |
| 10,000 | **2.34 s** | 2.52 s |

A first cut issued one Z3 query per (deployer, role) pair and took **240 s** to build the
10k graph. Two exact optimizations brought that to 2.3 s with an identical edge set:
principals that cannot syntactically pass *any* role are dropped as sources up front, and
a solver-free fast path decides PassRole/launch permission when it is provably granted (an
unconditional matching Allow, no Deny that could touch the request, no permission
boundary) — anything else still goes to Z3.

## Notes

- Counterexample extraction is included in all timings.
- `--max-hops` bounds BFS depth, not graph construction; graph build is where closure
  cost concentrates, and it is amortized across all invariants via `ReachabilityIndex`.
- Numbers will vary with policy complexity (statement count, condition operators,
  wildcard density) more than with principal count.
