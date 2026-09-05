# fable-lenses

A targeting machine for expensive-model time.

Sweep a codebase with cheap, deterministic passes; score every file on
**`impact × opportunity`**; discard the low scores; keep a ranked list of
high-leverage work *ready to point a premium model at*, rather than letting it
roam and burn context on point fixes.

The method follows the bug-hunting approach popularized by security
researchers: a cheap pass ranks where to look, an expensive one does the hard
work.

- **impact = git churn.** Exact, straight from git history. No model tokens
  spent estimating what the repository already knows.
- **opportunity = complexity.** Real cyclomatic and nesting depth via the
  stdlib `ast` for Python; a line-and-branch heuristic for TypeScript and
  JavaScript.
- Each axis becomes a 1–5 quintile bucket *within the repo*, multiplied to a
  1–25 score. Files where either axis lands in bucket 1–2 are discarded.

Scores are quintiles **within a repository**, so a score of 16 in one repo is
not comparable to a 16 in another. Rank inside a repo only.

## The lenses

One deterministic shape, `impact × opportunity`, applied through several
lenses. Every lens is a **recall filter**: it ranks where to look. It does not
pass judgement, and it is wrong often enough that you must confirm before
acting.

| lens | script | impact × opportunity |
|---|---|---|
| **tech debt** | `score_targets.py` | git churn × code complexity |
| **coverage gap** | `coverage_gap.py` | high churn × weak test coverage |
| **security** | `security_lens.py` | attack-surface reach × vulnerability likelihood |
| **dead code** | `deadcode_lens.py` | unused-confidence × size |
| **drift** | `drift_lens.py`, `drift_lens_ts.js` | copy-paste clones that diverged |
| **arch / coupling** | `arch_lens.py` | fan-in × (layering violations ⊕ cycles ⊕ fan-out) |
| **CI health** | `ci_lens.py` | run frequency × failure rate (cancelled ≠ failed) |
| **opportunity v2** | `opportunity_v2.py` | churn × (complexity ⊕ issue/audit/incident evidence) |

`run_all.py` runs all of them against one repo and writes a single
`REPORT-index.md` over the results; `selftest.py` checks the lenses themselves.

### Why drift is the interesting one

Most lenses rank *suspicion*. The drift lens ranks a specific bug shape: a
block copy-pasted to N sites where the copies then diverged, a guard added to
two of four call sites, a parser taught about new cases in one copy only.
Nothing fails when this happens. The copies simply disagree, and only under the
inputs the fix was about, which is why it survives review and testing.

It works by normalizing tokens (identifiers → `ID`, literals → `LIT`, keywords
kept), so clones differing only in names collapse to identical, and a real logic
difference is what shows up. Pairs whose similarity is *high but below 1.0* are
the drift band. Exactly 1.0 is a plain clone, tidiness debt, reported
separately.

## Install

No package to install. Python 3.11+ for the `.py` lenses (standard library
only); Node with **`typescript` 5.x** available for `drift_lens_ts.js`, either
in the repo being scanned or on `NODE_PATH` (TypeScript 7 ships the native
port, whose JavaScript package has no compiler API); the GitHub CLI (`gh`),
authenticated, for the CI and opportunity lenses.

```bash
git clone https://github.com/kvadney-insomniac/fable-lenses.git
```

## Run

Every lens takes the path to the repository you want to scan as its **first
argument**, writes its report to **stdout** unless you pass `--md PATH`, and is
**read-only** with respect to that repo, git history, static text, and the
GitHub API. No lens edits the code it is pointed at.

### Start here: all of them at once

```bash
python3 lenses/run_all.py /path/to/repo --out lens-out
```

That runs every lens into `lens-out/` as `REPORT-<lens>.md` and
`data-<lens>.json`, plus **`REPORT-index.md`**: the top 10 of each lens, one
line each, with the exact command that produced it. Read the index first, then
open the report a row came from.

Two lenses need the GitHub API and run only with `--gh-repo OWNER/NAME` (the CI
lens and opportunity v2); the TS/JS drift lens needs node with a resolvable
`typescript` 5.x. Anything that cannot run is listed in the index as
`skipped: reason` rather than failing the run, and a lens that errors is
recorded with its message while the other lenses still report.

Useful flags: `--since` (churn window), `--top` (rows per lens), `--ref` (the
git ref the arch lens reads), `--src-root`, `--tests-dir`, `--app-module`,
`--skip LENS`.

### Or one lens at a time

```bash
# tech debt, the core lens, and the one to start with
python3 lenses/score_targets.py /path/to/repo --since "180 days ago" --top 40 \
    --md REPORT.md --json data.json

# coverage gap: churn crossed with how little the tests mention a module.
# --scores reuses a score_targets run; without it that pass runs in-process.
python3 lenses/coverage_gap.py /path/to/repo --tests-dir tests/ \
    --md REPORT-coverage.md --json data-coverage.json

# drift, copy-pasted logic that diverged
python3 lenses/drift_lens.py /path/to/repo --md REPORT-drift.md
node lenses/drift_lens_ts.js /path/to/repo --md REPORT-drift-ts.md

# dead code, a candidate list, NOT a delete list
python3 lenses/deadcode_lens.py /path/to/repo --md REPORT-deadcode.md

# security, attack-surface reach × vulnerability likelihood.
# --app-module is the file that mounts the routers (default: app/main.py).
python3 lenses/security_lens.py /path/to/repo --app-module app/main.py \
    --md REPORT-security.md

# arch / coupling. --lang defaults to every language present; TS/JS imports
# resolve through tsconfig paths, baseUrl and index files.
python3 lenses/arch_lens.py /path/to/repo --md REPORT-arch.md
```

### Where each lens writes

| script | default | `--md` | `--json` | notes |
|---|---|---|---|---|
| `run_all.py` | `--out DIR`, default `lens-out/` | writes `REPORT-<lens>.md` per lens | writes `data-<lens>.json` per lens | also writes `REPORT-index.md` |
| `score_targets.py` | stdout | yes | yes | |
| `coverage_gap.py` | stdout | yes | yes | `--scores FILE` optional; the old `<scores.json> <repo>` argument order still works and warns |
| `security_lens.py` | stdout | yes | yes | `--app-module FILE` for the router wiring |
| `deadcode_lens.py` | stdout | yes | yes | |
| `arch_lens.py` | stdout | yes | yes | `--lang auto\|py\|ts`, `--strict-top-layer` |
| `drift_lens.py` | stdout | yes | yes | |
| `drift_lens_ts.js` | stdout | yes | yes | needs `typescript` 5.x in the target repo or on `NODE_PATH` |
| `ci_lens.py` | stdout | yes | yes | needs `gh` |
| `opportunity_v2.py` | `TARGETS-v2.md` | yes | `--json` | needs `gh`; `--data` is a `score_targets.py --json` file |

No lens writes anything into the repository it is scanning, and none of them
writes into the current directory unless you name a path there.

Lens output, `REPORT-*.md`, `data-*.json`, is git-ignored by default. Those
files are about *your* codebase and routinely name internal services, routes
and paths; a security report in particular is a map of your own soft spots.

### Self-checks

```bash
python3 lenses/selftest.py          # everything
python3 lenses/selftest.py arch     # cases whose name contains "arch"
```

Each case builds a throwaway git repo in a temp directory and runs a lens
against it the way you would. No framework to install, and nothing is read
from outside the fixture.

## Validate before you trust it

Run the core lens and check that its top tier reproduces hot spots you already
know about. If the files you would have named yourself do not surface
unprompted, the weighting is wrong for your codebase, fix that before going
further. On the repository this was extracted from, the known problem files
surfaced without being asked for; on an unrelated repository used as a control,
the top targets were exactly the files an unrelated piece of work had already
independently identified as needing changes.

That check is the whole basis for trusting the ranking. Do it first.

## Validated on

Every lens has been run end to end against two large real repositories: a
Python FastAPI backend (~560 modules, `app/` layout, routers mounted in
`app/main.py`) and a Next.js/TypeScript front end (~890 modules under `src/`,
app router, `@/` path alias). Neither is public, so what follows is the shapes
and the failure classes, not the code.

What that run found, and what changed as a result:

- **The arch lens saw no TypeScript at all.** It reported the front end as
  "8 modules, 0 import edges", which reads as "no coupling" when it means "no
  import was resolved". It now resolves TS/JS imports through `tsconfig.json`
  `paths` and `baseUrl`, relative specifiers, implicit extensions and `index`
  files: same repo, 888 modules and 3353 edges.
- **Next.js convention files looked dead.** `instrumentation-client.ts` and
  `app/global-error.tsx` were flagged with high confidence because nothing
  imports them; the framework loads them by name. The whole convention set is
  recognised now, along with files wired in by `next.config.*`,
  `sentry.*.config.*` or a `package.json` script.
- **A builder and the function it returns looked like a drifted clone pair.**
  The outer function's source span contains the inner one, so they always score
  as near-identical copies with nothing to reconcile. Pairs where one line
  range contains the other are skipped, in both drift lenses.
- **`route_no_auth_dep` could not see router-level auth.** FastAPI applies
  `APIRouter(dependencies=[...])` and `include_router(..., dependencies=[...])`
  to every handler underneath. Both are read now, only when the dependency list
  itself names an auth dependency, and suppressed handlers are counted in the
  report rather than deleted from it.
- **`exec` on TS/JS was `RegExp.prototype.exec`.** A regex match was scoring as
  code execution at weight 5 and pushing files into the top quadrant. The
  pattern is Python-only now; Node's real one is counted only in a file that
  imports `child_process`.
- **A top-layer module importing its own layer is normal in `app/`.** Next.js
  colocates by design. Left on, that rule reported 71 violations on the front
  end where 14 are real, so it is off for TS/JS and `--strict-top-layer` turns
  it back on.

The lesson underneath all six: a lens that cannot resolve something reports
*silence*, and silence looks exactly like a clean result. Check that the counts
a lens gives you are plausible for the repo's size before you trust its
ranking, which is what the section above is about.

## Triage before you dispatch

The lenses' recorded failure mode is **staleness and false positives**: targets
that were already fixed before anyone looked at them. Verifying by hand burns
expensive-model time on exactly the work a cheap model does well, so the
machine is a three-tier funnel.

```
Tier 0   lenses (deterministic)   free      recall     rank candidates per lens
Tier 1   cheap-model triage       cheap     precision  verify each against a ref
Tier 2   premium investigation    costly    judgment   deep-dive and fix survivors
```

`triage_candidates.py` assembles the capped candidate list; `triage_workflow.js`
runs one cheap agent per candidate, verifying against a git ref via
`git show` / `git grep` / `git log` only, never a checkout, so it is safe to
run agents in parallel. Each returns a structured verdict:
`real / already-fixed / false-positive / unclear`.

**One policy is deliberate: cheap models may not bury security findings.**
Security-lens rows are annotate-only, a cheap verdict adds context, but the row
always appears in the report. The asymmetry is the argument: a false discard on
an auth or tenancy issue is invisible, while a false pass costs one expensive
look. The same caution applies to trusting a `delete-candidate` verdict, since
dead-code detection cannot see dynamic references.

## What these are not

Not a linter, and not a judge. A lens tells you where to spend attention; it has
no opinion on whether the code is wrong. Every finding needs confirmation, and
the dead-code and security lenses in particular are tuned for recall over
precision on purpose, they would rather show you a false positive than hide a
real one.

## License

MIT.
