# fable-lenses

A targeting machine for expensive-model time.

Sweep a codebase with cheap, deterministic passes; score every file on
**`impact x opportunity`**; discard the low scores; keep a ranked list of
high-leverage work *ready to point a premium model at*, rather than letting it
roam and burn context on point fixes.

The method follows the bug-hunting approach popularized by security
researchers: a cheap pass ranks where to look, an expensive one does the hard
work. The churn-against-complexity view underneath it is older than this tool:
Michael Feathers described plotting each file's churn against its complexity to
pick refactoring targets in 2011 [[1]](#references), and Adam Tornhill's
behavioural code analysis made "hotspots", complex code that also changes
often, the centre of a book and a product [[2]](#references) [[3]](#references).

- **impact = git churn.** Exact, straight from git history. No model tokens
  spent estimating what the repository already knows.
- **opportunity = complexity.** Real cyclomatic and nesting depth via the
  standard library `ast` module for Python [[4]](#references); a
  line-and-branch heuristic for TypeScript and JavaScript.
- Each axis becomes a 1 to 5 quintile bucket *within the repo*, multiplied to a
  1 to 25 score. Files where either axis lands in bucket 1 or 2 are discarded.

Scores are quintiles **within a repository**, so a score of 16 in one repo is
not comparable to a 16 in another. Rank inside a repo only.

## Install

There is no package to install and nothing to build. Clone the repository and
run the scripts from it.

```bash
git clone https://github.com/kvadney-insomniac/fable-lenses.git
cd fable-lenses
python3 lenses/run_all.py --version
```

| you need | for | notes |
|---|---|---|
| Python 3.11 or newer | every `.py` lens | standard library only, no `pip install`; CI runs the self-checks on 3.11, 3.12 and 3.13 |
| Node 22 with the `typescript` JavaScript compiler API, 5.x or 6.x | `drift_lens_ts.js` only | resolved from the scanned repo's `node_modules` first, then from `NODE_PATH`. TypeScript 7 ships without a JavaScript API, so its package cannot be used here; the TypeScript team points API consumers at the `@typescript/typescript6` package until 7.1 [[5]](#references) |
| the GitHub CLI `gh`, authenticated | `ci_lens.py` and `opportunity_v2.py` only | both run only when `run_all.py` is given `--gh-repo OWNER/NAME` and are recorded as skipped otherwise |
| `git` | everything | churn, history and `git ls-files` are the input; the target must be a git checkout |

Check the install the same way CI does:

```bash
python3 lenses/selftest.py
```

Each of the 22 cases builds a throwaway git repo in a temp directory and runs a
lens against it. Four cases skip when no usable `typescript` package resolves,
and they say so.

## A two-minute example

Run every lens against this repository itself. The output below is a real run,
trimmed to the first rows; the paths are the only thing shortened.

```bash
python3 lenses/run_all.py . --out lens-out --top 3
```

```
[run_all] techdebt ...
[run_all] coverage ...
[run_all] security ...
[run_all] deadcode ...
[run_all] arch ...
[run_all] drift ...
[run_all] drift-ts ...
[run_all] skip ci: needs --gh-repo OWNER/NAME (GitHub API)
[run_all] skip opportunity: needs --gh-repo OWNER/NAME (GitHub API)
wrote lens-out/REPORT-index.md
[run_all] 7/9 lenses ran
```

That run took about four seconds. Read the index first:

```bash
cat lens-out/REPORT-index.md
```

```
| lens        | ranks                                            | status                                  |
|-------------|--------------------------------------------------|-----------------------------------------|
| techdebt    | git churn x code complexity                      | ok                                      |
| coverage    | high churn x weak test coverage                  | ok                                      |
| security    | attack-surface reach x vulnerability likelihood  | ok                                      |
| deadcode    | unused-confidence x size                         | ok                                      |
| arch        | fan-in x (layering violations, cycles, fan-out)  | ok                                      |
| drift       | Python clones that diverged                      | ok                                      |
| drift-ts    | TS/JS clones that diverged                       | ok                                      |
| ci          | run frequency x failure rate                     | skipped: needs --gh-repo OWNER/NAME     |
| opportunity | churn x (complexity, issue/audit evidence)       | skipped: needs --gh-repo OWNER/NAME     |

## techdebt

1. **25** (5x5) `lenses/security_lens.py`, 4 commits, cx 230.2
2. **16** (4x4) `lenses/deadcode_lens.py`, 4 commits, cx 141.1
3. **15** (3x5) `lenses/arch_lens.py`, 3 commits, cx 212.8

## security

1. **25** (5x5) `lenses/security_lens.py`, raw_sql_execx2, dangerously_htmlx2, execx1
2. **10** (5x2) `lenses/score_targets.py`, subprocessx1
3. **5** (1x5) `lenses/selftest.py`, subprocessx3, execx1

## drift

1. 4 copies, `lenses/arch_lens.py:453` **quintile**() +3 more
2. 3 copies, `lenses/selftest.py:343` **drift_py_skips_a_builder_and_its_inner_function**() +2 more
3. 2 copies, `lenses/deadcode_lens.py:477` **_scan_description**() +1 more
```

Three things to notice, because they are what you will see on your own repo:

1. **The tech-debt top row is right.** `security_lens.py` is the largest, most
   branching and most edited file here. That is the check in
   [Validate before you trust it](#validate-before-you-trust-it): the top of
   the list should be where you would have pointed yourself.
2. **The security top row is a false positive, and the report says so.** The
   security lens matches its own pattern table: the strings `.execute(` and
   `dangerouslySetInnerHTML` appear in it as regexes, not as calls. Every row
   is a candidate to confirm, and the report's caveat block lists the known
   over-reporting.
3. **The drift lens found a real clone family.** `quintile()` and the
   `bucket()` helper nested inside it are copied, near-identically, between
   `arch_lens.py` and `ci_lens.py`. Whether that is debt worth paying is a
   judgment call, which is exactly what the lenses leave to you or to the
   model you point at the list.

Every row in the index carries the exact command that produced it, so any row
can be reproduced on its own. The full reports are next to the index as
`lens-out/REPORT-<lens>.md`, with the ranked data in `lens-out/data-<lens>.json`.

## The lenses

One deterministic shape, `impact x opportunity`, applied through several
lenses. Every lens is a **recall filter**: it ranks where to look. It does not
pass judgement, and it is wrong often enough that you must confirm before
acting.

| lens | script | impact x opportunity |
|---|---|---|
| **tech debt** | `score_targets.py` | git churn x code complexity |
| **coverage gap** | `coverage_gap.py` | high churn x weak test coverage |
| **security** | `security_lens.py` | attack-surface reach x vulnerability likelihood |
| **dead code** | `deadcode_lens.py` | unused-confidence x size |
| **drift** | `drift_lens.py`, `drift_lens_ts.js` | copy-paste clones that diverged |
| **arch / coupling** | `arch_lens.py` | fan-in x (layering violations, cycles, fan-out) |
| **CI health** | `ci_lens.py` | run frequency x failure rate (cancelled is not failed) |
| **opportunity v2** | `opportunity_v2.py` | churn x (complexity, issue/audit/incident evidence) |

`run_all.py` runs all of them against one repo and writes a single
`REPORT-index.md` over the results; `selftest.py` checks the lenses themselves.

### Why drift is the interesting one

Most lenses rank *suspicion*. The drift lens ranks a specific bug shape: a
block copy-pasted to N sites where the copies then diverged, a guard added to
two of four call sites, a parser taught about new cases in one copy only.
Nothing fails when this happens. The copies simply disagree, and only under the
inputs the fix was about, which is why it survives review and testing.

It works by normalizing tokens (identifiers to `ID`, literals to `LIT`, keywords
kept), so clones differing only in names collapse to identical, and a real logic
difference is what shows up. Pairs whose similarity is *high but below 1.0* are
the drift band. Exactly 1.0 is a plain clone, tidiness debt, reported
separately.

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
`typescript` compiler API. Anything that cannot run is listed in the index as
`skipped: reason` rather than failing the run, and a lens that errors is
recorded with its message while the other lenses still report.

Useful flags: `--since` (churn window), `--top` (rows per lens in the index),
`--report-top` (rows in each lens's own report), `--ref` (the git ref the arch
lens reads), `--src-root`, `--tests-dir`, `--app-module`, `--skip LENS`,
`--version`.

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

# security, attack-surface reach x vulnerability likelihood.
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
| `coverage_gap.py` | stdout | yes | yes | `--scores FILE` optional; reads `--tests-dir` AND every co-located `*.test.*` / `test_*.py` in the tree; the old `<scores.json> <repo>` argument order still works and warns |
| `security_lens.py` | stdout | yes | yes | `--app-module FILE` for the router wiring |
| `deadcode_lens.py` | stdout | yes | yes | |
| `arch_lens.py` | stdout | yes | yes | `--lang auto\|py\|ts`, `--strict-top-layer` |
| `drift_lens.py` | stdout | yes | yes | `--top N` groups in the report (default 25); the JSON keeps all of them |
| `drift_lens_ts.js` | stdout | yes | yes | `--top N` as above; needs the `typescript` compiler API in the target repo or on `NODE_PATH` |
| `ci_lens.py` | stdout | yes | yes | needs `gh` |
| `opportunity_v2.py` | `TARGETS-v2.md` | yes | `--json` | needs `gh`; `--data` is a `score_targets.py --json` file |

No lens writes anything into the repository it is scanning. Only
`opportunity_v2.py` writes into the current directory without being asked, its
`--md` defaults to `TARGETS-v2.md`, which the triage tooling reads; every other
script prints to stdout until you name a path.

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
- **The coverage lens read one test directory and stopped.** Pointed at
  `e2e/` on the front end it read 122 browser specs, ignored the 838 unit
  tests that sit beside the code, and ranked `MembersTab.tsx` as "0 test
  file(s) mention it" with `MembersTab.test.tsx` in the same directory. It
  now reads `--tests-dir` and every conventionally named test file in the
  tree, and says how many of each it found.
- **A doc-comment apostrophe hid a sibling import from the dead-code lens.**
  The import-specifier regex let a quoted path run across lines, so "the
  client's" in a comment opened a string that closed on the real
  `'./affordability-client'` import below it. Two live client components
  headed the whole-file table. Specifiers are read one per line now.
- **A component's own test kept it "alive".** Every tracked file counted as a
  reference, tests included, so a dialog nothing rendered survived a previous
  dead-code pass because `ConversationViewerDialog.test.tsx` names it. A file
  referenced only by tests is listed now and marked `test-only`.

The lesson underneath all of these: a lens that cannot resolve something reports
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

`triage_report.py` renders the workflow's JSON result into a Markdown report (verified
findings first, false positives folded away, every security row always printed).

**One policy is deliberate: cheap models may not bury security findings.**
Security-lens rows are annotate-only, a cheap verdict adds context, but the row
always appears in the report. The asymmetry is the argument: a false discard on
an auth or tenancy issue is invisible, while a false pass costs one expensive
look. The same caution applies to trusting a `delete-candidate` verdict, since
dead-code detection cannot see dynamic references.

## FAQ

**Does it install anything, phone home, or modify my repository?**
No to all three. The Python lenses import only the standard library, the node
lens needs only the `typescript` package, and every lens is read-only against
the repo it scans. The two lenses that talk to GitHub do so through your own
authenticated `gh` and only when you pass `--gh-repo`. Reports are written
where you say, default `lens-out/`, and that output is git-ignored because it
describes your own codebase.

**Why does the security lens rank `security_lens.py` as its own top target?**
Because the file contains the strings it searches for, as regex patterns. It
is a clean demonstration of what every lens report says in its first lines: a
row is a candidate, not a finding. The same applies to any file in your repo
that defines or tests security patterns.

**Can I compare a score of 16 in one repo with a 16 in another?**
No. Both axes are quintile buckets computed within the repository being
scanned, so the scale is relative to that repo's own distribution. A score
means "top fifth on both axes here", nothing more.

**Is this CodeScene, or Feathers' churn-versus-complexity plot?**
It starts from the same observation, that churn crossed with complexity points
at the code worth attention [[1]](#references) [[2]](#references), and it
makes no claim to have invented that. What is different is the purpose and the
shape: the output is a dispatch list for a model with a context budget, not a
dashboard; it is a set of standalone scripts with no service and no install;
and the drift, security, dead-code and coupling lenses apply the same
`impact x opportunity` shape to bug classes a hotspot view does not rank.

**Which Python and TypeScript versions work?**
Python 3.11 or newer; CI runs the self-checks on 3.11, 3.12 and 3.13. The TS/JS
drift lens needs a `typescript` package whose JavaScript API exports
`createSourceFile` and `SyntaxKind`, which 5.x and 6.x do; CI covers both.
TypeScript 7 ships no JavaScript API [[5]](#references), so with a 7.x
`typescript` in the scanned repo, put a 5.x or 6.x copy somewhere on
`NODE_PATH` instead.

**A lens reports almost nothing. Is my codebase clean?**
Probably not; check the counts first. A lens that could not resolve imports,
find tests or read a config reports silence, and silence looks like a clean
result. Each report states how many files, modules, edges or test files it
read. If those numbers are implausible for the repo's size, fix the input
(`--src-root`, `--tests-dir`, `--app-module`, `NODE_PATH`) before reading the
ranking.

**Why does CI reject em dashes and en dashes?**
House style. The prose in this repository uses commas, colons and plain hyphens,
and `scripts/check_dashes.py` enforces that over every tracked file so the rule
does not depend on anyone remembering it.

**How are versions and releases managed?**
The version lives in one place, the `VERSION` file, and `run_all.py --version`
prints it. `CHANGELOG.md` follows Keep a Changelog [[6]](#references) and the
numbers follow Semantic Versioning [[7]](#references). CI checks that the
newest changelog heading, `VERSION` and `--version` agree. Pushing a tag
`vX.Y.Z` runs the release workflow, which refuses a tag that disagrees with
`VERSION`, reruns the self-checks, and creates a GitHub Release whose notes are
that version's changelog section. Nothing is published to a package index.

**I found a false positive or a lens that mis-resolved something. What now?**
Open an issue with the shape of the code, not the code itself if it is
private, the way the [Validated on](#validated-on) section describes failures.
A fixture in `selftest.py` that reproduces it is the best possible report.

## Contributing

Before opening a pull request, run what CI runs:

```bash
ruff check lenses scripts            # rule set in ruff.toml
for f in lenses/*.js; do node --check "$f"; done
python3 lenses/selftest.py
python3 scripts/check_version.py
python3 scripts/check_dashes.py
```

`ruff` is the only tool that is not already on a machine with Python and node;
install it with `python3 -m pip install ruff` [[8]](#references). Every pull
request also gets the self-checks on three Python versions.

## What these are not

Not a linter, and not a judge. A lens tells you where to spend attention; it has
no opinion on whether the code is wrong. Every finding needs confirmation, and
the dead-code and security lenses in particular are tuned for recall over
precision on purpose, they would rather show you a false positive than hide a
real one.

## References

1. Michael Feathers, "Getting Empirical about Refactoring", 2011.
   <https://www.stickyminds.com/article/getting-empirical-about-refactoring>
2. Adam Tornhill, *Your Code as a Crime Scene*, The Pragmatic Bookshelf;
   talk coverage at InfoQ, 2015.
   <https://www.infoq.com/news/2015/03/code-as-a-crime-scene>
3. CodeScene, the product built on behavioural code analysis.
   <https://en.wikipedia.org/wiki/CodeScene>
4. Python documentation, `ast`, Abstract Syntax Trees.
   <https://docs.python.org/3/library/ast.html>
5. Microsoft, "Announcing TypeScript 7.0": "it does not ship with an API", the
   `@typescript/typescript6` package re-exports the 6.0 API, and a new API is
   expected in 7.1.
   <https://devblogs.microsoft.com/typescript/announcing-typescript-7-0/>
6. Keep a Changelog 1.1.0. <https://keepachangelog.com/en/1.1.0/>
7. Semantic Versioning 2.0.0. <https://semver.org/spec/v2.0.0.html>
8. Ruff, rule reference. <https://docs.astral.sh/ruff/rules/>
9. GitHub Docs, events that trigger workflows (tag filters on `push`).
   <https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows>
10. GitHub Docs, using GitHub CLI in workflows (`gh` is preinstalled on
    GitHub-hosted runners; `GH_TOKEN` from `GITHUB_TOKEN`).
    <https://docs.github.com/en/actions/how-tos/writing-workflows/choosing-what-your-workflow-does/using-github-cli-in-workflows>

## License

MIT.
