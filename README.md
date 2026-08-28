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
only); Node with `typescript` available for `drift_lens_ts.js`; the GitHub CLI
(`gh`), authenticated, for the CI and opportunity lenses.

```bash
git clone https://github.com/kvadney-insomniac/fable-lenses.git
```

## Run

Every lens takes the path to the repository you want to scan and is
**read-only** with respect to it, git history, static text, and the GitHub
API. No lens edits the code it is pointed at.

```bash
# tech debt, the core lens, and the one to start with
python3 lenses/score_targets.py /path/to/repo --since "180 days ago" --top 40 \
    --md REPORT.md --json data.json

# drift, copy-pasted logic that diverged
python3 lenses/drift_lens.py /path/to/repo
node lenses/drift_lens_ts.js /path/to/repo

# dead code, a candidate list, NOT a delete list
python3 lenses/deadcode_lens.py /path/to/repo --md REPORT-deadcode.md

# security, attack-surface reach × vulnerability likelihood
python3 lenses/security_lens.py /path/to/repo --md REPORT-security.md
```

Lens output, `REPORT-*.md`, `data-*.json`, is git-ignored by default. Those
files are about *your* codebase and routinely name internal services, routes
and paths; a security report in particular is a map of your own soft spots.

## Validate before you trust it

Run the core lens and check that its top tier reproduces hot spots you already
know about. If the files you would have named yourself do not surface
unprompted, the weighting is wrong for your codebase, fix that before going
further. On the repository this was extracted from, the known problem files
surfaced without being asked for; on an unrelated repository used as a control,
the top targets were exactly the files an unrelated piece of work had already
independently identified as needing changes.

That check is the whole basis for trusting the ranking. Do it first.

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
