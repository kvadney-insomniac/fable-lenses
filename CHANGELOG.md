# Changelog

All notable changes to fable-lenses are recorded here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and the version
numbers follow [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).
Until 1.0.0, a minor bump may change report formats, JSON fields or flags.

The newest version heading below must match the `VERSION` file at the repo root;
`scripts/check_version.py` enforces that in CI and before every release.

## [Unreleased]

## [0.1.0] - 2026-11-03

First tagged release. The toolkit had been public and in use since August 2026;
this release pins a version to it and adds the checks a release needs.

### Added

- Eight deterministic lenses, each scoring every file on impact x opportunity
  and bucketing both axes by quintile within the repo: tech debt
  (`score_targets.py`), coverage gap (`coverage_gap.py`), security
  (`security_lens.py`), dead code (`deadcode_lens.py`), drift for Python
  (`drift_lens.py`) and for TS/JS (`drift_lens_ts.js`), architecture and
  coupling (`arch_lens.py`), CI health (`ci_lens.py`) and opportunity v2
  (`opportunity_v2.py`).
- `run_all.py`: one command that runs every lens into one directory and writes
  `REPORT-index.md`, the top rows of each lens with the exact command that
  produced them. Lenses that cannot run are recorded as skipped; a lens that
  errors is recorded with its message while the others still report
  ([#1](https://github.com/kvadney-insomniac/fable-lenses/pull/1)).
- `selftest.py`: 22 self-checks that build throwaway git repos and run the
  lenses against them, with no test framework to install.
- Tier-1 triage tooling: `triage_candidates.py`, `triage_workflow.js` and
  `triage_report.py`, with the annotate-only policy for security rows.
- `VERSION` file and `run_all.py --version`, the single source of the toolkit's
  version number.
- CI workflow (`ci.yml`): ruff lint over the Python lenses and scripts, a
  syntax check of the node lenses, the self-checks on Python 3.11, 3.12 and
  3.13 with TypeScript 5 (plus one cell on TypeScript 6), a check that
  `VERSION`, this changelog and `--version` agree, and a check that no tracked
  file contains an em dash or an en dash. Replaces the earlier `selftest.yml`
  ([#6](https://github.com/kvadney-insomniac/fable-lenses/pull/6)).
- Release workflow (`release.yml`): on a `v*` tag, verifies the tag equals
  `VERSION`, runs the self-checks, and creates a GitHub Release whose body is
  this file's section for that version. Nothing is published to a package
  index.
- `scripts/check_version.py`, `scripts/check_dashes.py` and
  `scripts/release_notes.py`, runnable locally the same way CI runs them.
- README: install steps, a two-minute example run against this repository
  itself, a FAQ, and a references section.
- Dependabot for GitHub Actions versions
  ([#6](https://github.com/kvadney-insomniac/fable-lenses/pull/6)).

### Fixed

Fixes that landed before the first tag, from running every lens end to end
against two large private repositories (a FastAPI backend and a Next.js
front end):

- arch lens: resolves TS/JS imports through `tsconfig.json` `paths` and
  `baseUrl`, relative specifiers, implicit extensions and `index` files; it
  previously saw no TypeScript edges at all
  ([#1](https://github.com/kvadney-insomniac/fable-lenses/pull/1)).
- arch lens: a top-layer module importing its own layer is not a violation for
  TS/JS by default; `--strict-top-layer` turns that back on
  ([#1](https://github.com/kvadney-insomniac/fable-lenses/pull/1)).
- dead-code lens: Next.js convention files and files wired in by
  `next.config.*`, `sentry.*.config.*` or a `package.json` script are not dead
  ([#1](https://github.com/kvadney-insomniac/fable-lenses/pull/1)).
- drift lenses: a builder and the inner function it returns are no longer
  reported as a drifted pair
  ([#1](https://github.com/kvadney-insomniac/fable-lenses/pull/1)).
- security lens: `exec` on TS/JS was matching `RegExp.prototype.exec`; the
  pattern is Python-only now and Node's `child_process` exec is counted only in
  files that import it
  ([#1](https://github.com/kvadney-insomniac/fable-lenses/pull/1)).
- security lens: router-level auth via `APIRouter(dependencies=[...])` and
  `include_router(..., dependencies=[...])` suppresses `route_no_auth_dep`, and
  suppressed handlers are counted in the report
  ([#3](https://github.com/kvadney-insomniac/fable-lenses/pull/3)).
- coverage lens: reads `--tests-dir` and every co-located `*.test.*` or
  `test_*.py` file in the tree, and says how many of each it found
  ([#4](https://github.com/kvadney-insomniac/fable-lenses/pull/4),
  [#5](https://github.com/kvadney-insomniac/fable-lenses/pull/5)).
- dead-code lens: import specifiers are read one per line, so an apostrophe in
  a doc comment no longer hides the import under it; a file referenced only by
  tests is listed and marked `test-only`
  ([#5](https://github.com/kvadney-insomniac/fable-lenses/pull/5)).
- drift lenses: `--top` caps the report, not the JSON
  ([#5](https://github.com/kvadney-insomniac/fable-lenses/pull/5)).
- Lint: two unused imports removed, semicolon-joined statements split and two
  lambda assignments turned into functions, so `ruff check` passes clean.

[Unreleased]: https://github.com/kvadney-insomniac/fable-lenses/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kvadney-insomniac/fable-lenses/releases/tag/v0.1.0
