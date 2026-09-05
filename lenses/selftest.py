#!/usr/bin/env python3
"""Self-checks for the lenses.

There is no test framework here on purpose: the toolkit installs nothing, so
its checks should not either. Every case builds a tiny throwaway git repo in a
temp directory, runs a lens against it exactly the way a user would, and
asserts on the output.

    python3 lenses/selftest.py            # run everything
    python3 lenses/selftest.py arch       # run cases whose name contains "arch"

Fixtures are invented. No case reads anything outside its own temp directory.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path

LENSES = Path(__file__).resolve().parent
PY = sys.executable or "python3"

CASES: list[tuple[str, object]] = []


def case(fn):
    CASES.append((fn.__name__, fn))
    return fn


# --------------------------------------------------------------------------- #
# fixture helpers
# --------------------------------------------------------------------------- #
def _git(repo: Path, *args: str) -> str:
    """Run git with identity and hooks pinned, so a machine's global config
    (hooksPath, commit signing, a missing user.email) cannot fail a fixture."""
    out = subprocess.run(
        ["git", "-C", str(repo),
         "-c", "user.name=lens selftest",
         "-c", "user.email=selftest@example.invalid",
         "-c", "commit.gpgsign=false",
         "-c", "core.hooksPath=/dev/null",
         *args],
        capture_output=True, text=True)
    if out.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {out.stderr.strip()}")
    return out.stdout


def write_files(repo: Path, files: dict[str, str]) -> None:
    for rel, body in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")


def make_repo(tmp: Path, files: dict[str, str], commits: int = 1) -> Path:
    """A git repo containing `files`, committed `commits` times (for churn)."""
    repo = tmp / "fixture"
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q", "-b", "main")
    write_files(repo, files)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "initial")
    for n in range(1, commits):
        # Touch every file so churn is non-zero and comparable across the tree.
        for rel in files:
            p = repo / rel
            p.write_text(p.read_text(encoding="utf-8") + f"\n# rev {n}\n"
                         if rel.endswith(".py")
                         else p.read_text(encoding="utf-8") + f"\n// rev {n}\n",
                         encoding="utf-8")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", f"rev {n}")
    return repo


def run_lens(script: str, *args: str, expect_ok: bool = True):
    """Run a lens as a subprocess, the way the README tells people to."""
    cmd = ([PY, str(LENSES / script)] if script.endswith(".py")
           else ["node", str(LENSES / script)]) + list(args)
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          env={**os.environ, "PYTHONPATH": str(LENSES)})
    if expect_ok and proc.returncode != 0:
        raise AssertionError(
            f"{script} exited {proc.returncode}\nSTDOUT:\n{proc.stdout}\n"
            f"STDERR:\n{proc.stderr}")
    return proc


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# coverage_gap: repo-path-first CLI, --md / --json, optional --scores
# --------------------------------------------------------------------------- #
COVERAGE_FIXTURE = {
    "pkg/__init__.py": "",
    "pkg/pricing.py": "def quote(a, b):\n    if a > b:\n        return a\n    return b\n",
    "pkg/mailer.py": "def send(to):\n    if not to:\n        return None\n    return to\n",
    "tests/test_mailer.py": "from pkg.mailer import send\n\n\ndef test_send():\n    assert send('x')\n",
}


@case
def coverage_gap_repo_first_cli():
    """The natural invocation: repo path first, --md, --json, no --scores."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        repo = make_repo(tmp, COVERAGE_FIXTURE, commits=3)
        md, js = tmp / "REPORT-coverage.md", tmp / "data-coverage.json"
        run_lens("coverage_gap.py", str(repo), "--since", "10 years ago",
                 "--min-impact", "1", "--md", str(md), "--json", str(js))
        assert md.is_file(), "--md wrote nothing"
        rows = load_json(js)
        files = {r["file"] for r in rows}
        assert "pkg/pricing.py" in files, f"pricing.py missing from {files}"
        by_file = {r["file"]: r for r in rows}
        # mailer is named by a test file, pricing is not: pricing must rank above.
        assert by_file["pkg/mailer.py"]["test_refs"] == 1, by_file["pkg/mailer.py"]
        assert by_file["pkg/pricing.py"]["test_refs"] == 0, by_file["pkg/pricing.py"]
        assert rows[0]["file"] == "pkg/pricing.py", f"wrong top row: {rows[0]}"
        assert "COVERAGE-GAP lens" in md.read_text(encoding="utf-8")


@case
def coverage_gap_prints_to_stdout_by_default():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        repo = make_repo(tmp, COVERAGE_FIXTURE, commits=2)
        proc = run_lens("coverage_gap.py", str(repo), "--since", "10 years ago",
                        "--min-impact", "1")
        assert "COVERAGE-GAP lens" in proc.stdout, proc.stdout[:400]
        assert "pkg/pricing.py" in proc.stdout


@case
def coverage_gap_legacy_positional_order_still_works():
    """The old `<scores.json> <repo>` shape keeps working, with a warning."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        repo = make_repo(tmp, COVERAGE_FIXTURE, commits=3)
        scores = tmp / "data.json"
        run_lens("score_targets.py", str(repo), "--since", "10 years ago",
                 "--json", str(scores), "--md", str(tmp / "t.md"))
        new_json, old_json = tmp / "new.json", tmp / "old.json"
        run_lens("coverage_gap.py", str(repo), "--scores", str(scores),
                 "--min-impact", "1", "--md", str(tmp / "a.md"), "--json", str(new_json))
        proc = run_lens("coverage_gap.py", str(scores), str(repo),
                        "--min-impact", "1", "--md", str(tmp / "b.md"),
                        "--json", str(old_json))
        assert "deprecated" in proc.stderr, proc.stderr
        assert load_json(new_json) == load_json(old_json), "legacy order diverged"


# --------------------------------------------------------------------------- #
def main() -> int:
    wanted = sys.argv[1:]
    selected = [(n, f) for n, f in CASES
                if not wanted or any(w in n for w in wanted)]
    if not selected:
        print(f"no case matches {wanted}", file=sys.stderr)
        return 2
    failures = 0
    for name, fn in selected:
        try:
            fn()
        except Exception:
            failures += 1
            print(f"FAIL {name}")
            traceback.print_exc()
        else:
            print(f"ok   {name}")
    print(f"\n{len(selected) - failures}/{len(selected)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
