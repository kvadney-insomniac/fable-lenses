#!/usr/bin/env python3
"""Run every lens against one repository, with one entry point to read after.

The lenses are separate scripts on purpose, each is meant to be runnable and
readable on its own. The cost of that is a person (or a model) pointing at a
new codebase has to know eight invocations, each with its own flags, and then
has to open eight reports to find out which ones said anything.

This runs all of them with consistent flags into one directory:

    REPORT-<lens>.md      the lens's own report, unchanged
    data-<lens>.json      the lens's ranked data
    REPORT-index.md       the top 10 of every lens, one line each

Read REPORT-index.md first, then open the report a row came from. Nothing here
adds judgement: the index is a table of contents over the same rankings, so
every caveat in the individual reports still applies. The lenses are recall
filters, and confirming a row is still the next step.

Two lenses need the GitHub API (`gh`, authenticated): the CI lens and
opportunity v2. They run only when `--gh-repo OWNER/NAME` is given, and are
recorded as skipped otherwise rather than failing the run. The TS drift lens
needs node with a resolvable `typescript` 5.x, and is skipped the same way.

Usage:
    python3 lenses/run_all.py /path/to/repo --out lens-out
    python3 lenses/run_all.py /path/to/repo --out lens-out --gh-repo owner/name
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PY = sys.executable or "python3"


# --------------------------------------------------------------------------- #
# index rendering: one line per row, per lens
# --------------------------------------------------------------------------- #
def _top_techdebt(data, n):
    return [f"**{r['score']}** ({r['impact']}x{r['opportunity']}) `{r['file']}`, "
            f"{r['commits']} commits, cx {r['complexity']['raw']}"
            for r in data[:n]]


def _top_coverage(data, n):
    return [f"gap **{r['gap']}** `{r['file']}`, {r['commits']} commits, "
            f"{r['test_refs']} test file(s) mention it" for r in data[:n]]


def _top_security(data, n):
    out = []
    for r in data[:n]:
        pats = ", ".join(f"{k}x{v}" for k, v in
                         sorted(r["patterns"].items(), key=lambda kv: -kv[1])[:3])
        out.append(f"**{r['score']}** ({r['reach']}x{r['vuln']}) `{r['file']}`, "
                   f"{pats or 'no risk patterns, reach-driven'}")
    return out


def _top_deadcode(data, n):
    rows = [f"`{r['file']}`, {r['loc']} LOC, confidence {r['confidence']}"
            for r in data.get("files", [])[:n]]
    if not rows:
        rows = [f"symbol `{r['symbol']}` in `{r['file']}` ({r['loc']} LOC file)"
                for r in data.get("symbols", [])[:n]]
    return rows


def _top_arch(data, n):
    return [f"**{r['score']}** ({r['impact']}x{r['opportunity']}) `{r['module']}`, "
            f"fan-in {r['fan_in']}, fan-out {r['fan_out']}"
            + (f", {len(r['violations'])} layering violation(s)" if r["violations"] else "")
            + (", in a cycle" if r["in_cycle"] else "")
            for r in data.get("rows", [])[:n]]


def _top_drift(data, n):
    out = []
    for group in data[:n]:
        head = group[0]
        others = len(group) - 1
        out.append(f"{len(group)} copies, `{head['file']}:{head['line']}` "
                   f"**{head['name']}**()" + (f" +{others} more" if others else ""))
    return out


def _top_ci(data, n):
    return [f"**{w['score']}** `{w['workflow']}`, {w['runs']} runs, "
            f"{int(w['failure_rate'] * 100)}% failure rate"
            for w in data.get("workflows", [])[:n]]


def _top_opportunity(data, n):
    return [f"`{r['file']}` rose {r['delta_rank']} places "
            f"({r['old_score']} -> {r['new_score']}), {r['issues']} issue hit(s)"
            for r in data[:n]]


# name -> (report stem, extractor, what the lens ranks)
EXTRACTORS = {
    "techdebt": (_top_techdebt, "git churn x code complexity"),
    "coverage": (_top_coverage, "high churn x weak test coverage"),
    "security": (_top_security, "attack-surface reach x vulnerability likelihood"),
    "deadcode": (_top_deadcode, "unused-confidence x size"),
    "arch": (_top_arch, "fan-in x (layering violations, cycles, fan-out)"),
    "drift": (_top_drift, "Python clones that diverged"),
    "drift-ts": (_top_drift, "TS/JS clones that diverged"),
    "ci": (_top_ci, "run frequency x failure rate"),
    "opportunity": (_top_opportunity, "churn x (complexity, issue/audit evidence)"),
}


# --------------------------------------------------------------------------- #
def have_typescript(repo: Path) -> bool:
    if not shutil.which("node"):
        return False
    probe = (
        "const p=require('path');"
        "for (const c of [p.join(process.argv[1],'node_modules','typescript'),'typescript']) {"
        "  try { const t=require(c); if (t.createSourceFile) process.exit(0); } catch {}"
        "}"
        "process.exit(9);"
    )
    return subprocess.run(["node", "-e", probe, str(repo.resolve())],
                          capture_output=True).returncode == 0


def has_ext(repo: Path, *patterns: str) -> bool:
    out = subprocess.run(["git", "-C", str(repo), "ls-files", *patterns],
                         capture_output=True, text=True)
    return bool(out.stdout.strip())


def build_plan(args, repo: Path, out: Path) -> list[dict]:
    """Every lens, its command, and why it might not run."""
    def md(name):
        return str(out / f"REPORT-{name}.md")

    def js(name):
        return str(out / f"data-{name}.json")

    src_root_flags = []
    for r in args.src_root or []:
        src_root_flags += ["--src-root", r]

    plan = [
        {"name": "techdebt", "cmd": [PY, str(HERE / "score_targets.py"), str(repo),
                                     "--since", args.since, "--top", str(args.top),
                                     "--md", md("techdebt"), "--json", js("techdebt")]},
        # Reuses the ranking the tech-debt pass just wrote, rather than
        # recomputing churn and complexity for the whole repo a second time.
        {"name": "coverage", "cmd": [PY, str(HERE / "coverage_gap.py"), str(repo),
                                     "--scores", js("techdebt"),
                                     "--tests-dir", args.tests_dir,
                                     "--top", str(args.top),
                                     "--md", md("coverage"), "--json", js("coverage")],
         "after": "techdebt"},
        {"name": "security", "cmd": [PY, str(HERE / "security_lens.py"), str(repo),
                                     *src_root_flags, "--top", str(args.top),
                                     *(["--app-module", args.app_module] if args.app_module else []),
                                     "--md", md("security"), "--json", js("security")]},
        {"name": "deadcode", "cmd": [PY, str(HERE / "deadcode_lens.py"), str(repo),
                                     *src_root_flags, "--top", str(args.top),
                                     "--md", md("deadcode"), "--json", js("deadcode")]},
        {"name": "arch", "cmd": [PY, str(HERE / "arch_lens.py"), str(repo),
                                 "--ref", args.ref, "--top", str(args.top),
                                 "--md", md("arch"), "--json", js("arch")]},
        {"name": "drift", "cmd": [PY, str(HERE / "drift_lens.py"), str(repo),
                                  "--md", md("drift"), "--json", js("drift")],
         "skip": None if has_ext(repo, "*.py") else "no tracked .py files"},
        {"name": "drift-ts", "cmd": ["node", str(HERE / "drift_lens_ts.js"), str(repo),
                                     "--md", md("drift-ts"), "--json", js("drift-ts")],
         "skip": (None if has_ext(repo, "*.ts", "*.tsx", "*.js", "*.jsx",
                                  "*.mjs", "*.cjs")
                  else "no tracked TS/JS files")},
        {"name": "ci", "cmd": [PY, str(HERE / "ci_lens.py"), args.gh_repo or "",
                               "--limit", str(args.ci_limit),
                               "--md", md("ci"), "--json", js("ci")],
         "skip": None if args.gh_repo else "needs --gh-repo OWNER/NAME (GitHub API)"},
        {"name": "opportunity", "cmd": [PY, str(HERE / "opportunity_v2.py"), str(repo),
                                        "--data", js("techdebt"),
                                        "--gh-repo", args.gh_repo or "",
                                        "--ref", args.ref, "--top", str(args.top),
                                        "--md", md("opportunity"),
                                        "--json", js("opportunity")],
         "after": "techdebt",
         "skip": None if args.gh_repo else "needs --gh-repo OWNER/NAME (GitHub API)"},
    ]
    if not any(p["name"] == "drift-ts" and p.get("skip") for p in plan):
        if not have_typescript(repo):
            for p in plan:
                if p["name"] == "drift-ts":
                    p["skip"] = ("needs node with a resolvable typescript 5.x "
                                 "(npm i -D typescript in the target repo)")
    for p in plan:
        if p["name"] in (args.skip or []):
            p["skip"] = "skipped by --skip"
    return plan


def run_plan(plan: list[dict], out: Path, verbose: bool) -> list[dict]:
    results = []
    done: set[str] = set()
    for step in plan:
        name = step["name"]
        cmd = step["cmd"]
        shown = " ".join(cmd)
        reason = step.get("skip")
        if not reason and step.get("after") and step["after"] not in done:
            reason = f"needs the {step['after']} lens, which did not produce data"
        if reason:
            results.append({"name": name, "status": "skipped", "reason": reason,
                            "cmd": shown})
            print(f"[run_all] skip {name}: {reason}", file=sys.stderr)
            continue
        print(f"[run_all] {name} ...", file=sys.stderr)
        started = time.time()
        proc = subprocess.run(cmd, capture_output=True, text=True)
        took = round(time.time() - started, 1)
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout).strip().splitlines()
            results.append({"name": name, "status": "failed", "cmd": shown,
                            "took": took,
                            "reason": tail[-1] if tail else f"exit {proc.returncode}"})
            print(f"[run_all] FAILED {name}: {results[-1]['reason']}", file=sys.stderr)
            continue
        done.add(name)
        results.append({"name": name, "status": "ok", "cmd": shown, "took": took})
        if verbose and proc.stderr.strip():
            print(proc.stderr.strip(), file=sys.stderr)
    return results


def render_index(repo: str, out: Path, results: list[dict], top: int,
                 args) -> str:
    lines = [
        f"# Lens index, `{repo}`",
        "",
        f"_Every lens, top {top}. Written by `run_all.py` into `{out}/`. "
        f"Churn window: {args.since} · git ref: {args.ref}._",
        "",
        "> **Recall filters, not verdicts.** Each row is a candidate to confirm, "
        "not a defect. Open the linked report before acting on anything here, "
        "the caveats that matter are in the individual reports. Scores are "
        "quintiles **within this repo** and do not compare across repos.",
        "",
        "| lens | ranks | status | report |",
        "|------|-------|--------|--------|",
    ]
    for r in results:
        _, ranks = EXTRACTORS.get(r["name"], (None, ""))
        status = r["status"] if r["status"] == "ok" else f"{r['status']}: {r['reason']}"
        link = (f"[REPORT-{r['name']}.md](REPORT-{r['name']}.md)"
                if r["status"] == "ok" else "-")
        lines.append(f"| {r['name']} | {ranks} | {status} | {link} |")
    lines.append("")

    for r in results:
        name = r["name"]
        extractor, ranks = EXTRACTORS.get(name, (None, ""))
        lines.append(f"## {name}")
        lines.append("")
        lines.append(f"_{ranks}. Command:_")
        lines.append("")
        lines.append("```")
        lines.append(r["cmd"])
        lines.append("```")
        lines.append("")
        if r["status"] != "ok":
            lines.append(f"**{r['status']}**: {r['reason']}")
            lines.append("")
            continue
        data_file = out / f"data-{name}.json"
        try:
            data = json.loads(data_file.read_text(encoding="utf-8"))
            rows = extractor(data, top) if extractor else []
        except (OSError, json.JSONDecodeError, KeyError, TypeError, IndexError) as exc:
            lines += [f"_report written, but `{data_file.name}` could not be "
                      f"summarised here ({type(exc).__name__}). Open "
                      f"[REPORT-{name}.md](REPORT-{name}.md)._", ""]
            continue
        if not rows:
            lines += ["_nothing ranked: this lens found no candidates._", ""]
            continue
        for i, row in enumerate(rows, 1):
            lines.append(f"{i}. {row}")
        lines += ["", f"Full report: [REPORT-{name}.md](REPORT-{name}.md)", ""]
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("repo", help="path to the git repo to sweep")
    ap.add_argument("--out", default="lens-out", metavar="DIR",
                    help="directory for the reports and data (default: lens-out)")
    ap.add_argument("--since", default="180 days ago", help="git churn window")
    ap.add_argument("--top", type=int, default=10,
                    help="rows per lens in the index, and --top for each lens "
                         "(default: 10)")
    ap.add_argument("--ref", default="HEAD", help="git ref the arch lens reads")
    ap.add_argument("--src-root", action="append", metavar="DIR",
                    help="source root for the security and dead-code lenses; "
                         "repeatable. Default: each lens auto-detects.")
    ap.add_argument("--tests-dir", default="tests/",
                    help="git pathspec for the test suite (default: tests/)")
    ap.add_argument("--app-module", metavar="FILE",
                    help="module that mounts the routers, for the security lens")
    ap.add_argument("--gh-repo", metavar="OWNER/NAME",
                    help="GitHub repo for the CI and opportunity lenses; without "
                         "it both are recorded as skipped")
    ap.add_argument("--ci-limit", type=int, default=300,
                    help="CI runs to sample (default: 300)")
    ap.add_argument("--skip", action="append", metavar="LENS",
                    help="lens name to skip; repeatable")
    ap.add_argument("--verbose", action="store_true",
                    help="pass through each lens's own stderr summary")
    args = ap.parse_args()

    repo = Path(args.repo)
    if not (repo / ".git").exists():
        print(f"[run_all] {repo} is not a git checkout (no .git); the lenses read "
              "git history and a committed ref", file=sys.stderr)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    plan = build_plan(args, repo, out)
    results = run_plan(plan, out, args.verbose)
    index = out / "REPORT-index.md"
    index.write_text(render_index(args.repo, out, results, args.top, args),
                     encoding="utf-8")

    ok = sum(1 for r in results if r["status"] == "ok")
    failed = [r["name"] for r in results if r["status"] == "failed"]
    print(f"wrote {index}")
    print(f"[run_all] {ok}/{len(results)} lenses ran"
          + (f", failed: {', '.join(failed)}" if failed else ""), file=sys.stderr)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
