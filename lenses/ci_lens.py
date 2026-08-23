#!/usr/bin/env python3
"""CI/CD health lens — which workflows burn the most trust and wall-clock?

impact × opportunity, same shape as the other lenses:
  impact      = run frequency (how often the workflow gates someone)
  opportunity = failure rate (completed runs only; conclusion == failure)

Cancelled runs are counted separately, NOT as failures. A cancelled deploy is
usually supersession — a newer push landed while this run was still queued —
which is healthy churn, and folding it into the failure rate makes the busiest
workflows look the most broken precisely because they are the busiest.

Data source: `gh run list` (GitHub Actions). Deterministic, read-only,
zero model tokens. Needs `gh` authenticated with repo access.

Usage:
  python3 ci_lens.py [OWNER/NAME] [--path .] [--limit 300]
      [--md out.md] [--json out.json]

With no OWNER/NAME the repo is inferred from the git remote of --path.
"""

import argparse
import json
import subprocess
from collections import defaultdict
from datetime import datetime
from pathlib import Path


def quintile(values):
    srt = sorted(values)
    def bucket(v):
        if not srt or v <= 0:
            return 1
        rank = sum(1 for x in srt if x <= v) / len(srt)
        return min(5, 1 + int(rank * 5))
    return bucket


def infer_repo(path):
    """OWNER/NAME for the repo checked out at `path`, from its git remote.

    `gh` already knows how to read every remote URL form (ssh, https, gh:),
    so ask it rather than re-implementing the parsing here.
    """
    out = subprocess.run(
        ["gh", "repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner"],
        cwd=path, capture_output=True, text=True, check=False).stdout.strip()
    if not out:
        raise SystemExit(
            f"[ci_lens] could not infer a GitHub repo from {path!r}; "
            "pass it explicitly as OWNER/NAME")
    return out


def fetch(repo, limit):
    out = subprocess.run(
        ["gh", "run", "list", "-R", repo, "--limit", str(limit),
         "--json", "workflowName,conclusion,status,createdAt,updatedAt,event"],
        capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def main():
    ap = argparse.ArgumentParser(description="CI/CD health lens (GitHub Actions).")
    ap.add_argument("repo", nargs="?",
                    help="GitHub repo as OWNER/NAME (default: infer from --path)")
    ap.add_argument("--path", default=".",
                    help="local checkout to infer the repo from (default: .)")
    ap.add_argument("--limit", type=int, default=300)
    ap.add_argument("--md")
    ap.add_argument("--json")
    args = ap.parse_args()

    repo = args.repo or infer_repo(args.path)
    runs = fetch(repo, args.limit)
    by_wf = defaultdict(list)
    for r in runs:
        by_wf[r["workflowName"]].append(r)

    stats = []
    for wf, rs in by_wf.items():
        done = [r for r in rs if r["status"] == "completed"]
        concl = defaultdict(int)
        for r in done:
            concl[r["conclusion"]] += 1
        durs = []
        for r in done:
            try:
                a = datetime.fromisoformat(r["createdAt"].replace("Z", "+00:00"))
                b = datetime.fromisoformat(r["updatedAt"].replace("Z", "+00:00"))
                durs.append((b - a).total_seconds())
            except ValueError:
                pass
        judged = concl["success"] + concl["failure"]  # exclude cancelled/skipped
        stats.append({
            "workflow": wf,
            "runs": len(rs),
            "success": concl["success"], "failure": concl["failure"],
            "cancelled": concl["cancelled"], "other":
                len(done) - concl["success"] - concl["failure"] - concl["cancelled"],
            "failure_rate": round(concl["failure"] / judged, 3) if judged else 0.0,
            "p50_min": round(sorted(durs)[len(durs) // 2] / 60, 1) if durs else None,
        })

    freq_b = quintile([s["runs"] for s in stats])
    fail_b = quintile([s["failure_rate"] for s in stats])
    for s in stats:
        s["impact"], s["opportunity"] = freq_b(s["runs"]), fail_b(s["failure_rate"])
        s["score"] = s["impact"] * s["opportunity"]
    stats.sort(key=lambda s: (-s["score"], -s["failure_rate"], -s["runs"]))

    if args.json:
        Path(args.json).write_text(json.dumps(
            {"repo": repo, "sampled_runs": len(runs), "workflows": stats}, indent=1))

    window = f"last {len(runs)} runs"
    L = [f"# CI lens — `{repo}` ({window})", "",
         "Failure rate excludes cancelled runs (a cancelled run is usually "
         "supersession by a newer push, not a defect). p50 includes queue time.", "",
         "| score | I×O | workflow | runs | fail rate | fail | cancel | p50 min |",
         "|------:|:---:|----------|-----:|----------:|-----:|-------:|--------:|"]
    for s in stats:
        L.append(f"| {s['score']} | {s['impact']}×{s['opportunity']} | {s['workflow']} "
                 f"| {s['runs']} | {s['failure_rate']:.0%} | {s['failure']} "
                 f"| {s['cancelled']} | {s['p50_min'] if s['p50_min'] is not None else '—'} |")
    report = "\n".join(L) + "\n"
    if args.md:
        Path(args.md).write_text(report)
    print(report)


if __name__ == "__main__":
    main()
