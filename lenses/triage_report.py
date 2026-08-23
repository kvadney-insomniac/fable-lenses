#!/usr/bin/env python3
"""Render a tier-1 triage run (the workflow's JSON result) into a Markdown report.

The synthesis header -- the tier-2 judgment: dispatch shortlist, caveats -- is
written by the premium model and passed via --header; this script renders the
verdict data mechanically, so the report regenerates identically from the JSON
and no verdict is quietly reworded on the way to the page.

Section order is deliberate. Verified-real findings lead; false positives are
folded away in a <details> block because they are the bulk of a healthy run and
reading them is nobody's job. The one section that is never filtered is
security: EVERY security-lens row is printed with its verdict, including the
ones triage called false-positive.

    POLICY -- a cheap model may not silently discard a security finding.
    The asymmetry is the argument: a false discard on an auth/tenancy issue is
    invisible (nobody ever learns the row existed), while a false pass costs
    exactly one premium-model look. So the cheap tier may annotate a security
    row, never bury it. The same reasoning applies to `delete-candidate`
    verdicts elsewhere in the pipeline -- a deletion that looked safe has been
    wrong before, because the only references were dynamic.

Usage:
  python3 triage_report.py --json data-triage.json \\
      [--header header.md] --md TRIAGE.md
"""

import argparse
import json
from pathlib import Path


def esc(s, n=260):
    s = " ".join(str(s).split())
    return s[: n - 1] + "…" if len(s) > n else s


def main():
    ap = argparse.ArgumentParser(description="Render a tier-1 triage run into Markdown.")
    ap.add_argument("--json", required=True,
                    help="the triage workflow's result JSON (has a `verdicts` list)")
    ap.add_argument("--header", help="Markdown file to prepend (the tier-2 synthesis)")
    ap.add_argument("--md", required=True, help="report to write")
    args = ap.parse_args()

    res = json.loads(Path(args.json).read_text())
    vs = res["verdicts"]
    name = lambda v: f"`{v['file']}`" + (f" · `{v.get('symbol')}`" if v.get("symbol") else "")
    # Rows carry the target name they were scored under; older runs may not.
    tgt = lambda v: v.get("target", "")

    L = []
    if args.header:
        L += [Path(args.header).read_text().rstrip(), ""]

    real = [v for v in vs if v["verdict"]["status"] == "real"]
    fixed = [v for v in vs if v["verdict"]["status"] == "already-fixed"]
    fps = [v for v in vs if v["verdict"]["status"] == "false-positive"]
    uncl = [v for v in vs if v["verdict"]["status"] == "unclear"]

    L += [f"## Verified real ({len(real)})", "",
          "| pri | lens | target | file | class | action |",
          "|:---:|------|--------|------|-------|--------|"]
    for v in sorted(real, key=lambda v: (-v["verdict"]["priority"], v["lens"])):
        w = v["verdict"]
        L.append(f"| {w['priority']} | {v['lens']} | {tgt(v)} | {name(v)} "
                 f"| {w['klass']} | {esc(w['suggested_action'])} |")

    L += ["", "### Evidence (real findings)", ""]
    for v in sorted(real, key=lambda v: (-v["verdict"]["priority"], v["lens"])):
        L += [f"- **{name(v)}** ({v['lens']}, p{v['verdict']['priority']}): "
              f"{esc(v['verdict']['evidence'], 420)}"]

    # Annotate-only: every security row is listed whatever its verdict said.
    sec = [v for v in vs if v["lens"] == "security"]
    L += ["", f"## Security annotations - all {len(sec)} rows (annotate-only policy)", "",
          "_Listed regardless of verdict: a cheap model annotates a security row, "
          "it never discards one. A false discard is invisible; a false pass costs "
          "one premium-model look._", "",
          "| target | file | verdict | note |", "|--------|------|---------|------|"]
    for v in sec:
        L.append(f"| {tgt(v)} | `{v['file']}` | {v['verdict']['status']} "
                 f"| {esc(v['verdict']['evidence'], 220)} |")

    # Kept as its own section rather than merged into false-positives: "the lens
    # was right but the work already shipped" is the pipeline's most common
    # failure mode, and burying it hides how much of a sweep is stale.
    L += ["", f"## Already fixed before dispatch ({len(fixed)})", ""]
    for v in fixed:
        L.append(f"- {name(v)} ({v['lens']}): {esc(v['verdict']['evidence'], 300)}")

    L += ["", f"## Discarded as false-positive ({len(fps)})", "",
          "<details><summary>expand</summary>", ""]
    for v in fps:
        L.append(f"- {name(v)} ({v['lens']}): {esc(v['verdict']['evidence'], 200)}")
    L += ["", "</details>"]
    if uncl:
        L += ["", f"## Unclear ({len(uncl)}) - needs a premium look", ""]
        for v in uncl:
            L.append(f"- {name(v)} ({v['lens']}): {esc(v['verdict']['evidence'], 200)}")

    Path(args.md).write_text("\n".join(L) + "\n")
    print(f"{args.md}: {len(real)} real, {len(fixed)} already-fixed, "
          f"{len(fps)} false-positive, {len(uncl)} unclear")


if __name__ == "__main__":
    main()
