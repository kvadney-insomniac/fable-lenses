#!/usr/bin/env python3
"""Tier-0 -> Tier-1 bridge: assemble the cheap-model triage candidate list.

Reads every lens's ranked JSON output for each named target and emits
`candidates.json` -- a capped, deduplicated list of {lens, target, file, detail}
rows for the triage workflow (`triage_workflow.js`) to verify against a git ref.

A "target" is just a name you gave one scored codebase: whatever you passed as
`<target>` when you wrote the lens outputs. One repo, several packages of a
monorepo, a service per name -- the count is up to you, and the per-lens files
are looked up by that name:

    data-<target>.json            score_targets.py   (tech debt)
    data-security-<target>.json   security_lens.py
    data-deadcode-<target>.json   deadcode_lens.py
    data-drift-<target>.json      drift_lens.py
    data-v2-<target>.json         opportunity_v2.py --json

Any of those that don't exist are simply skipped, so a target that was only
swept by two lenses contributes two lenses' worth of candidates.

Caps are per-lens recall->precision handoff sizes, not quality judgements:
  techdebt   8/target   (top score, minus anything on the skip list)
  security   8/target   (ANNOTATE-ONLY downstream -- triage may never discard these)
  deadcode   12/target  (whole files first, then largest symbols)
  drift      10/target  (largest diverged clone groups)
  v2-risers  8/target   (largest rank deltas from the evidence lens)

Deterministic, read-only, zero model tokens -- same contract as the lenses.

Usage:
    python3 triage_candidates.py <target> [<target> ...] [--data-dir DIR] \\
        [--out candidates.json] [--skip PATH ...] [--skip-file LIST.txt] \\
        [--cap-techdebt N] [--cap-security N] [--cap-deadcode N] \\
        [--cap-drift N] [--cap-risers N]
"""

import argparse
import json
import sys
from pathlib import Path


def load(data_dir, name):
    p = Path(data_dir) / name
    return json.loads(p.read_text()) if p.exists() else None


def techdebt(data_dir, target, skip, cap):
    rows = load(data_dir, f"data-{target}.json") or []
    out = []
    for r in sorted(rows, key=lambda r: (-r["score"], -r["churn_raw"])):
        if r["file"] in skip:
            continue
        out.append({
            "lens": "techdebt", "target": target, "file": r["file"],
            "detail": f"score {r['score']} (churn bucket {r['impact']}, "
                      f"complexity bucket {r['opportunity']}; cc={r['complexity']['cc']}, "
                      f"loc={r['complexity']['loc']}, depth={r['complexity']['depth']})",
        })
        if len(out) >= cap:
            break
    return out


def security(data_dir, target, skip, cap):
    # The skip list applies here too -- that is a HUMAN deciding a known finding
    # doesn't need re-verifying, which is a different thing from the annotate-only
    # policy downstream. That policy binds the cheap MODEL: once a security row
    # is in this list, no verdict may drop it from the report, because a wrong
    # discard on an auth/tenancy issue is invisible while a wrong keep costs one
    # premium-model look. Skipping is on the record; discarding isn't.
    rows = load(data_dir, f"data-security-{target}.json") or []
    out = []
    for r in sorted(rows, key=lambda r: (-r["score"], -r["reach_raw"])):
        if r["file"] in skip:
            continue
        pats = ", ".join(f"{k}x{v}" for k, v in r.get("patterns", {}).items()) or "none"
        gaps = ", ".join(r.get("auth_gaps", [])) or "none"
        out.append({
            "lens": "security", "target": target, "file": r["file"],
            "detail": f"reach {r['reach']} (imported_by {r['imported_by']}), "
                      f"vuln {r['vuln']}; patterns: {pats}; auth_gaps: {gaps}",
        })
        if len(out) >= cap:
            break
    return out


def deadcode(data_dir, target, skip, cap):
    d = load(data_dir, f"data-deadcode-{target}.json") or {}
    files, symbols = d.get("files", []), d.get("symbols", [])
    out = []
    # Whole-file candidates first: "no module imports this" is a far more
    # reliable signal than "this name appears nowhere else", so it gets the
    # budget before per-symbol guesses do.
    for r in files:
        if r["file"] in skip:
            continue
        out.append({
            "lens": "deadcode", "target": target, "file": r["file"],
            "detail": f"whole file unreferenced? confidence={r['confidence']}, "
                      f"loc={r['loc']}, fp_tags={r['fp_tags'] or 'none'}",
        })
    for r in sorted(symbols, key=lambda r: -r["score"]):
        if len(out) >= cap:
            break
        if r["file"] in skip:
            continue
        out.append({
            "lens": "deadcode", "target": target, "file": r["file"],
            "symbol": r["symbol"],
            "detail": f"symbol `{r['symbol']}` unreferenced? confidence={r['confidence']}, "
                      f"loc={r['loc']}, fp_tags={r['fp_tags'] or 'none'}",
        })
    return out[:cap]


def drift(data_dir, target, skip, cap):
    groups = load(data_dir, f"data-drift-{target}.json") or []
    out = []
    for g in groups:
        if len(out) >= cap:
            break
        if any(m["file"] in skip for m in g):
            continue
        members = "; ".join(f"{m['file']}::{m['name']} (line {m['line']})" for m in g)
        out.append({
            "lens": "drift", "target": target, "file": g[0]["file"],
            "group": [{"file": m["file"], "name": m["name"], "line": m["line"]} for m in g],
            "detail": f"diverged clone group: {members}",
        })
    return out


def v2_risers(data_dir, target, skip, cap):
    # opportunity_v2.py --json writes these already sorted by rank delta, so the
    # cap is a straight head() -- the biggest movers are the whole point.
    rows = load(data_dir, f"data-v2-{target}.json") or []
    out = []
    for r in rows:
        if len(out) >= cap:
            break
        if r["file"] in skip:
            continue
        out.append({
            "lens": "v2-riser", "target": target, "file": r["file"],
            "detail": f"rank delta +{r['delta_rank']} from evidence: "
                      f"{r['issues']} open issue(s), {r['audit']} audit finding(s), "
                      f"{r['incidents']} incident note(s)"
                      + ("" if r.get("basename_unique", True)
                         else "; basename NOT unique - low confidence"),
        })
    return out


def read_skip(paths, skip_file):
    """Files to leave out of triage entirely.

    The point is budget, not correctness: anything already dispatched to the
    premium model, already fixed, or knowingly accepted as-is will burn a tier-1
    agent to tell you what you already know. Keep the list in version control
    next to the lens outputs and pass it with --skip-file; one path per line,
    `#` comments allowed.
    """
    skip = set(paths or [])
    if skip_file:
        p = Path(skip_file)
        if not p.exists():
            print(f"  ! skip file not found, ignoring: {skip_file}")
        else:
            for line in p.read_text().splitlines():
                line = line.split("#", 1)[0].strip()
                if line:
                    skip.add(line)
    return skip


def main():
    ap = argparse.ArgumentParser(
        description="Assemble the tier-1 triage candidate list from lens JSON outputs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("targets", nargs="+",
                    help="target names whose lens outputs to read (any number)")
    ap.add_argument("--data-dir", default=".",
                    help="directory holding the lenses' data-*.json (default: .)")
    ap.add_argument("--out", default="candidates.json", help="where to write the list")
    ap.add_argument("--skip", action="append", default=[], metavar="PATH",
                    help="repo-relative file to exclude (already dispatched / "
                         "already fixed / knowingly accepted). Repeatable.")
    ap.add_argument("--skip-file", metavar="FILE",
                    help="file of paths to exclude, one per line, `#` comments ok")
    ap.add_argument("--cap-techdebt", type=int, default=8)
    ap.add_argument("--cap-security", type=int, default=8,
                    help="annotate-only downstream: triage may never discard these")
    ap.add_argument("--cap-deadcode", type=int, default=12)
    ap.add_argument("--cap-drift", type=int, default=10)
    ap.add_argument("--cap-risers", type=int, default=8)
    args = ap.parse_args()

    skip = read_skip(args.skip, args.skip_file)
    cands = []
    for target in args.targets:
        cands += techdebt(args.data_dir, target, skip, args.cap_techdebt)
        cands += security(args.data_dir, target, skip, args.cap_security)
        cands += deadcode(args.data_dir, target, skip, args.cap_deadcode)
        cands += drift(args.data_dir, target, skip, args.cap_drift)
        cands += v2_risers(args.data_dir, target, skip, args.cap_risers)

    # dedupe (the same file can surface via several lenses -- keep all lenses'
    # rows, because each asks a different question about it; only drop exact
    # lens+target+file+symbol duplicates)
    seen, out = set(), []
    for c in cands:
        key = (c["lens"], c["target"], c["file"], c.get("symbol", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(c)

    dst = Path(args.out)
    dst.write_text(json.dumps(out, indent=1))
    by_lens = {}
    for c in out:
        by_lens[c["lens"]] = by_lens.get(c["lens"], 0) + 1
    print(f"{len(out)} candidates -> {dst}")
    for k, v in sorted(by_lens.items()):
        print(f"  {k:10} {v}")
    if not out:
        print("  (no lens outputs found - check --data-dir and the target names)")


if __name__ == "__main__":
    sys.exit(main())
