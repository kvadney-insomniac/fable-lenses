#!/usr/bin/env python3
"""Opportunity v2: extend the OPPORTUNITY axis with real-world evidence of pain.

The generic machine scores opportunity = code complexity. That's a proxy for
"how much latent debt." But a repo usually has *direct* signals of where pain
actually lives, which complexity can't see:

  (a) OPEN GitHub issues that name the file  , users/devs are hitting it now
  (b) code-review / audit findings on it     , a reviewer already flagged it
  (c) incident notes that mention it         , it has burned you in production

v2 opportunity = complexity-bucket  (+)  evidence (a + 2b + 3c, capped & bucketed).
The IMPACT axis (git churn) is unchanged. We re-bucket the new opportunity,
re-multiply, and report **old_rank -> new_rank sorted by biggest positive delta**
-- i.e. the files generic churn x complexity UNDER-ranked that real-world
evidence flags as hot. That delta list is the whole point of the lens; the
absolute ranking it produces is less interesting than what moved.

Why start from the churn-surviving set (impact >= 3), not the both->=4 target
list: a file can only *rise* if its evidence outweighs a LOW complexity score.
Files already in the top quadrant have nowhere to climb -- the movers are the
mid-complexity files that issues/incidents light up.

Matching (the traps):
  * issues + evidence notes -> basename WITH extension, word-boundary
    (`\\bfoo\\.py\\b`). Without the extension, `main`/`page`/`chat` match
    English prose and every sibling file.
  * NON-UNIQUE basenames (dozens of `page.tsx`/`route.ts`) are flagged
    low-confidence and their issue/evidence hits are DROPPED -- attributing a
    "page.tsx" mention to every page in the repo is noise, not signal.
  * audit findings -> full path match (a findings log carries `src/a/b.py`).
  * count issues/blocks CONTAINING the name, not raw occurrences: one issue
    that names a file six times is one issue.

Every evidence source is OPTIONAL. With none of them supplied this degrades to
"generic ranking, nothing moved" and says so -- it never hard-fails.

Usage:
    python3 opportunity_v2.py <repo_path> --data data-<target>.json \\
        [--gh-repo OWNER/NAME] [--ref HEAD] [--evidence NOTES.md ...] \\
        [--audit findings.jsonl] [--label NAME] \\
        [--md TARGETS-v2.md] [--json data-v2-<target>.json]

`--data` is the ranked JSON that score_targets.py writes for this repo. The
GitHub repo is inferred from the `origin` remote when `--gh-repo` is omitted;
issue evidence is skipped when neither is available (or `gh` is not installed).
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections import Counter
from datetime import datetime
from functools import lru_cache
from pathlib import Path

# Only UNRESOLVED signal counts as current opportunity. An evidence note or
# audit finding for already-fixed work double-counts closed effort. This is the
# lens's recorded failure mode: a service once ranked #1 here on three audit
# findings that had all been fixed in the very merge that introduced them.
_RESOLVED_RE = re.compile(r"\b(resolved|closed)\b", re.IGNORECASE)

# A top-level list item or an ATX heading starts a new evidence block; anything
# else continues the current one until a blank line.
_LIST_ITEM_RE = re.compile(r"^(?:[-*+]|\d+[.)])\s+")


def _parse_iso(dt: str):
    try:
        return datetime.fromisoformat(dt.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _run(cmd: list[str]) -> str | None:
    """Run a command, return stdout, or None if it failed / isn't installed.

    Every external tool here (git, gh) is optional evidence, never a hard
    dependency -- a missing binary or an unknown ref degrades the report, it
    does not end the run.
    """
    try:
        out = subprocess.run(cmd, capture_output=True, text=True)
    except (OSError, ValueError):
        return None
    return out.stdout if out.returncode == 0 else None


# ---------------------------------------------------------------- git helpers


@lru_cache(maxsize=None)
def _file_last_modified(repo: str, ref: str, relpath: str) -> str | None:
    """ISO date of the file's last commit on `ref`, or None."""
    if not repo:
        return None
    out = _run(["git", "-C", repo, "log", "-1", "--format=%cI", ref, "--", relpath])
    return (out or "").strip() or None


_REMOTE_RE = re.compile(
    r"(?:github\.com[:/])([^/\s]+)/([^/\s]+?)(?:\.git)?$", re.IGNORECASE
)


def infer_gh_repo(repo_path: str) -> str | None:
    """`OWNER/NAME` from the repo's `origin` remote, or None if it isn't GitHub.

    Inference only -- pass `--gh-repo` when the remote is a mirror, a fork, or
    the issues live somewhere other than where the code does.
    """
    url = (_run(["git", "-C", repo_path, "remote", "get-url", "origin"]) or "").strip()
    m = _REMOTE_RE.search(url)
    return f"{m.group(1)}/{m.group(2)}" if m else None


# ------------------------------------------------------------ issue evidence

# A closing keyword may be followed by SEVERAL issues: "closes #11 #12 #13 #14".
# Capture the whole run of #N tokens after the keyword, then pull each one.
_CLOSE_KW_RE = re.compile(
    r"\b(?:closes?|closed|fix(?:es|ed)?|resolves?|resolved)\b((?:[\s,]+(?:and\s+)?#\d+)+)",
    re.IGNORECASE,
)
_ISSUE_NUM_RE = re.compile(r"#(\d+)")


def merged_pr_closed_issues(gh_repo: str) -> set[int]:
    """Issue numbers a MERGED PR already implemented (`closes #N` in its body).

    An issue stays OPEN after its closing PR merges to a non-default branch, so
    'open' != 'undone'. These issues shipped already -- counting them as current
    opportunity is the same stale-signal bug as counting historical audit
    findings, and it fires often enough to be worth this extra API call.
    """
    out = _run(["gh", "pr", "list", "-R", gh_repo, "--state", "merged",
                "--limit", "400", "--json", "body"])
    closed: set[int] = set()
    if out is None:
        return closed
    try:
        for pr in json.loads(out or "[]"):
            for m in _CLOSE_KW_RE.finditer(pr.get("body") or ""):
                for num in _ISSUE_NUM_RE.findall(m.group(1)):
                    closed.add(int(num))
    except json.JSONDecodeError:
        pass
    return closed


def fetch_issue_bodies(gh_repo: str | None) -> list[str]:
    """[title+body] blobs for open issues NOT already shipped by a merged PR."""
    if not gh_repo:
        print("  (no GitHub repo configured or inferred - skipping issue evidence)")
        return []
    shipped = merged_pr_closed_issues(gh_repo)
    out = _run(["gh", "issue", "list", "-R", gh_repo, "--state", "open",
                "--limit", "100", "--json", "number,title,body"])
    if out is None:
        print(f"  ! gh unavailable or failed for {gh_repo} - skipping issue evidence")
        return []
    try:
        data = json.loads(out or "[]")
    except json.JSONDecodeError:
        return []
    kept = [d for d in data if d.get("number") not in shipped]
    dropped = len(data) - len(kept)
    if dropped:
        print(f"  ({gh_repo}: dropped {dropped} open issues already closed by a merged PR)")
    return [f"{d.get('title','')}\n{d.get('body','') or ''}" for d in kept]


# --------------------------------------------------------- incident evidence


def _split_blocks(text: str) -> list[str]:
    """Split an evidence file into blocks -- one incident / note / topic each.

    Blocking matters because we count *how many notes mention a file*, not how
    many times the file is mentioned; one long postmortem that names a file
    nine times is one incident.

    A new block starts at a top-level list item (`- ...`), at an ATX heading
    (`## ...`), or after a blank line. Indented continuation lines (including
    nested list items) stay with the block they follow, so a bullet with a
    sub-list is one note.
    """
    blocks: list[str] = []
    cur: list[str] = []

    def flush() -> None:
        if any(ln.strip() for ln in cur):
            blocks.append("\n".join(cur).strip())
        cur.clear()

    for ln in text.splitlines():
        if not ln.strip():
            flush()
        elif ln.startswith("#") or _LIST_ITEM_RE.match(ln):
            flush()
            cur.append(ln)
        else:
            cur.append(ln)
    flush()
    return blocks


def evidence_blocks(paths: list[str]) -> list[str]:
    """Read the `--evidence` files into blocks, dropping resolved ones.

    An evidence file is any plain-text or Markdown file describing incidents,
    postmortems, recurring-bug topics, or review notes -- an incident log, a
    running notes file, an exported ticket dump. There is no required schema:
    the lens only needs prose that happens to name files.

    A block is dropped when its FIRST line (its title) reads as resolved or
    closed -- a closed incident is past effort, not current opportunity. The
    match is deliberately confined to the title: testing the whole body would
    drop any note that merely uses the word "fixed" in passing.
    """
    out: list[str] = []
    for p in paths or []:
        f = Path(p)
        if not f.exists():
            print(f"  ! evidence file not found, skipping: {p}")
            continue
        blocks = _split_blocks(f.read_text(encoding="utf-8", errors="ignore"))
        live = [b for b in blocks if not _RESOLVED_RE.search(b.splitlines()[0])]
        if len(blocks) != len(live):
            print(f"  ({f.name}: dropped {len(blocks) - len(live)} blocks marked resolved/closed)")
        out += live
    return out


# ------------------------------------------------------------ audit evidence


def audit_file_counts(audit_path: str | None, repo: str, ref: str) -> Counter:
    """Full-path -> number of audit findings that likely STILL STAND.

    `--audit` takes a JSONL file of code-review findings, one object per line,
    of which only two fields are read:

        {"file": "src/module.py", "ts": "2026-01-01T12:00:00Z"}

    (`ts` optional; any other fields are ignored, so most review-tool exports
    can be fed in as-is.)

    Such logs rarely have a resolution field, so we use the best available
    proxy: if the file was modified AFTER the finding was logged, the finding
    was probably addressed in that change. Those are dropped; only findings on
    files unchanged-since-flagged count as current opportunity. Without this
    filter the lens reliably promotes files whose findings were all fixed long
    ago -- the single biggest source of false top-ranks it has produced.
    """
    counts: Counter = Counter()
    if not audit_path:
        return counts
    p = Path(audit_path)
    if not p.exists():
        print(f"  ! audit file not found, skipping: {audit_path}")
        return counts
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        f = d.get("file")
        if not f:
            continue
        finding_ts = _parse_iso(d.get("ts", ""))
        last_mod = _parse_iso(_file_last_modified(repo, ref, f) or "")
        if finding_ts and last_mod and last_mod > finding_ts:
            continue  # file changed since flagged -> likely addressed
        counts[f] += 1
    return counts


# ------------------------------------------------------------------- scoring


def evidence_for_rows(rows: list[dict], issue_blobs: list[str],
                      note_blobs: list[str], audit: Counter) -> dict:
    # Detect non-unique basenames within this repo's scored files.
    basename_count: Counter = Counter(Path(r["file"]).name for r in rows)

    ev: dict[str, dict] = {}
    for r in rows:
        path = r["file"]
        base = Path(path).name
        unique = basename_count[base] == 1
        # word-boundary, extension-included basename match. The lookbehind must
        # also reject a preceding `.` so a suffix-collision like `config.ts`
        # doesn't match inside `next.config.ts` / `vitest.config.ts` (basenames
        # differ -- both look "unique" -- but the string is a substring).
        rx = re.compile(rf"(?<![\w/.]){re.escape(base)}(?![\w])")

        if unique:
            n_issues = sum(1 for b in issue_blobs if rx.search(b))
            n_notes = sum(1 for b in note_blobs if rx.search(b))
        else:
            # non-unique basename: drop issue/note evidence (it would be noise).
            n_issues = 0
            n_notes = 0
        n_audit = audit.get(path, 0)

        ev[path] = {
            "issues": n_issues,
            "audit": n_audit,
            "incidents": n_notes,
            "basename_unique": unique,
            # weighted: a production incident >> a reviewer flag >> an open issue
            "evidence_raw": n_issues + 2 * n_audit + 3 * n_notes,
        }
    return ev


def ev_score_to_bonus(raw: float) -> int:
    """Absolute (not quintile) evidence -> opportunity bonus.

    Evidence is SPARSE -- most files have none -- so a quintile bucketer
    collapses: any nonzero value would map to bucket 5. An absolute scale keeps
    the bump proportional to the real signal, so one stray issue mention is a +1
    nudge rather than an instant max-out, and only heavy evidence (several
    issues, a production incident, repeat audit flags) reaches the top.
    """
    if raw <= 0:
        return 0
    if raw <= 1:
        return 1   # a single passing mention
    if raw <= 2:
        return 2
    if raw <= 4:
        return 3   # multiple issues OR a reviewer flag
    return 4       # production incident / heavy convergent evidence


def rerank(rows: list[dict], issue_blobs: list[str], note_blobs: list[str],
           audit: Counter) -> tuple[list[dict], dict]:
    """Return (movers sorted by delta-rank, summary). Re-rank within impact>=3."""
    # Original ranking is rows as-loaded (already sorted by score desc).
    base = [r for r in rows if r["impact"] >= 3]
    for i, r in enumerate(base, 1):
        r["_old_rank"] = i
        r["_old_score"] = r["score"]

    ev = evidence_for_rows(base, issue_blobs, note_blobs, audit)

    for r in base:
        e = ev[r["file"]]
        bonus = ev_score_to_bonus(e["evidence_raw"])
        # Additive on top of complexity (capped at 5). This lets a low-complexity
        # but heavily-flagged file climb, without slamming every 1-issue file to 5.
        new_opp = min(5, r["opportunity"] + bonus)
        r["_new_opportunity"] = new_opp
        r["_ev_bonus"] = bonus
        r["_new_score"] = r["impact"] * new_opp
        r["_ev"] = e

    new_order = sorted(
        base, key=lambda r: (r["_new_score"], r["_ev"]["evidence_raw"], r["churn_raw"]),
        reverse=True,
    )
    for i, r in enumerate(new_order, 1):
        r["_new_rank"] = i

    movers = [r for r in new_order
              if r["_old_rank"] - r["_new_rank"] > 0 and r["_ev"]["evidence_raw"] > 0]
    movers.sort(key=lambda r: (r["_old_rank"] - r["_new_rank"], r["_ev"]["evidence_raw"]),
                reverse=True)
    return movers, {"base_n": len(base), "new_order": new_order}


# ------------------------------------------------------------------ rendering


def render(label: str, movers: list[dict], info: dict, top: int) -> list[str]:
    out = [
        f"## `{label}` - biggest opportunity shifts (evidence vs generic complexity)",
        "",
        f"_{info['base_n']} churn-surviving files (impact >= 3) re-ranked. "
        f"**{len(movers)}** rose once issue / audit / incident evidence folded "
        "into the opportunity axis._",
        "",
        "`v2 opportunity = min(5, complexity-bucket + evidence-bonus)`. "
        "`evidence_raw = issues + 2*audit + 3*incidents`; bonus = "
        "0/1/2/3/4 for raw 0 / <=1 / <=2 / <=4 / >4 (absolute scale - evidence is "
        "too sparse for a quintile). Impact (churn) unchanged.",
        "",
        "| drank | old->new | file | iss | aud | inc | +opp | old IxO | new IxO |",
        "|------:|:--------:|------|----:|----:|----:|:----:|:-------:|:-------:|",
    ]
    if not movers:
        out += ["", "_No file rose: no evidence source matched a scored file. "
                    "With no `--evidence` / `--audit` / GitHub issues this is the "
                    "expected result - the ranking is the generic one._", ""]
        return out
    for r in movers[:top]:
        e = r["_ev"]
        delta = r["_old_rank"] - r["_new_rank"]
        flag = "" if e["basename_unique"] else " (!)"
        out.append(
            f"| **+{delta}** | {r['_old_rank']}->{r['_new_rank']} | "
            f"`{r['file']}`{flag} | {e['issues']} | {e['audit']} | {e['incidents']} | "
            f"+{r['_ev_bonus']} | "
            f"{r['impact']}x{r['opportunity']} | {r['impact']}x{r['_new_opportunity']} |"
        )
    out.append("")
    return out


def as_json_rows(label: str, movers: list[dict]) -> list[dict]:
    """Flat rows for downstream consumers (triage_candidates.py reads these)."""
    return [
        {
            "target": label,
            "file": r["file"],
            "delta_rank": r["_old_rank"] - r["_new_rank"],
            "old_rank": r["_old_rank"],
            "new_rank": r["_new_rank"],
            "issues": r["_ev"]["issues"],
            "audit": r["_ev"]["audit"],
            "incidents": r["_ev"]["incidents"],
            "evidence_raw": r["_ev"]["evidence_raw"],
            "basename_unique": r["_ev"]["basename_unique"],
            "impact": r["impact"],
            "opportunity": r["opportunity"],
            "new_opportunity": r["_new_opportunity"],
            "old_score": r["_old_score"],
            "new_score": r["_new_score"],
        }
        for r in movers
    ]


def doc_header(label: str, sources: list[str]) -> list[str]:
    return [
        f"# Opportunity v2 (`{label}`) - opportunity axis extended with evidence",
        "",
        "Generic churn x complexity is blind to *which* hot files are actually "
        "hurting. This report folds repo-specific signals into the opportunity "
        "axis and shows which files **rise** as a result - the ones the generic "
        "machine under-ranked but open issues, review findings, and incident "
        "notes flag as hot.",
        "",
        "**Evidence sources used in this run** (all read-only, fetched once): "
        + (", ".join(sources) if sources else "_none supplied - generic ranking_"),
        "",
        "- **issues** - open GitHub issues (`gh issue list`, 100 most recent) whose "
        "title/body names the file (basename + extension, word-boundary), minus "
        "any already closed by a merged PR.",
        "- **audit** - rows in the `--audit` findings log referencing the file "
        "(full-path match), minus findings on files modified since they were logged.",
        "- **incidents** - blocks in the `--evidence` notes naming the file, minus "
        "blocks whose title is marked resolved/closed.",
        "",
        "> A `(!)` on a file means its **basename is not unique** in the repo "
        "(e.g. `page.tsx`, `route.ts`); issue/incident evidence is DROPPED for "
        "those (attributing a `page.tsx` mention to every page is noise) - only "
        "their audit (full-path) evidence counts. Treat with low confidence.",
        "",
        "> **This is a verified-POINTER, not a build-list.** Evidence signals lag "
        "the code: an issue stays open after its work ships, a review finding "
        "survives its own fix, a deleted file lingers in the churn snapshot. We "
        "filter the worst of it (resolved-note drop, mtime-stale audit drop, "
        "merged-PR-closed-issue drop, ghost-file drop), but a surviving 'open "
        "issue names this file' STILL does not prove the work is undone - epics "
        "stay open, commit-message closes are missed, partial work ships. "
        "**Verify every target against the current ref before building.** Runs of "
        "this lens have put already-shipped work in the top three more than once; "
        "that failure is what the tier-1 triage pass exists to catch. For "
        "reliable build targets, prefer the CODE-grounded lenses (tech-debt / "
        "coverage-gap / security / dead-code) - they measure the code directly "
        "and cannot go stale.",
        "",
    ]


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Opportunity v2 lens: re-rank a scored repo with issue / "
                    "audit / incident evidence and report what moved.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("repo", help="path to the git repo these files live in")
    ap.add_argument("--data", required=True,
                    help="ranked JSON from score_targets.py for this repo")
    ap.add_argument("--gh-repo", metavar="OWNER/NAME",
                    help="GitHub repo for issue evidence "
                         "(default: inferred from the repo's `origin` remote; "
                         "issue evidence is skipped if neither is available)")
    ap.add_argument("--ref", default="HEAD",
                    help="git ref to score against (default: HEAD)")
    ap.add_argument("--evidence", action="append", metavar="FILE", default=[],
                    help="plain-text or Markdown file of incident / postmortem / "
                         "review notes; blocks naming a file count as incident "
                         "evidence. Repeatable. Omitted = no incident evidence.")
    ap.add_argument("--audit", metavar="FILE",
                    help="JSONL findings log; each line needs a `file` field and "
                         "optionally a `ts` timestamp. Omitted = no audit evidence.")
    ap.add_argument("--label", help="name for this target in the report "
                                    "(default: the repo directory name)")
    ap.add_argument("--top", type=int, default=25, help="rows to render (default 25)")
    ap.add_argument("--md", default="TARGETS-v2.md", help="write the markdown report here")
    ap.add_argument("--json", dest="json_out",
                    help="write the movers as JSON here (triage_candidates.py input)")
    args = ap.parse_args()

    repo = str(Path(args.repo).expanduser())
    label = args.label or Path(repo).resolve().name
    data_path = Path(args.data)
    if not data_path.exists():
        raise SystemExit(f"{data_path} missing - run score_targets.py --json first")
    rows = json.loads(data_path.read_text())

    # Score only files that STILL EXIST on `ref`. A file deleted or consolidated
    # away lingers in the churn snapshot and would otherwise rank as a ghost
    # target -- the premium model then burns a look on a path that isn't there.
    tree = _run(["git", "-C", repo, "ls-tree", "-r", args.ref, "--name-only"])
    if tree is None:
        print(f"  (could not list {args.ref} in {repo} - skipping ghost-file filter)")
    else:
        existing = set(tree.splitlines())
        if existing:
            before = len(rows)
            rows = [r for r in rows if r["file"] in existing]
            if before != len(rows):
                print(f"  (dropped {before - len(rows)} ghost files not on {args.ref})")

    gh_repo = args.gh_repo or infer_gh_repo(repo)
    issue_blobs = fetch_issue_bodies(gh_repo)
    note_blobs = evidence_blocks(args.evidence)
    audit = audit_file_counts(args.audit, repo, args.ref)

    sources = []
    if issue_blobs:
        sources.append(f"{len(issue_blobs)} open issues (`{gh_repo}`)")
    if note_blobs:
        sources.append(f"{len(note_blobs)} evidence blocks")
    if audit:
        sources.append(f"{sum(audit.values())} audit findings")

    movers, info = rerank(rows, issue_blobs, note_blobs, audit)
    doc = doc_header(label, sources) + render(label, movers, info, args.top)

    Path(args.md).write_text("\n".join(doc), encoding="utf-8")
    print(f"wrote {args.md} ({len(movers)} risers from {info['base_n']} churn-surviving files)")
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(as_json_rows(label, movers), indent=2), encoding="utf-8")
        print(f"wrote {args.json_out}")


if __name__ == "__main__":
    main()
