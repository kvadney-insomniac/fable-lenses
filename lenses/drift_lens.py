#!/usr/bin/env python3
"""Drift lens, find copy-pasted code that has DIVERGED.

This exists because a whole class of latent bugs turned out to share one shape:
a block duplicated across N sites where the copies silently drifted apart. A
guard added to two of four call sites. A parser taught about new cases in one
copy and not its siblings. A default corrected in one place.

Nothing fails when this happens, the copies simply disagree, and only under the
inputs the fix was about, which is exactly why it survives review and testing.
Churn x complexity surfaces these occasionally, by accident, because a
much-edited file tends to be a much-copied one. This lens looks for them on
purpose.

Method (code-grounded, no issue tracker, cannot go stale):
  1. Extract every function via stdlib `ast` (Python only; TS has no stdlib parser).
  2. NORMALIZE tokens: identifiers -> ID, literals -> LIT, keywords/operators kept.
     So two clones that differ only in variable/column names become IDENTICAL,
     and a real logic difference (a missing guard, +/- flip, an extra branch)
     is what shows up as the diff.
  3. Near-duplicate detection with a shingle prefilter (avoids O(n^2)).
  4. Flag pairs whose normalized similarity is HIGH but < 1.0, that band is
     drift: same logic, one copy changed. (== 1.0 = exact clone modulo names:
     dedup debt, reported separately.)

A drifted group is the highest-value finding: same code that MUST stay in sync
but didn't. Each is a verify-then-fix candidate (diff the members, decide which
behavior is correct, unify behind one helper + a golden master).

Usage: python3 drift_lens.py <repo_dir> [--md REPORT-drift.md] [--json data-drift.json]

Prints the report to stdout by default; --md writes it to a path instead.
"""
from __future__ import annotations

import argparse
import ast
import difflib
import io
import json
import keyword
import subprocess
import sys
import tokenize
from collections import defaultdict
from pathlib import Path

MIN_TOKENS = 40        # skip trivial functions (getters, one-liners)
SHINGLE_K = 5          # token n-gram size for the prefilter
MAX_SHINGLE_FANOUT = 25  # ignore boilerplate shingles shared by > this many funcs
MIN_SHARED_SHINGLES = 8  # candidate pair must share at least this many shingles
DRIFT_LO = 0.80        # flag pairs with normalized similarity in [LO, 1.0)
DENY = ("alembic/versions/", "/migrations/", "__pycache__/", "/tests/",
        "test_", "_test.", "conftest.py", "/node_modules/")


def tracked_py(repo: str) -> list[str]:
    out = subprocess.run(["git", "-C", repo, "ls-files", "*.py"],
                         capture_output=True, text=True).stdout.splitlines()
    return [f for f in out if not any(d in f for d in DENY)]


def normalize_tokens(segment: str) -> list[str]:
    """Identifiers->ID, literals->LIT, keep keywords/operators. Names erased so
    rename-only clones collapse and real logic diffs remain visible."""
    toks: list[str] = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(segment).readline):
            tt = tok.type
            if tt in (tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE,
                      tokenize.INDENT, tokenize.DEDENT, tokenize.ENCODING,
                      tokenize.ENDMARKER):
                continue
            if tt in (tokenize.STRING, tokenize.NUMBER):
                toks.append("LIT")
            elif tt == tokenize.NAME:
                toks.append(tok.string if keyword.iskeyword(tok.string) else "ID")
            else:
                toks.append(tok.string)
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return []
    return toks


def collect_functions(repo: str) -> list[dict]:
    funcs: list[dict] = []
    for rel in tracked_py(repo):
        try:
            src = (Path(repo) / rel).read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(src)
        except (OSError, SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            seg = ast.get_source_segment(src, node)
            if not seg:
                continue
            toks = normalize_tokens(seg)
            if len(toks) < MIN_TOKENS:
                continue
            funcs.append({
                "file": rel, "name": node.name, "line": node.lineno,
                "end": getattr(node, "end_lineno", None) or node.lineno,
                "toks": toks, "loc": seg.count("\n") + 1,
            })
    return funcs


def candidate_pairs(funcs: list[dict]) -> set[tuple[int, int]]:
    """Pairs sharing >= MIN_SHARED_SHINGLES k-gram shingles (boilerplate filtered)."""
    index: dict[int, list[int]] = defaultdict(list)
    shingles: list[set[int]] = []
    for i, f in enumerate(funcs):
        t = f["toks"]
        sh = {hash(tuple(t[j:j + SHINGLE_K])) for j in range(len(t) - SHINGLE_K + 1)}
        shingles.append(sh)
        for s in sh:
            index[s].append(i)
    shared: dict[tuple[int, int], int] = defaultdict(int)
    for s, members in index.items():
        if len(members) < 2 or len(members) > MAX_SHINGLE_FANOUT:
            continue  # unique or boilerplate, no signal
        for a in range(len(members)):
            for b in range(a + 1, len(members)):
                shared[(members[a], members[b])] += 1
    return {p for p, n in shared.items() if n >= MIN_SHARED_SHINGLES}


def nested(a: dict, b: dict) -> bool:
    """True when one function's line range contains the other's.

    A builder and the closure it returns are not two drifted copies of one
    block: a `_build_handler` reported against the `handler` it defines inside
    itself is an artifact of the outer span including the inner one, and it
    looks exactly like a real finding in the report. Decorators, closures,
    factory functions and nested helpers all produce it, and there is nothing
    to reconcile because there is only one piece of code.
    """
    if a["file"] != b["file"]:
        return False
    return ((a["line"] <= b["line"] and b["end"] <= a["end"])
            or (b["line"] <= a["line"] and a["end"] <= b["end"]))


def find_class(parent: dict[int, int], x: int) -> int:
    while parent.get(x, x) != x:
        parent[x] = parent.get(parent[x], parent[x])
        x = parent[x]
    return x


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("repo")
    ap.add_argument("--md")
    ap.add_argument("--json")
    args = ap.parse_args()

    funcs = collect_functions(args.repo)
    pairs = candidate_pairs(funcs)

    flagged: list[tuple[float, int, int]] = []
    exact: list[tuple[int, int]] = []
    for a, b in pairs:
        if funcs[a]["name"] == funcs[b]["name"] and funcs[a]["file"] == funcs[b]["file"]:
            continue
        if nested(funcs[a], funcs[b]):
            continue  # an outer function and the one it defines inside itself
        ratio = difflib.SequenceMatcher(None, funcs[a]["toks"], funcs[b]["toks"]).ratio()
        if ratio >= 1.0:
            exact.append((a, b))
        elif ratio >= DRIFT_LO:
            flagged.append((ratio, a, b))

    # Cluster flagged pairs into drift groups (union-find).
    parent: dict[int, int] = {}
    for _, a, b in flagged:
        parent.setdefault(a, a); parent.setdefault(b, b)
        parent[find_class(parent, a)] = find_class(parent, b)
    groups: dict[int, set[int]] = defaultdict(set)
    for node in list(parent):
        groups[find_class(parent, node)].add(node)
    best_ratio: dict[int, float] = defaultdict(float)
    for r, a, b in flagged:
        root = find_class(parent, a)
        best_ratio[root] = max(best_ratio[root], r)

    ranked = sorted(
        groups.values(),
        key=lambda g: (max(funcs[i]["loc"] for i in g) * len(g)),
        reverse=True,
    )

    out = [f"# Drift lens, `{args.repo}`", "",
           f"_{len(funcs)} functions scanned · **{len(ranked)} drifted groups** "
           f"(similar but not identical) · {len(exact)} exact clones (dedup debt)._",
           "",
           "Each group = the same normalized logic copied to N sites where the "
           "copies **diverged**. Diff the members, decide the correct behavior, "
           "unify behind one helper + a golden master.", "",
           "> **Nesting is excluded.** A pair where one function's line range "
           "contains the other's is skipped: a builder and the closure it "
           "returns, a decorator and its wrapper, a nested helper. The outer "
           "span includes the inner one, so they always look like near-identical "
           "copies, and there is nothing to reconcile because there is only one "
           "piece of code. Copies in the same file at disjoint line ranges are "
           "still reported.", ""]
    for gi, g in enumerate(ranked[:25], 1):
        members = sorted(g, key=lambda i: funcs[i]["file"])
        root = find_class(parent, members[0])
        out.append(f"### {gi}. {len(g)} drifted copies · max sim "
                   f"{best_ratio[root]:.0%} · ~{max(funcs[i]['loc'] for i in g)} LOC")
        for i in members:
            out.append(f"- `{funcs[i]['file']}:{funcs[i]['line']}` "
                       f"**{funcs[i]['name']}**(), {funcs[i]['loc']} LOC")
        out.append("")
    md = "\n".join(out) + "\n"

    if args.md:
        Path(args.md).write_text(md, encoding="utf-8")
        print(f"wrote {args.md}")
    else:
        print(md, end="")
    if args.json:
        Path(args.json).write_text(json.dumps(
            [[{"file": funcs[i]["file"], "name": funcs[i]["name"],
               "line": funcs[i]["line"]} for i in sorted(g)] for g in ranked],
            indent=2), encoding="utf-8")
        print(f"wrote {args.json}")
    print(f"[drift_lens] {len(funcs)} functions, {len(ranked)} drifted groups, "
          f"{len(exact)} exact clones", file=sys.stderr)


if __name__ == "__main__":
    main()
