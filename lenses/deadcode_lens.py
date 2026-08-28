#!/usr/bin/env python3
"""Lens 4: dead-code = unused-confidence x size.

Find code that is *defined but apparently never referenced elsewhere*, the
files and symbols where a premium model could delete or consolidate with high
leverage. Same machine shape: rank cheaply so the expensive model only reads
the plausible candidates.

    score = unused_confidence  x  size(LOC)

Two granularities, in order of trust:

  1. WHOLE-FILE, a module imported by no other file. Far more reliable than
     per-symbol; lead with it.
  2. PER-SYMBOL, a top-level def/class whose name appears nowhere else in the
     repo (grep across all source). Recall filter only.

  *** THIS IS A CANDIDATE LIST, NOT A DELETE LIST. ***

False POSITIVES (look dead, are not), dynamic dispatch hides the reference:
  - FastAPI/Flask route handlers (referenced only by their `@router.get`
    decorator, never by name)
  - Functions wired into a registry rather than called, an LLM tool decorated
    with `@tool` and listed in a tools array, a plugin registered by entry point
  - Pydantic / SQLAlchemy models (instantiated reflectively / by name)
  - Next.js file-routing entrypoints, `page.tsx` / `layout.tsx` / `route.ts`
    are referenced by *nothing* in code; the framework mounts them by path.
  - Scheduler jobs, CLI entrypoints, `__all__` exports.
These classes are auto-tagged in the report so they can be discounted.

False NEGATIVES (are dead, look alive), per-symbol grep skews toward UNIQUE
names. Common names (`get`, `run`, `process`, `handler`) match somewhere by
coincidence and get filtered out, so the symbol list UNDER-reports. Safer
direction, but state it.

WHICH DIRECTORIES GET SCANNED
    ``--src-root`` (repeatable, or comma-separated) names the directories that
    hold the code being *judged*, relative to the repo root. When omitted the
    lens auto-detects the common layouts (``src/``, ``app/``, ``lib/``) and
    falls back to the whole repo if it finds none. Note that this only narrows
    the CANDIDATE set, the reference corpus that decides whether something is
    referenced is always every tracked source file in the repo (see below).

Usage:
    python3 deadcode_lens.py <repo_path> [--src-root src] [--top 40]
        [--md out.md] [--json out.json]
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from collections import Counter
from pathlib import Path

from score_targets import DENY, denied, git

PY_EXT = {".py"}
TS_EXT = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}

# Directory names tried, in order, when --src-root is not given. Deliberately
# duplicated across the lenses rather than shared: each lens is meant to run as
# a standalone script, and the resolver is small enough that the duplication is
# cheaper than the coupling.
SRC_ROOT_CANDIDATES = ("src", "app", "lib")

# Files the framework mounts by path / name, not by import, never "dead".
ENTRYPOINT_BASENAMES = {
    "main.py", "__init__.py", "conftest.py", "scheduler.py", "config.py",
    "page.tsx", "layout.tsx", "route.ts", "loading.tsx", "error.tsx",
    "not-found.tsx", "template.tsx", "middleware.ts", "next.config.js",
    "page.jsx", "layout.jsx",
}


def resolve_src_roots(repo_path: Path, requested: list[str] | None) -> tuple[str, ...]:
    """Return the path prefixes to scan, e.g. ``("src/",)`` or ``("",)`` for all.

    An empty string means "the repo root", it works because every prefix test
    is ``path.startswith(root)`` and every path starts with "". Falling back to
    the whole repo rather than guessing a layout matters here: a wrong guess
    produces an empty candidate list, which reads as "no dead code" instead of
    "you pointed me at nothing".
    """
    roots: list[str] = []
    for chunk in requested or []:
        for r in chunk.split(","):
            r = r.strip()
            if not r:
                continue
            if r in (".", "./", "/"):
                roots.append("")  # explicit "scan everything"
            else:
                roots.append(r.strip("/") + "/")
    if roots:
        return tuple(dict.fromkeys(roots))

    found = tuple(f"{c}/" for c in SRC_ROOT_CANDIDATES if (repo_path / c).is_dir())
    return found or ("",)


def is_entrypoint(rel: str) -> bool:
    base = Path(rel).name
    if base in ENTRYPOINT_BASENAMES:
        return True
    # Next.js app-router files, wherever the app directory happens to live
    if re.match(r"(page|layout|route|loading|error|not-found|template)\.(tsx?|jsx?)$", base):
        return True
    return False


def fp_class(rel: str, src: str) -> list[str]:
    """Tag likely false-positive categories so the report can discount."""
    tags = []
    low = rel.lower()
    if is_entrypoint(rel):
        tags.append("framework-entrypoint")
    if "/routes/" in low or "/api/" in low:
        tags.append("fastapi-route")
    if "@tool" in src or "StructuredTool" in src:
        tags.append("llm-tool")
    if re.search(r"\bclass\s+\w+\((?:[\w\.]*Base|.*BaseModel|.*Base\b)", src) or "Mapped[" in src:
        tags.append("orm/pydantic-model")
    if "@router." in src or "@app." in src:
        tags.append("fastapi-route")
    if "scheduler.add_job" in src or "BackgroundScheduler" in src:
        tags.append("scheduler-job")
    if "__all__" in src:
        tags.append("explicit-export")
    # Code an SDK or framework looks up by name at run time, evaluators, plugin
    # entry points and the like. Nothing calls them in-tree, so a reference grep
    # reports them dead every time.
    if (
        "evaluator" in low
        or "@run_evaluator" in src
        or "RunEvaluator" in src
        or "entry_points" in src
    ):
        tags.append("dynamic-registry")
    return sorted(set(tags))


def loc_of(src: str, is_py: bool) -> int:
    n = 0
    for ln in src.splitlines():
        s = ln.strip()
        if not s:
            continue
        if is_py and s.startswith("#"):
            continue
        if not is_py and s.startswith(("//", "*", "/*")):
            continue
        n += 1
    return n


def top_level_symbols(src: str, is_py: bool) -> list[str]:
    """Top-level def/class (py) or exported function/const (ts)."""
    names: list[str] = []
    if is_py:
        try:
            tree = ast.parse(src)
        except (SyntaxError, ValueError):
            return names
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if not node.name.startswith("_"):  # private = intra-file by convention
                    names.append(node.name)
    else:
        for m in re.finditer(
            r"export\s+(?:async\s+)?(?:function|const|class)\s+(\w+)", src
        ):
            names.append(m.group(1))
    return names


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("repo")
    ap.add_argument(
        "--src-root",
        action="append",
        metavar="DIR",
        help="directory holding the code to judge, relative to the repo root; "
        "repeatable or comma-separated. Default: auto-detect src/, app/, lib/, "
        "else the whole repo. Does not narrow the reference corpus.",
    )
    ap.add_argument("--top", type=int, default=40)
    ap.add_argument("--md")
    ap.add_argument("--json")
    args = ap.parse_args()

    repo = args.repo
    repo_path = Path(repo)
    src_roots = resolve_src_roots(repo_path, args.src_root)

    ls = git(["ls-files"], repo).splitlines()
    # CANDIDATE set = product code under the source roots, non-test.
    candidates = [
        f for f in ls
        if (Path(f).suffix in PY_EXT or Path(f).suffix in TS_EXT)
        and not denied(f)
        and any(f.startswith(r) for r in src_roots)
    ]
    # REFERENCE corpus = EVERY tracked source file repo-wide, tooling scripts,
    # migrations, e2e suites, benchmarks, AND tests. A product module that is
    # only imported from a script outside the source roots is NOT dead; scoping
    # the corpus to product code + tests was a real false-positive class, so the
    # asymmetry here is deliberate: narrow what we judge, widen what counts as a
    # reference.
    corpus_files = [
        f for f in ls
        if Path(f).suffix in PY_EXT or Path(f).suffix in TS_EXT
    ]

    # Read candidate files (also need their text for symbol extraction / loc).
    contents: dict[str, str] = {}
    for f in candidates:
        try:
            contents[f] = (repo_path / f).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            contents[f] = ""

    # Read the full reference corpus once.
    corpus_blobs: list[str] = []
    for f in corpus_files:
        try:
            corpus_blobs.append((repo_path / f).read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            pass
    all_src = "\n".join(corpus_blobs)

    # ---- ONE-PASS indexes (avoid O(symbols × corpus) rescans) ----
    # 1. Global identifier frequency across the WHOLE repo. Catches Python
    #    import/usage and TS PascalCase symbol references.
    _IDENT = re.compile(r"[A-Za-z_]\w*")
    ident_freq: Counter[str] = Counter(_IDENT.findall(all_src))
    # 2. Import-specifier stems. TS module paths are often hyphenated (e.g.
    #    `date-picker`) so they never appear as a single ident token, collect
    #    their stems from import/from/require specifiers, parsed PER FILE so
    #    quote pairing stays sane (a global quote-regex drifts on apostrophes
    #    once the corpus is a few megabytes).
    spec_stems: Counter[str] = Counter()
    _SPEC = re.compile(r"""(?:import|from|require|dynamic)\b[^'"\n]*['"]([^'"]+)['"]""")
    for blob in corpus_blobs:
        for spec in _SPEC.findall(blob):
            spec_stems[Path(spec).stem] += 1

    file_rows = []
    symbol_rows = []
    for f, src in contents.items():
        is_py = f.endswith(".py")
        loc = loc_of(src, is_py)
        if loc < 10:
            continue
        stem = Path(f).stem
        tags = fp_class(f, src)

        # whole-file reference: is this module imported / named anywhere else?
        # A file's own definitions inflate ident_freq[stem]; subtract this file's
        # own count so we measure references from OTHER files.
        own_stem_uses = len(re.findall(rf"\b{re.escape(stem)}\b", src))
        external_stem_uses = ident_freq.get(stem, 0) - own_stem_uses
        if is_py:
            referenced = external_stem_uses > 0
        else:
            # TS: a module is referenced if another file imports its path stem,
            # OR its exported symbols are used by ident (PascalCase components).
            own_spec = 1 if re.search(r"""(?:import|from|require)\b[^'"\n]*['"][^'"]*\b%s\b""" % re.escape(stem), src) else 0
            referenced = external_stem_uses > 0 or (spec_stems.get(stem, 0) - own_spec) > 0
        if not referenced and not is_entrypoint(f):
            file_rows.append(
                {
                    "kind": "file",
                    "file": f,
                    "loc": loc,
                    "fp_tags": tags,
                    "confidence": "high" if not tags else "low",
                    "score": loc,
                }
            )

        # --- Per-symbol: top-level name appears nowhere else ---
        for name in top_level_symbols(src, is_py):
            if len(name) < 4:
                continue  # too-common short names skew false; skip (under-report)
            own_uses = len(re.findall(rf"\b{re.escape(name)}\b", src))
            external = ident_freq.get(name, 0) - own_uses
            # >0 use elsewhere means alive. 0 external uses = candidate.
            if external <= 0:
                symbol_rows.append(
                    {
                        "kind": "symbol",
                        "file": f,
                        "symbol": name,
                        "loc": loc,
                        "fp_tags": tags,
                        "confidence": "low",  # per-symbol is always a recall filter
                        "score": loc,
                    }
                )

    if not contents:
        shown = ", ".join(r or "<repo root>" for r in src_roots)
        print(
            f"no source files matched under: {shown}, pass --src-root to point "
            "the lens at your source directories",
            file=sys.stderr,
        )

    # Untagged rows (real candidates) sort above tagged (likely-alive) ones.
    file_rows.sort(key=lambda r: (not r["fp_tags"], r["score"]), reverse=True)
    symbol_rows.sort(key=lambda r: (not r["fp_tags"], r["score"]), reverse=True)

    md = render_md(repo, file_rows, symbol_rows, args.top, src_roots, sorted(contents))
    payload = {"files": file_rows, "symbols": symbol_rows}
    if args.md:
        Path(args.md).write_text(md, encoding="utf-8")
        print(f"wrote {args.md}")
    else:
        print(md)
    if args.json:
        Path(args.json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"wrote {args.json}")


def _scan_description(scanned: list[str], src_roots: tuple[str, ...]) -> str:
    """Describe what was actually scanned, languages and roots, not repo names.

    Derived from the files we *looked at*, not from the candidate rows: a clean
    repo produces no candidates, and inferring the language from an empty
    candidate list would report "no recognised sources" for a repo we scanned
    successfully.
    """
    langs = []
    if any(f.endswith(".py") for f in scanned):
        langs.append("Python")
    if any(Path(f).suffix in TS_EXT for f in scanned):
        langs.append("TS/JS")
    lang = " + ".join(langs) if langs else "no recognised"
    roots = ", ".join(f"`{r}`" for r in src_roots if r) or "the repo root"
    return f"{lang} sources under {roots}"


def render_md(
    repo: str,
    file_rows: list[dict],
    symbol_rows: list[dict],
    top: int,
    src_roots: tuple[str, ...],
    scanned: list[str],
) -> str:
    high = [r for r in file_rows if r["confidence"] == "high"]
    out = [
        f"# Fable-target, DEAD-CODE lens, `{repo}`",
        "",
        f"_{len(scanned)} files scanned ({_scan_description(scanned, src_roots)}) · "
        f"{len(file_rows)} candidate files · {len(symbol_rows)} candidate symbols · "
        f"**{len(high)}** files flagged with no obvious framework reason._",
        "",
        "`score = unused-confidence × size(LOC)`. Whole-file (imported by nothing) "
        "ranks above per-symbol (name grep-absent elsewhere).",
        "",
        "> ### ⚠️ This is a CANDIDATE list, NOT a delete list.",
        ">",
        "> Static grep/AST cannot see dynamic references. **Confirm every row by "
        "hand** before removing anything.",
        ">",
        "> **False positives** (look dead, aren't) are auto-tagged: "
        "`framework-entrypoint` (Next.js `page/layout/route`, `main.py`), "
        "`fastapi-route` (mounted by decorator, never called by name), "
        "`llm-tool` (registered in a tool list rather than invoked), "
        "`orm/pydantic-model` (reflective), `scheduler-job`, "
        "`dynamic-registry` (looked up by name at run time, evaluators, plugin "
        "entry points), `explicit-export` (`__all__`). A row WITH tags is almost "
        "certainly alive.",
        ">",
        "> **False negatives**: per-symbol grep skews toward *uniquely-named* "
        "symbols, common names (`get`, `run`, `process`) match by coincidence and "
        "get filtered, so the symbol list UNDER-reports (safe direction). Symbols "
        "shorter than 4 chars are skipped for the same reason.",
        ">",
        "> **Reference corpus**: every tracked source file in the repo counts as a "
        "reference, including tests, tooling and scripts outside the scanned "
        "roots. A module used only by a build script is not dead.",
        "",
        "## 🎯 Whole-file candidates, imported by nothing (highest trust)",
        "",
        "Files with **no** framework tag are the real candidates; tagged rows are "
        "shown for completeness but are very likely alive.",
        "",
        "| # | LOC | confidence | file | likely-alive tags |",
        "|--:|----:|:----------:|------|-------------------|",
    ]
    for i, r in enumerate(file_rows[:top], 1):
        tags = ", ".join(f"`{t}`" for t in r["fp_tags"]) or "**- none (candidate)**"
        out.append(f"| {i} | {r['loc']} | {r['confidence']} | `{r['file']}` | {tags} |")
    out.append("")
    out.append("## Per-symbol candidates, top-level name grep-absent elsewhere (low trust)")
    out.append("")
    out.append(
        "_Recall filter only, a symbol here may be referenced dynamically, via "
        "`getattr`, a registry, or a string. Verify before touching._"
    )
    out.append("")
    out.append("| # | LOC(file) | symbol | file | likely-alive tags |")
    out.append("|--:|----------:|--------|------|-------------------|")
    for i, r in enumerate(symbol_rows[:top], 1):
        tags = ", ".join(f"`{t}`" for t in r["fp_tags"]) or "-"
        out.append(
            f"| {i} | {r['loc']} | `{r['symbol']}` | `{r['file']}` | {tags} |"
        )
    out.append("")
    return "\n".join(out)


if __name__ == "__main__":
    main()
