#!/usr/bin/env python3
"""Architecture/coupling lens — where is an abstraction missing or violated?

The drift lens finds copy-paste; this lens finds *coupling*: the import graph
among the repo's own Python modules, read from a committed git ref rather than
the working tree, so a run is reproducible and unaffected by whatever is
half-edited on disk. Default ref is `HEAD`.

Signals per module:
- fan-in / fan-out (who depends on me / whom do I depend on)
- layering violations, from path-derived layers (see DEFAULT_LAYERS): a module
  may import its own layer or anything below it, never a layer above it, and
  the top layer may not import itself (entrypoints importing entrypoints is
  how a routing layer quietly becomes a service layer)
- import cycles (Tarjan SCCs, size > 1)

Score keeps the machine's shape: impact × opportunity, quintile-bucketed 1-5.
  impact      = fan-in  (how much of the codebase feels a change here)
  opportunity = 3·violations + 2·(in a cycle) + fan-out  (how tangled)

Usage:
  python3 arch_lens.py /path/to/repo [--ref HEAD] [--src-root app] [--top 30]
      [--layers "routes,services,models"] [--md out.md] [--json out.json]

Read-only, deterministic, zero model tokens.
"""

import argparse
import ast
import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path


def git(repo, *args):
    return subprocess.run(["git", "-C", repo, *args], capture_output=True,
                          text=True, check=True).stdout


# Where a repo keeps its own source. Checked in order; falls back to the repo
# root, which is correct for flat single-package projects.
SRC_CANDIDATES = ("src", "app", "lib")

# Default layering convention, outermost first. Ranks are comma-separated; the
# names within one rank are `|`-separated aliases and the first is the label
# used in reports. A module may import its own rank or any rank to the right,
# never one to the left.
#
# This default describes the layout most HTTP services converge on — request
# handlers on top, domain services beneath them, data/schema definitions and
# shared helpers at the bottom. It is a widespread convention, not a law: a
# repo that layers differently should pass --layers, and one with no layering
# convention at all will simply report every module as `core` and fall back to
# fan-in and cycles, which need no convention to mean something.
DEFAULT_LAYERS = (
    "route|routes|api|controllers|handlers,"
    "service|services|middleware|usecases,"
    "model|models|schema|schemas|entities|repositories,"
    "util|utils|lib|helpers|common"
)


def parse_layers(spec):
    """"a|b,c" -> {"a": ("a", 0), "b": ("a", 0), "c": ("c", 1)} (name -> label, rank)."""
    ranks = {}
    for rank, group in enumerate(spec.split(",")):
        names = [n.strip().lower() for n in group.split("|") if n.strip()]
        for name in names:
            ranks.setdefault(name, (names[0], rank))
    return ranks


def detect_src_root(paths):
    """Pick the directory holding the repo's own Python source."""
    for cand in SRC_CANDIDATES:
        if any(p.startswith(cand + "/") and p.endswith(".py") for p in paths):
            return cand
    return ""  # flat repo: modules live at the top level


def list_modules(repo, ref, src_root):
    out = git(repo, "ls-tree", "-r", ref, "--name-only")
    paths = out.splitlines()
    if src_root:
        paths = [p for p in paths if p.startswith(src_root + "/")]
    return [p for p in paths if p.endswith(".py")]


def module_prefix_to_strip(src_root, paths):
    """Is src_root itself a package, or just a container of packages?

    `app/__init__.py` present means `app` IS the package, so imports say
    `app.routes.chat` and the module name keeps the prefix. A bare `src/` with
    no `__init__.py` is the "src layout": the packages live *inside* it and no
    import statement ever mentions it, so names are taken relative to it.
    """
    if not src_root:
        return ""
    return "" if f"{src_root}/__init__.py" in paths else src_root + "/"


def path_to_module(path, strip=""):
    # app/routes/chat.py -> app.routes.chat ; app/utils/__init__.py -> app.utils
    if strip and path.startswith(strip):
        path = path[len(strip):]
    mod = path[:-3].replace("/", ".")
    return mod[: -len(".__init__")] if mod.endswith(".__init__") else mod


def layer_of(path, ranks, src_root=""):
    """(label, rank) for a file — first path segment below src_root that names a layer.

    The file stem counts too, so a one-file layer (`models.py`) lands the same
    way a directory (`models/`) does. First match wins; anything unmatched is
    `core` with rank None — unranked code is never flagged in either direction,
    because we have no evidence about where it is supposed to sit.
    """
    rel = path[len(src_root) + 1:] if src_root and path.startswith(src_root + "/") else path
    parts = rel.split("/")
    for seg in parts[:-1] + [Path(parts[-1]).stem]:
        hit = ranks.get(seg.lower())
        if hit:
            return hit
    return ("core", None)


def violates(src_rank, tgt_rank):
    """An import is a violation if it reaches UP the stack, or sideways at the top."""
    if src_rank is None or tgt_rank is None:
        return False          # unranked (`core`) code: no expectation to break
    if tgt_rank < src_rank:
        return True           # a lower layer importing a higher one
    return tgt_rank == src_rank == 0  # top layer importing itself


def imports_of(repo, ref, path, known, tops, strip=""):
    """In-repo modules imported by `path` (absolute + relative), filtered to `known`.

    `tops` is the set of top-level package names this repo actually owns, which
    is how an in-repo import is told apart from a third-party one — no
    hardcoded namespace required.
    """
    try:
        src = git(repo, "show", f"{ref}:{path}")
        tree = ast.parse(src)
    except (subprocess.CalledProcessError, SyntaxError):
        return set()
    pkg_parts = path_to_module(path, strip).split(".")[:-1]  # containing package
    found = set()

    def add(mod):
        # resolve to a known module: exact, or its package __init__
        while mod:
            if mod in known:
                found.add(mod)
                return
            mod = mod.rsplit(".", 1)[0] if "." in mod else ""

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] in tops:
                    add(a.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # relative
                base = pkg_parts[: len(pkg_parts) - (node.level - 1)]
                stem = ".".join(base + (node.module.split(".") if node.module else []))
            else:
                stem = node.module or ""
            if stem.split(".")[0] in tops:
                for a in node.names:
                    add(f"{stem}.{a.name}")
                add(stem)
    return found


def tarjan_sccs(graph):
    index, low, on_stack, stack = {}, {}, set(), []
    sccs, counter = [], [0]
    for start in graph:
        if start in index:
            continue
        work = [(start, iter(graph.get(start, ())))]
        index[start] = low[start] = counter[0]; counter[0] += 1
        stack.append(start); on_stack.add(start)
        while work:
            node, it = work[-1]
            advanced = False
            for nxt in it:
                if nxt not in index:
                    index[nxt] = low[nxt] = counter[0]; counter[0] += 1
                    stack.append(nxt); on_stack.add(nxt)
                    work.append((nxt, iter(graph.get(nxt, ()))))
                    advanced = True
                    break
                if nxt in on_stack:
                    low[node] = min(low[node], index[nxt])
            if advanced:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] == index[node]:
                scc = []
                while True:
                    w = stack.pop(); on_stack.discard(w); scc.append(w)
                    if w == node:
                        break
                if len(scc) > 1:
                    sccs.append(sorted(scc))
    return sccs


def quintile(values):
    """value -> 1-5 bucket by quintile within the population (0 stays 1)."""
    srt = sorted(values)
    def bucket(v):
        if not srt or v <= 0:
            return 1
        rank = sum(1 for x in srt if x <= v) / len(srt)
        return min(5, 1 + int(rank * 5))
    return bucket


def main():
    ap = argparse.ArgumentParser(description="Import-graph / layering lens.")
    ap.add_argument("repo")
    # A committed ref, not the working tree: same input every run, and immune
    # to uncommitted edits. HEAD is whatever the repo is currently on.
    ap.add_argument("--ref", default="HEAD",
                    help="git ref to read the source from (default: HEAD)")
    ap.add_argument("--src-root", default=None,
                    help="directory holding the repo's own source "
                         f"(default: auto-detect {'/'.join(SRC_CANDIDATES)}, else repo root)")
    ap.add_argument("--layers", default=DEFAULT_LAYERS,
                    help="layer order, outermost first: 'a|alias,b,c' "
                         f"(default: {DEFAULT_LAYERS})")
    ap.add_argument("--top", type=int, default=30)
    ap.add_argument("--md")
    ap.add_argument("--json")
    args = ap.parse_args()

    ranks = parse_layers(args.layers)
    try:
        all_paths = git(args.repo, "ls-tree", "-r", args.ref, "--name-only").splitlines()
    except subprocess.CalledProcessError:
        sys.exit(f"[arch_lens] cannot read ref {args.ref!r} in {args.repo} "
                 f"(pass --ref with a ref that exists)")
    src_root = args.src_root if args.src_root is not None else detect_src_root(all_paths)
    src_root = src_root.strip("/")
    strip = module_prefix_to_strip(src_root, all_paths)

    paths = list_modules(args.repo, args.ref, src_root)
    if not paths:
        sys.exit(f"[arch_lens] no .py files under {src_root or '<repo root>'} "
                 f"at {args.ref} (pass --src-root)")
    mod_of = {p: path_to_module(p, strip) for p in paths}
    path_of = {m: p for p, m in mod_of.items()}
    known = set(mod_of.values())
    tops = {m.split(".")[0] for m in known}  # this repo's own top-level packages

    edges = defaultdict(set)  # module -> imported modules
    for p in paths:
        me = mod_of[p]
        for tgt in imports_of(args.repo, args.ref, p, known, tops, strip):
            if tgt != me:
                edges[me].add(tgt)

    def layer(m):
        return layer_of(path_of[m], ranks, src_root)

    fan_in = defaultdict(int)
    violations = defaultdict(list)  # module -> [(target, "route->route"), ...]
    for src, tgts in edges.items():
        src_label, src_rank = layer(src)
        for t in tgts:
            fan_in[t] += 1
            t_label, t_rank = layer(t)
            if violates(src_rank, t_rank):
                violations[src].append((t, f"{src_label}->{t_label}"))

    sccs = tarjan_sccs({m: edges.get(m, set()) for m in known})
    in_cycle = {m for scc in sccs for m in scc}

    rows = []
    fi_bucket = quintile([fan_in.get(m, 0) for m in known])
    opp_raw = {m: 3 * len(violations.get(m, [])) + (2 if m in in_cycle else 0)
                  + len(edges.get(m, ())) for m in known}
    opp_bucket = quintile(list(opp_raw.values()))
    for m in known:
        imp, opp = fi_bucket(fan_in.get(m, 0)), opp_bucket(opp_raw[m])
        score = imp * opp
        if imp <= 2 and not violations.get(m) and m not in in_cycle:
            continue  # same discard rule as the other lenses
        rows.append({
            "module": m, "file": path_of[m], "layer": layer(m)[0],
            "fan_in": fan_in.get(m, 0), "fan_out": len(edges.get(m, ())),
            "violations": [f"{v[1]} {v[0]}" for v in violations.get(m, [])],
            "in_cycle": m in in_cycle,
            "impact": imp, "opportunity": opp, "score": score,
        })
    rows.sort(key=lambda r: (-r["score"], -r["fan_in"]))

    if args.json:
        Path(args.json).write_text(json.dumps(
            {"rows": rows, "cycles": sccs, "ref": args.ref,
             "src_root": src_root or ".", "layers": args.layers}, indent=1))
    lines = [f"# arch lens — `{Path(args.repo).name}` @ {args.ref}",
             "",
             f"Source root `{src_root or '.'}` · layers `{args.layers}`.",
             "",
             f"{len(known)} modules, {sum(len(v) for v in edges.values())} import edges, "
             f"{sum(len(v) for v in violations.values())} layering violations, "
             f"{len(sccs)} import cycle(s).",
             "",
             "| score | I×O | module | layer | fan-in | fan-out | violations | cycle |",
             "|------:|:---:|--------|-------|-------:|--------:|------------|:-----:|"]
    for r in rows[: args.top]:
        v = "; ".join(r["violations"][:3]) + (" …" if len(r["violations"]) > 3 else "")
        lines.append(f"| {r['score']} | {r['impact']}×{r['opportunity']} | `{r['module']}` "
                     f"| {r['layer']} | {r['fan_in']} | {r['fan_out']} | {v or '—'} "
                     f"| {'⭕' if r['in_cycle'] else ''} |")
    if sccs:
        lines += ["", "## Import cycles (SCCs)", ""]
        for i, scc in enumerate(sccs, 1):
            lines.append(f"{i}. ({len(scc)} modules) " + " ↔ ".join(f"`{m}`" for m in scc[:8])
                         + (" …" if len(scc) > 8 else ""))
    report = "\n".join(lines) + "\n"
    if args.md:
        Path(args.md).write_text(report)
    else:
        print(report)
    print(f"[arch_lens] {len(rows)} surviving modules, top score "
          f"{rows[0]['score'] if rows else 0}", file=sys.stderr)


if __name__ == "__main__":
    main()
