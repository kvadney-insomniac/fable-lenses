#!/usr/bin/env python3
"""Architecture/coupling lens, where is an abstraction missing or violated?

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

Both languages are read. Python imports resolve through the module graph;
TS/JS imports resolve the way a bundler does, through `tsconfig.json` `paths`
aliases (`@/x`), `baseUrl`, implicit extensions and `index` files. Without that
resolution a Next.js repo reports its modules and *zero* edges, which reads as
"no coupling" when it means "the lens could not follow an import".

Usage:
  python3 arch_lens.py /path/to/repo [--ref HEAD] [--src-root app] [--top 30]
      [--lang auto|py|ts] [--layers "routes,services,models"]
      [--strict-top-layer] [--md out.md] [--json out.json]

Read-only, deterministic, zero model tokens.
"""

import argparse
import ast
import json
import posixpath
import re
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
# This default describes the layout most HTTP services converge on, request
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


# The same idea for a TS/JS front end. A Next.js app has no `routes/` directory:
# the routing layer IS `app/` (or `pages/`), the presentation layer is
# `components/`, and the stateful glue lives in `hooks/`, `contexts/` and
# `store/`. `lib/` and `utils/` sit at the bottom exactly as they do server-side.
DEFAULT_LAYERS_TS = (
    "app|pages|routes|route|api|controllers|handlers,"
    "components|containers|views|features,"
    "hooks|contexts|providers|service|services|middleware|store|stores|usecases,"
    "model|models|schema|schemas|entities|repositories|types,"
    "util|utils|lib|helpers|common"
)

TS_EXT = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
# Suffixes tried when resolving a specifier to a file, in TypeScript's order.
TS_RESOLVE_SUFFIXES = ("", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
                       "/index.ts", "/index.tsx", "/index.js", "/index.jsx")
# Tests, mocks, stories and type-only declarations are not architecture. Left in,
# a test file's fan-out dominates the graph and `.d.ts` shadows real modules.
TS_DENY = (".d.ts", ".test.", ".spec.", ".stories.", "/__tests__/", "/__mocks__/",
           "/node_modules/", "/dist/", "/build/", "/.next/", "/coverage/")


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


def ts_denied(path):
    return any(tok in path for tok in TS_DENY)


def ts_sources(paths, root=""):
    prefix = root + "/" if root else ""
    return sorted(p for p in paths
                  if p.startswith(prefix) and p.endswith(TS_EXT) and not ts_denied(p))


def detect_ts_root(paths):
    """`src/` when the TS sources live there, otherwise the repo root.

    Deliberately not the `SRC_CANDIDATES` walk used for Python: in a Next.js
    app without `src/`, `app/` is a *sibling* of `components/`, `hooks/` and
    `lib/`, so picking `app/` as the source root would throw away most of the
    repo and, worse, most of the import graph.
    """
    return "src" if ts_sources(paths, "src") else ""


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
    """(label, rank) for a file, first path segment below src_root that names a layer.

    The file stem counts too, so a one-file layer (`models.py`) lands the same
    way a directory (`models/`) does. First match wins; anything unmatched is
    `core` with rank None, unranked code is never flagged in either direction,
    because we have no evidence about where it is supposed to sit.
    """
    rel = path[len(src_root) + 1:] if src_root and path.startswith(src_root + "/") else path
    parts = rel.split("/")
    for seg in parts[:-1] + [Path(parts[-1]).stem]:
        hit = ranks.get(seg.lower())
        if hit:
            return hit
    return ("core", None)


def violates(src_rank, tgt_rank, top_self=True):
    """An import is a violation if it reaches UP the stack, or sideways at the top.

    ``top_self`` controls the sideways-at-the-top half. It holds for a service
    whose top layer is request handlers: a route importing a route is how a
    routing layer quietly becomes a service layer. It does NOT hold for a
    Next.js `app/` directory, where colocation is the framework's own design, a
    layout importing a sibling segment's component is ordinary, and leaving the
    rule on buries every real violation under hundreds of these.
    """
    if src_rank is None or tgt_rank is None:
        return False          # unranked (`core`) code: no expectation to break
    if tgt_rank < src_rank:
        return True           # a lower layer importing a higher one
    return top_self and tgt_rank == src_rank == 0  # top layer importing itself


def imports_of(repo, ref, path, known, tops, strip=""):
    """In-repo modules imported by `path` (absolute + relative), filtered to `known`.

    `tops` is the set of top-level package names this repo actually owns, which
    is how an in-repo import is told apart from a third-party one, no
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

    def add_sibling(mod):
        """`import helper` inside a directory that also contains helper.py.

        A flat directory of scripts (the shape this toolkit itself has) imports
        its neighbours by bare name, so the top-level-package test above calls
        every one of those third-party and the graph comes out empty. `add`
        only records modules that exist in this repo, so the worst case of
        trying the sibling first is an edge to a real local file.
        """
        if mod:
            add(".".join(pkg_parts + mod.split(".")))

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] in tops:
                    add(a.name)
                else:
                    add_sibling(a.name)
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
            elif not node.level:
                for a in node.names:
                    add_sibling(f"{stem}.{a.name}")
                add_sibling(stem)
    return found


# --------------------------------------------------------------------------- #
# TS/JS import resolution
# --------------------------------------------------------------------------- #
def _rel(path):
    """Normalize a repo-relative posix path; the repo root is the empty string."""
    norm = posixpath.normpath(path)
    return "" if norm in (".", "/") else norm.lstrip("/")


def strip_jsonc(text):
    """tsconfig.json is JSONC: line/block comments and trailing commas are legal.

    Written out rather than pulled from a package because the whole toolkit is
    standard library only, and `json.loads` on a real tsconfig fails on the
    first `//`.
    """
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(c)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def load_tsconfig(repo, ref, name="tsconfig.json", depth=0):
    """Read `paths` / `baseUrl` from a tsconfig at `ref`, following `extends` once.

    Returns ``{"base_url": str|None, "paths": {...}, "paths_base": str}``. A
    missing or unparseable tsconfig is not an error: relative imports still
    resolve, only the alias ones are lost, and saying so beats refusing to run.
    """
    cfg = {"base_url": None, "paths": {}, "paths_base": ""}
    try:
        raw = git(repo, "show", f"{ref}:{name}")
    except subprocess.CalledProcessError:
        return cfg
    try:
        doc = json.loads(strip_jsonc(raw))
    except (json.JSONDecodeError, ValueError):
        return cfg
    if not isinstance(doc, dict):
        return cfg
    cfg_dir = posixpath.dirname(name)

    ext = doc.get("extends")
    if depth < 1 and isinstance(ext, str) and ext.startswith("."):
        parent = _rel(posixpath.join(cfg_dir, ext))
        if not parent.endswith(".json"):
            parent += ".json"
        cfg = load_tsconfig(repo, ref, parent, depth + 1)

    opts = doc.get("compilerOptions")
    opts = opts if isinstance(opts, dict) else {}
    if isinstance(opts.get("baseUrl"), str):
        cfg["base_url"] = _rel(posixpath.join(cfg_dir, opts["baseUrl"]))
    paths = opts.get("paths")
    if isinstance(paths, dict):
        for pattern, targets in paths.items():
            if isinstance(targets, list):
                cfg["paths"][pattern] = [t for t in targets if isinstance(t, str)]
    # `paths` entries are relative to baseUrl when there is one, and to the
    # tsconfig's own directory otherwise (TS 4.4+ allows paths with no baseUrl).
    cfg["paths_base"] = cfg["base_url"] if cfg["base_url"] is not None else _rel(cfg_dir)
    return cfg


# Every shape that names a module: `from 'x'`, a side-effect `import 'x'`, a
# dynamic `import('x')`, and CommonJS `require('x')`.
_TS_SPEC_PATTERNS = (
    re.compile(r"""\bfrom\s*['"]([^'"]+)['"]"""),
    re.compile(r"""\bimport\s*['"]([^'"]+)['"]"""),
    re.compile(r"""\bimport\s*\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""\brequire\s*\(\s*['"]([^'"]+)['"]"""),
)


def ts_specifiers(src):
    specs = set()
    for rx in _TS_SPEC_PATTERNS:
        specs.update(rx.findall(src))
    return specs


def resolve_ts_spec(spec, importer, index, cfg):
    """Resolve one specifier to a tracked file, the way a bundler would.

    Relative first, then `paths` aliases (`@/*` -> `./src/*`), then a bare
    specifier against `baseUrl`. Each candidate base is tried with TypeScript's
    implicit extensions and `index` files. Anything unresolved is a third-party
    package, which is not part of this repo's architecture.
    """
    bases = []
    if spec.startswith("."):
        bases.append(_rel(posixpath.join(posixpath.dirname(importer), spec)))
    else:
        for pattern, targets in cfg["paths"].items():
            head, star, tail = pattern.partition("*")
            if star:
                if (spec.startswith(head) and spec.endswith(tail)
                        and len(spec) >= len(head) + len(tail)):
                    mid = spec[len(head): len(spec) - len(tail)] if tail else spec[len(head):]
                    for t in targets:
                        bases.append(_rel(posixpath.join(cfg["paths_base"],
                                                         t.replace("*", mid))))
            elif spec == pattern:
                for t in targets:
                    bases.append(_rel(posixpath.join(cfg["paths_base"], t)))
        if cfg["base_url"] is not None:
            bases.append(_rel(posixpath.join(cfg["base_url"], spec)))
    for base in bases:
        for suffix in TS_RESOLVE_SUFFIXES:
            cand = base + suffix
            if cand in index:
                return cand
    return None


def ts_edges(repo, ref, files, cfg):
    """{file: {imported files}} for the TS/JS half of the repo."""
    index = set(files)
    out = defaultdict(set)
    for f in files:
        try:
            src = git(repo, "show", f"{ref}:{f}")
        except subprocess.CalledProcessError:
            continue
        for spec in ts_specifiers(src):
            target = resolve_ts_spec(spec, f, index, cfg)
            if target and target != f:
                out[f].add(target)
    return out


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
    ap.add_argument("--lang", choices=("auto", "py", "ts"), default="auto",
                    help="which import graph to build (default: auto = every "
                         "language present, Python and TS/JS side by side)")
    ap.add_argument("--layers", default=None,
                    help="layer order, outermost first: 'a|alias,b,c'. Applies "
                         "to both languages. Defaults are per-language: "
                         f"Python '{DEFAULT_LAYERS}', TS/JS '{DEFAULT_LAYERS_TS}'")
    ap.add_argument("--strict-top-layer", action="store_true",
                    help="also treat a top-layer module importing its own layer "
                         "as a violation on TS/JS. On by default for Python "
                         "(route importing route), off for TS/JS because Next.js "
                         "colocation inside app/ makes it the normal case.")
    ap.add_argument("--top", type=int, default=30)
    ap.add_argument("--md")
    ap.add_argument("--json")
    args = ap.parse_args()

    py_layers = args.layers or DEFAULT_LAYERS
    ts_layers = args.layers or DEFAULT_LAYERS_TS
    ranks_py, ranks_ts = parse_layers(py_layers), parse_layers(ts_layers)
    try:
        all_paths = git(args.repo, "ls-tree", "-r", args.ref, "--name-only").splitlines()
    except subprocess.CalledProcessError:
        sys.exit(f"[arch_lens] cannot read ref {args.ref!r} in {args.repo} "
                 f"(pass --ref with a ref that exists)")

    # module -> how to read it back: its file, its language, its layer table.
    meta: dict[str, dict] = {}
    edges = defaultdict(set)
    roots: dict[str, str] = {}
    tsconfig = None

    if args.lang in ("auto", "py"):
        py_root = (args.src_root if args.src_root is not None
                   else detect_src_root(all_paths)).strip("/")
        paths = list_modules(args.repo, args.ref, py_root)
        if paths:
            roots["py"] = py_root or "."
            strip = module_prefix_to_strip(py_root, all_paths)
            mod_of = {p: path_to_module(p, strip) for p in paths}
            known = set(mod_of.values())
            tops = {m.split(".")[0] for m in known}
            for p in paths:
                meta[mod_of[p]] = {"path": p, "lang": "py", "ranks": ranks_py,
                                   "root": py_root}
            for p in paths:
                me = mod_of[p]
                for tgt in imports_of(args.repo, args.ref, p, known, tops, strip):
                    if tgt != me:
                        edges[me].add(tgt)

    if args.lang in ("auto", "ts"):
        ts_root = (args.src_root if args.src_root is not None
                   else detect_ts_root(all_paths)).strip("/")
        ts_paths = ts_sources(all_paths, ts_root)
        if ts_paths:
            roots["ts"] = ts_root or "."
            # A TS module is named by its file path: `x.ts` and `x/index.ts` are
            # different modules that would collide under any prettier scheme.
            tsconfig = load_tsconfig(args.repo, args.ref)
            for p in ts_paths:
                meta[p] = {"path": p, "lang": "ts", "ranks": ranks_ts,
                           "root": ts_root}
            for src, tgts in ts_edges(args.repo, args.ref, ts_paths, tsconfig).items():
                edges[src] |= tgts

    if not meta:
        sys.exit(f"[arch_lens] no {args.lang} source files found at {args.ref} in "
                 f"{args.repo} (pass --src-root, or --lang)")
    known = set(meta)
    path_of = {m: meta[m]["path"] for m in meta}

    def layer(m):
        return layer_of(meta[m]["path"], meta[m]["ranks"], meta[m]["root"])

    fan_in = defaultdict(int)
    violations = defaultdict(list)  # module -> [(target, "route->route"), ...]
    for src, tgts in edges.items():
        src_label, src_rank = layer(src)
        top_self = args.strict_top_layer or meta[src]["lang"] == "py"
        for t in tgts:
            fan_in[t] += 1
            t_label, t_rank = layer(t)
            if violates(src_rank, t_rank, top_self):
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
            "lang": meta[m]["lang"],
            "fan_in": fan_in.get(m, 0), "fan_out": len(edges.get(m, ())),
            "violations": [f"{v[1]} {v[0]}" for v in violations.get(m, [])],
            "in_cycle": m in in_cycle,
            "impact": imp, "opportunity": opp, "score": score,
        })
    rows.sort(key=lambda r: (-r["score"], -r["fan_in"]))

    n_edges = sum(len(v) for v in edges.values())
    root_desc = " · ".join(f"{lang} root `{r}`" for lang, r in sorted(roots.items()))
    counts = {lang: sum(1 for m in known if meta[m]["lang"] == lang)
              for lang in sorted(roots)}
    if args.json:
        Path(args.json).write_text(json.dumps(
            {"rows": rows, "cycles": sccs, "ref": args.ref,
             "roots": roots, "modules_by_lang": counts,
             "layers": {"py": py_layers, "ts": ts_layers},
             "tsconfig_paths": sorted((tsconfig or {}).get("paths", {})),
             "edges": n_edges}, indent=1))
    lines = [f"# arch lens, `{Path(args.repo).resolve().name}` @ {args.ref}",
             "",
             f"{root_desc} · "
             + ", ".join(f"{n} {lang} modules" for lang, n in counts.items()) + ".",
             "",
             f"{len(known)} modules, {n_edges} import edges, "
             f"{sum(len(v) for v in violations.values())} layering violations, "
             f"{len(sccs)} import cycle(s).",
             ""]
    if "ts" in roots:
        aliases = ", ".join(f"`{p}`" for p in sorted((tsconfig or {}).get("paths", {}))) or "none"
        lines += [
            f"TS/JS imports resolved through `tsconfig.json`: aliases {aliases}, "
            f"baseUrl `{(tsconfig or {}).get('base_url') or '-'}`, plus relative "
            "specifiers, implicit extensions and `index` files. An unresolved "
            "specifier is treated as a third-party package. If the alias list "
            "above is empty on a repo that uses `@/`, the tsconfig was not found "
            "at this ref and the graph is relative-imports-only.",
            "",
            f"Layer order, TS/JS: `{ts_layers}`. A top-layer module importing its "
            "own layer is NOT counted as a violation here (Next.js colocates "
            "inside `app/` by design); pass `--strict-top-layer` to count it.",
            "",
        ]
    if "py" in roots:
        lines += [f"Layer order, Python: `{py_layers}`.", ""]
    lines += [
             "| score | I×O | module | layer | fan-in | fan-out | violations | cycle |",
             "|------:|:---:|--------|-------|-------:|--------:|------------|:-----:|"]
    for r in rows[: args.top]:
        v = "; ".join(r["violations"][:3]) + (" …" if len(r["violations"]) > 3 else "")
        lines.append(f"| {r['score']} | {r['impact']}×{r['opportunity']} | `{r['module']}` "
                     f"| {r['layer']} | {r['fan_in']} | {r['fan_out']} | {v or '-'} "
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
