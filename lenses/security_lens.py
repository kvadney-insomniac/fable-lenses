#!/usr/bin/env python3
"""Lens 3: security = attack-surface-reach x vuln-likelihood.

The Carlini use case: a cheap deterministic sweep ranks WHERE a premium model
should look for vulnerabilities, so its expensive attention lands on the files
that are both *reachable by an attacker* and *dense in risky patterns*, instead
of reading the whole tree.

    score = reach(imported-by + entrypoint role)  x  vuln(risk-pattern density)

Both axes bucket 1-5 by quintile WITHIN a repo (same as score_targets.py), then
multiply (1..25). Static grep/AST only, no execution, no model tokens.

  * reach   = how many other files import this one + a role bonus for files that
              sit on the request edge (routes / auth / webhooks / input handlers).
              A bug in a high-reach file has a wider blast radius.
  * vuln    = density of risk patterns (raw SQL, f-string/%-into-SQL, eval/exec,
              subprocess/os.system, pickle, yaml.load non-safe, requests to a
              user-controlled URL, a route handler with no auth dependency,
              hand-rolled crypto, literal secrets).

THIS IS A RECALL FILTER, NOT A VERDICT. Every "finding" is a candidate the
premium model must confirm, the auth-missing check in particular over-reports,
because auth applied by middleware, by a router-level ``dependencies=[...]``, or
through a helper dependency is invisible to a grep of the handler. See the
caveats block in the generated report.

WHICH DIRECTORIES GET SCANNED
    ``--src-root`` (repeatable, or comma-separated) names the directories to
    walk, relative to the repo root, e.g. ``--src-root src --src-root lib``.
    When omitted the lens auto-detects the common layouts (``src/``, ``app/``,
    ``lib/``) and falls back to scanning the whole repo if it finds none. The
    Python import graph derives its module prefix from whichever roots are in
    play, so ``src/pkg/mod.py`` resolves ``from pkg.mod import ...`` without any
    project-specific wiring.

PUBLIC / ALREADY-PROTECTED PATHS
    The auth-gap check flags route handlers that declare no auth dependency.
    Some routes are *supposed* to be unauthenticated (health probes, webhooks
    that verify a signature rather than a user JWT), and in most codebases a
    further set is protected at the middleware layer rather than per handler.
    Neither is a finding, and left unsuppressed they bury the rows that matter -
    a noisy list is a list nobody reads. So those paths are suppressed:

      * built-in defaults cover only the universal cases (liveness/readiness/
        health probes, metrics scrape endpoints, webhook receivers);
      * add your own with ``--public-paths /internal,/status`` (repeatable, or
        comma-separated);
      * or drop a ``.fable-public-paths`` file at the root of the scanned repo,
        one token per line, ``#`` starts a comment.

    The three sources are UNIONED, the file and the flag extend the defaults,
    they do not replace them. Tokens are matched case-insensitively as a
    *substring* of the handler's decorated path.

    Keep the list tight. Every token you add silently deletes findings, and a
    token short or generic enough to match paths you did not intend (``/`` or
    ``/api``) will hide real missing-auth bugs without saying so. Prefer several
    specific tokens over one broad one, and re-read the list when it grows.

Usage:
    python3 security_lens.py <repo_path> [--src-root src] [--public-paths /ping]
        [--top 40] [--md out.md] [--json out.json]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

# Reuse the shared primitives so this lens stays consistent with the machine.
from score_targets import DENY, denied, git, quintile_bucketer

PY_EXT = {".py"}
TS_EXT = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}

# Directory names tried, in order, when --src-root is not given. These are the
# layouts that show up across ecosystems (Python src-layout and app-layout, JS
# src/ and lib/). If none of them exist we scan the whole repo rather than
# guessing, a wrong guess silently scores zero files, which looks like a clean
# repo instead of a misconfiguration.
SRC_ROOT_CANDIDATES = ("src", "app", "lib")

# Universal public paths, the ones that are unauthenticated in essentially any
# service, so they are safe to suppress without knowing anything about the repo.
# Health/liveness/readiness probes are hit by the orchestrator, metrics by the
# scrape job, and webhook receivers authenticate the *sender's signature* rather
# than a user JWT, so "no auth dependency" is the correct design there.
# Everything project-specific belongs in --public-paths or .fable-public-paths;
# see the module docstring for why that list should stay short.
DEFAULT_PUBLIC_PATHS = (
    "/health",
    "/healthz",
    "/livez",
    "/liveness",
    "/readyz",
    "/readiness",
    "/metrics",
    "webhook",
)

# Optional per-repo config, read from the root of the repo being scanned.
PUBLIC_PATHS_FILENAME = ".fable-public-paths"


def _normalise_tokens(raw) -> list[str]:
    """Split on commas, strip `#` comments and whitespace, lowercase, drop empties.

    Matching is done against a lowercased path, so a token that arrives with any
    uppercase in it would silently never match, normalise on the way in rather
    than trusting the caller.
    """
    out: list[str] = []
    for chunk in raw:
        chunk = chunk.split("#", 1)[0]
        for tok in chunk.split(","):
            tok = tok.strip().lower()
            if tok:
                out.append(tok)
    return out


def load_public_paths(repo_path: Path, cli_values: list[str] | None) -> tuple[str, ...]:
    """Union of built-in defaults, the repo's config file, and --public-paths.

    Union, not override: the defaults are universal, so there is no sane reason
    to drop them, and making the flag replace them would let a one-token
    invocation quietly re-enable health-probe noise.
    """
    tokens = _normalise_tokens(DEFAULT_PUBLIC_PATHS)

    cfg = repo_path / PUBLIC_PATHS_FILENAME
    if cfg.is_file():
        try:
            tokens += _normalise_tokens(cfg.read_text(encoding="utf-8", errors="ignore").splitlines())
        except OSError:
            pass

    tokens += _normalise_tokens(cli_values or [])

    # de-dupe, preserve order so the report can show them in a stable sequence
    return tuple(dict.fromkeys(tokens))


def resolve_src_roots(repo_path: Path, requested: list[str] | None) -> tuple[str, ...]:
    """Return the path prefixes to scan, e.g. ``("src/",)`` or ``("",)`` for all.

    An empty string means "the repo root", it works because every prefix test
    is ``path.startswith(root)`` and every path starts with "".
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


# --------------------------------------------------------------------------- #
# VULN-LIKELIHOOD: density of risky patterns
# --------------------------------------------------------------------------- #
# (name, compiled regex, weight). Weight ~ how exploitable / how rarely benign.
_RISK = [
    # --- SQL injection surface ---
    ("raw_sql_exec", re.compile(r"\b(?:execute|executemany|text)\s*\(", re.I), 1),
    ("fstring_sql", re.compile(r'(?:execute|text|query)\s*\(\s*f["\']', re.I), 4),
    ("percent_sql", re.compile(r'(?:SELECT|INSERT|UPDATE|DELETE).*["\']\s*%\s*\(', re.I), 4),
    ("str_concat_sql", re.compile(r'(?:SELECT|INSERT|UPDATE|DELETE)[^"\']*["\']\s*\+', re.I), 3),
    # --- code execution ---
    ("eval", re.compile(r"\beval\s*\("), 5),
    ("exec", re.compile(r"\bexec\s*\("), 5),
    ("subprocess", re.compile(r"\bsubprocess\.(?:call|run|Popen|check_output|check_call)\b"), 3),
    ("shell_true", re.compile(r"shell\s*=\s*True"), 4),
    ("os_system", re.compile(r"\bos\.system\s*\("), 5),
    # --- unsafe deserialization ---
    ("pickle", re.compile(r"\bpickle\.(?:load|loads)\b"), 4),
    ("yaml_unsafe", re.compile(r"\byaml\.(?:load|unsafe_load|full_load)\s*\((?![^)]*Safe)"), 4),
    ("marshal", re.compile(r"\bmarshal\.loads?\b"), 3),
    # --- SSRF: requests to a non-literal (potentially user-controlled) URL ---
    ("ssrf_request", re.compile(r"\b(?:requests|httpx|aiohttp)\.(?:get|post|put|delete|request)\s*\(\s*(?!['\"])"), 2),
    ("urlopen", re.compile(r"\burlopen\s*\(\s*(?!['\"])"), 2),
    ("fetch_var", re.compile(r"\bfetch\s*\(\s*`[^`]*\$\{"), 1),  # JS template-literal URL
    # --- hand-rolled crypto / weak hashing ---
    ("weak_hash", re.compile(r"\bhashlib\.(?:md5|sha1)\s*\("), 2),
    ("homerolled_crypto", re.compile(r"\b(?:AES|DES|RSA|Cipher)\.new\s*\(|Crypto\.Cipher"), 2),
    ("insecure_random", re.compile(r"\brandom\.(?:random|randint|choice)\b.*(?:token|secret|password|key)", re.I), 3),
    # --- literal secrets ---
    ("literal_secret", re.compile(r'(?:password|secret|api_key|apikey|token|private_key)\s*=\s*["\'][A-Za-z0-9_\-/+]{12,}["\']', re.I), 3),
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}"), 5),
    ("bearer_literal", re.compile(r'["\']Bearer\s+[A-Za-z0-9_\-\.]{12,}["\']'), 3),
    # --- disabled TLS / auth ---
    ("verify_false", re.compile(r"verify\s*=\s*False"), 3),
    ("dangerously_html", re.compile(r"dangerouslySetInnerHTML"), 2),
]

# Generic FastAPI/Flask/Starlette routing idiom: `@router.get("/x")`, `@app.post("/x")`.
_ROUTE_DECORATOR = re.compile(r"@\w+\.(get|post|put|patch|delete)\s*\(\s*['\"]([^'\"]+)", re.I)
_AUTH_DEP = re.compile(r"get_current_user|require_|Depends\(\s*(?:get_current|require)")


def _strip_comments(src: str, is_py: bool) -> str:
    """Crude comment strip so we don't count risk tokens inside comments."""
    lines = []
    for ln in src.splitlines():
        s = ln.lstrip()
        if is_py and s.startswith("#"):
            continue
        if not is_py and s.startswith(("//", "*", "/*")):
            continue
        lines.append(ln)
    return "\n".join(lines)


# Patterns that only make sense in Python, skipped on TS/JS to cut noise
# (e.g. `.text()` response parsing, `pickle`, `yaml.load` don't exist client-side).
_PY_ONLY_PATTERNS = {
    "raw_sql_exec", "fstring_sql", "percent_sql", "str_concat_sql",
    "subprocess", "shell_true", "os_system", "pickle", "yaml_unsafe",
    "marshal", "urlopen", "weak_hash", "homerolled_crypto",
    "insecure_random", "verify_false",
}


def vuln_signals(
    src: str, is_py: bool, file_rel: str, public_paths: tuple[str, ...]
) -> tuple[float, dict, list]:
    """Return (weighted_score, per-pattern counts, list of route auth gaps)."""
    body = _strip_comments(src, is_py)
    counts: dict[str, int] = {}
    score = 0.0
    for name, rx, weight in _RISK:
        if not is_py and name in _PY_ONLY_PATTERNS:
            continue
        n = len(rx.findall(body))
        if n:
            counts[name] = n
            score += n * weight

    # Route handlers missing an explicit auth dependency. We inspect the ~12 lines
    # following each route decorator (decorator + signature window).
    #
    # The gate is the decorator regex itself, not the directory the file lives in:
    # every project lays its handlers out differently (routes/, routers/, api/,
    # or beside the models), and a directory allowlist is exactly the kind of
    # layout assumption that makes a lens useless on the next repo. The cost is
    # that a non-route file which happens to use the `@x.get("...")` shape, a
    # cache wrapper, a test client helper, will be inspected too. That is rare,
    # and it fails toward over-reporting rather than silence.
    auth_gaps: list[str] = []
    if is_py:
        lines = body.splitlines()
        for i, ln in enumerate(lines):
            m = _ROUTE_DECORATOR.search(ln)
            if not m:
                continue
            full_path = decorated_route_path(file_rel, m.group(2))
            if any(p in full_path.lower() for p in public_paths):
                continue
            window = "\n".join(lines[i : i + 12])
            if not _AUTH_DEP.search(window):
                auth_gaps.append(f"{m.group(1).upper()} {m.group(2)}")
        if auth_gaps:
            counts["route_no_auth_dep"] = len(auth_gaps)
            score += len(auth_gaps) * 3
    return round(score, 1), counts, auth_gaps


def decorated_route_path(file_rel: str, decorated: str) -> str:
    """Best-effort full path for a route, only used for the public-path filter.

    The router's mount prefix is assembled at app-wiring time (``include_router``
    / ``register_blueprint``), which a per-file grep never sees, so the decorated
    string is all we have. We fold the filename stem in as a weak hint, on the
    common convention that a handler module is mounted under its own name, e.g.
    ``routes/billing.py`` declaring ``/{id}`` becomes ``/billing/{id}``.

    Consequence worth knowing: a public path is only suppressible if its token
    appears in the decorated string or the filename. A route whose public-ness
    lives entirely in the mount prefix cannot be matched here, and will keep
    surfacing as a candidate. That is documented over-reporting, not a filter
    you can trust to be complete.
    """
    stem = Path(file_rel).stem
    return f"/{stem}{decorated}"


# --------------------------------------------------------------------------- #
# REACH: imported-by count + entrypoint role
# --------------------------------------------------------------------------- #
def build_import_graph(
    files: list[str], repo_path: Path, src_roots: tuple[str, ...]
) -> dict[str, int]:
    """Return {file_rel: imported-by count}. Cheap: match module stems in imports.

    Python: ``from pkg.services.foo import`` / ``import pkg.services.foo``, we
    index every file by its dotted path derived from its location, AND by that
    path with the source root stripped, because a root that is a packaging
    directory rather than a package (the ``src/`` of a src-layout project) does
    not appear in the import statement. The prefixes come from the source roots
    in play, so nothing here is tied to one project's package name.
    JS/TS: ``@/lib/foo`` (alias to the source root) or relative ``./foo``, by
    stem. Heuristic, like the TS complexity axis: lower confidence than Python,
    because a stem that occurs in two directories can't be disambiguated.
    """
    # Index files by stem and by dotted-module path for resolution.
    by_stem: dict[str, list[str]] = defaultdict(list)
    by_module: dict[str, str] = {}
    # "src/" -> "src.", so we can also index modules with the root stripped off.
    module_prefixes = tuple(r.replace("/", ".") for r in src_roots if r)
    for f in files:
        stem = Path(f).stem
        by_stem[stem].append(f)
        # pkg/services/widget_service.py -> pkg.services.widget_service
        mod = f[:-3].replace("/", ".") if f.endswith(".py") else None
        if mod:
            by_module[mod] = f
            for prefix in module_prefixes:
                if mod.startswith(prefix):
                    by_module.setdefault(mod[len(prefix) :], f)

    imported_by: dict[str, int] = defaultdict(int)
    py_import = re.compile(r"^\s*(?:from\s+([\w\.]+)\s+import|import\s+([\w\.]+))", re.M)
    ts_import = re.compile(r"""(?:import|from|require)\s*\(?\s*['"]([^'"]+)['"]""")

    for f in files:
        try:
            src = (repo_path / f).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if f.endswith(".py"):
            for m in py_import.finditer(src):
                mod = m.group(1) or m.group(2)
                if not mod:
                    continue
                # try full dotted path, then progressively shorter tails
                target = by_module.get(mod)
                if not target:
                    last = mod.rsplit(".", 1)[-1]
                    cands = by_stem.get(last, [])
                    target = cands[0] if len(cands) == 1 else None
                if target and target != f:
                    imported_by[target] += 1
        else:
            for m in ts_import.finditer(src):
                spec = m.group(1)
                if not (spec.startswith(".") or spec.startswith("@/")):
                    continue  # external package
                stem = Path(spec).stem
                cands = by_stem.get(stem, [])
                target = cands[0] if len(cands) == 1 else None
                if target and target != f:
                    imported_by[target] += 1
    return imported_by


def role_bonus(file_rel: str, src: str) -> tuple[int, list[str]]:
    """Entrypoint role bonus, files on the request edge have higher reach."""
    roles: list[str] = []
    low = file_rel.lower()
    if "/routes/" in low or "/api/" in low or "route.ts" in low:
        roles.append("route")
    if "auth" in low or "rbac" in low or "permission" in low or "middleware" in low:
        roles.append("auth")
    if "webhook" in low or "webhook" in src.lower():
        roles.append("webhook")
    if re.search(r"request\.(?:json|form|body|query|args)|await\s+request\.|Body\(|Query\(|Form\(", src):
        roles.append("input-handler")
    # each distinct role adds reach
    return len(set(roles)), sorted(set(roles))


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #
def score_repo(
    repo: str, src_roots: tuple[str, ...], public_paths: tuple[str, ...]
) -> list[dict]:
    repo_path = Path(repo)

    tracked = [
        f
        for f in git(["ls-files"], repo).splitlines()
        if (Path(f).suffix in PY_EXT or Path(f).suffix in TS_EXT)
        and not denied(f)
        and any(f.startswith(r) for r in src_roots)
    ]
    imported_by = build_import_graph(tracked, repo_path, src_roots)

    rows: list[dict] = []
    for f in tracked:
        try:
            src = (repo_path / f).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        is_py = f.endswith(".py")
        vuln, counts, auth_gaps = vuln_signals(src, is_py, f, public_paths)
        rbonus, roles = role_bonus(f, src)
        nimp = imported_by.get(f, 0)
        rows.append(
            {
                "file": f,
                "imported_by": nimp,
                "roles": roles,
                "reach_raw": nimp + 2.0 * rbonus,  # role edge weighted: an edge file is reachable directly
                "vuln_raw": vuln,
                "patterns": counts,
                "auth_gaps": auth_gaps,
            }
        )

    reach_bucket = quintile_bucketer([r["reach_raw"] for r in rows])
    vuln_bucket = quintile_bucketer([r["vuln_raw"] for r in rows])
    for r in rows:
        r["reach"] = reach_bucket(r["reach_raw"])
        r["vuln"] = vuln_bucket(r["vuln_raw"])
        r["score"] = r["reach"] * r["vuln"]
    # tie-break by raw vuln (the security-relevant axis), then reach
    rows.sort(key=lambda r: (r["score"], r["vuln_raw"], r["reach_raw"]), reverse=True)
    return rows


def _scan_description(rows: list[dict], src_roots: tuple[str, ...]) -> str:
    """Describe what was actually scanned, languages and roots, not repo names."""
    langs = []
    if any(r["file"].endswith(".py") for r in rows):
        langs.append("Python")
    if any(Path(r["file"]).suffix in TS_EXT for r in rows):
        langs.append("TS/JS")
    lang = " + ".join(langs) if langs else "no recognised"
    roots = ", ".join(f"`{r}`" for r in src_roots if r) or "the repo root"
    return f"{lang} sources under {roots}"


def render_md(
    repo: str,
    rows: list[dict],
    top: int,
    src_roots: tuple[str, ...],
    public_paths: tuple[str, ...],
) -> str:
    target = [r for r in rows if r["reach"] >= 4 and r["vuln"] >= 4]
    # Key the language caveats on what was actually scanned. Doing this by source
    # root instead would be wrong the moment someone keeps Python under `src/`.
    has_ts = any(Path(r["file"]).suffix in TS_EXT for r in rows)
    out = [
        f"# Fable-target, SECURITY lens, `{repo}`",
        "",
        f"_{len(rows)} source files scored ({_scan_description(rows, src_roots)}) · "
        f"**{len(target)}** in the high-reach × high-vuln-likelihood quadrant._",
        "",
        "`score = reach(imported-by + edge role, 1-5) × vuln(risk-pattern density, 1-5)`. "
        "Quintiles **within this repo**, don't compare across repos.",
        "",
        "> **This is a recall filter, not a verdict.** Every row is a *candidate* "
        "for a premium model (the Carlini use case) to confirm, high density of "
        "risky patterns ≠ a vulnerability. Known over-reporting:",
        ">",
        "> - **`route_no_auth_dep`**, this reads only the handler's decorator and "
        "signature. Auth applied at the middleware layer, at the router level "
        "(`dependencies=[...]`), or through a helper dependency is invisible to "
        "the grep, so a flagged handler may be perfectly well protected. Confirm "
        "each row against your own auth wiring before acting on it.",
        "> - **`raw_sql_exec`** counts every `.execute(`/`text(`, most are "
        "parameterized and safe. The dangerous siblings are `fstring_sql` / "
        "`percent_sql` / `str_concat_sql`.",
        "> - **`ssrf_request`** flags any non-literal URL arg, many are config "
        "constants, not user input.",
        "> - The import graph is grep-resolved; **reach on TS/JS is "
        "lower-confidence** than on Python (`@/` alias + relative resolution "
        "can't disambiguate a stem that occurs twice, same caveat as the TS "
        "complexity axis).",
        "",
    ]
    if has_ts:
        # Replace the trailing blank line so this stays inside the same blockquote.
        out[-1:] = [
            "> - **The client-side vuln signal is THIN.** SQL/exec/pickle/SSRF/"
            "crypto patterns are Python-only (skipped on TS/JS), so the only live "
            "signals on a TS/JS file are `fetch_var` (a templated-URL fetch, "
            "weight 1), an `.exec()` regex false positive, and "
            "`dangerouslySetInnerHTML` / literal secrets. So a top-quadrant TS/JS "
            "file is usually **reach-driven**, a widely-imported API client with "
            "one templated fetch, NOT a hot finding. Real client-side risk (XSS "
            "sinks, token handling, auth-redirect flows) needs human/LLM review, "
            "not this grep.",
            "",
        ]

    def table(items: list[dict]) -> list[str]:
        lines = [
            "| # | score | R×V | file | imp-by | roles | top patterns |",
            "|--:|------:|:---:|------|-------:|-------|--------------|",
        ]
        for i, r in enumerate(items, 1):
            pats = sorted(r["patterns"].items(), key=lambda kv: -kv[1])
            patstr = ", ".join(f"`{k}`×{v}" for k, v in pats[:4]) or "-"
            roles = ",".join(r["roles"]) or "-"
            lines.append(
                f"| {i} | **{r['score']}** | {r['reach']}×{r['vuln']} | "
                f"`{r['file']}` | {r['imported_by']} | {roles} | {patstr} |"
            )
        return lines

    out.append("## 🎯 Security target list, high reach × high vuln-likelihood (both ≥ 4)")
    out.append("")
    out.append("Point the premium model here first for a vulnerability pass.")
    out.append("")
    out += table(target[:top])
    out.append("")

    # Spotlight: route handlers with no detected auth dependency (candidate list).
    gaps = [r for r in rows if r["auth_gaps"]]
    if gaps:
        suppressed = ", ".join(f"`{p}`" for p in public_paths)
        out.append("## ⚠️ Route handlers with no detected auth dependency (candidates)")
        out.append("")
        out.append(
            "_Handlers whose decorated path matches a public token are suppressed. "
            f"Active tokens: {suppressed}, the built-in probe/metrics/webhook "
            "defaults, plus anything from `--public-paths` or `.fable-public-paths`. "
            "The suppression is deliberately **partial**: the router's mount prefix "
            "is assembled at app-wiring time and is not visible per file, so a route "
            "whose public-ness lives in that prefix still surfaces here. Note the "
            "opposite hazard too, a token that is short or generic enough to match "
            "unintended paths deletes real findings from this table without warning. "
            "Each remaining row still needs confirmation: auth may be applied at the "
            "router level (`dependencies=[...]`), by middleware, or via a helper "
            "dependency this grep can't see._"
        )
        out.append("")
        out.append("| file | handlers |")
        out.append("|------|----------|")
        for r in sorted(gaps, key=lambda r: -len(r["auth_gaps"]))[:20]:
            hs = ", ".join(f"`{g}`" for g in r["auth_gaps"][:6])
            out.append(f"| `{r['file']}` | {hs} |")
        out.append("")

    out.append(f"## Full top {top} (any axis ≥ 3)")
    out.append("")
    out += table([r for r in rows if r["reach"] >= 3 or r["vuln"] >= 3][:top])
    out.append("")
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("repo", help="path to the git repo to score")
    ap.add_argument(
        "--src-root",
        action="append",
        metavar="DIR",
        help="directory to scan, relative to the repo root; repeatable or "
        "comma-separated. Default: auto-detect src/, app/, lib/, else the "
        "whole repo.",
    )
    ap.add_argument(
        "--public-paths",
        action="append",
        metavar="TOKEN",
        help="extra path tokens whose handlers are legitimately unauthenticated; "
        "repeatable or comma-separated. Unioned with the built-in defaults and "
        f"with {PUBLIC_PATHS_FILENAME} at the repo root. Keep it tight, every "
        "token silently hides findings.",
    )
    ap.add_argument("--top", type=int, default=40)
    ap.add_argument("--md")
    ap.add_argument("--json")
    args = ap.parse_args()

    repo_path = Path(args.repo)
    src_roots = resolve_src_roots(repo_path, args.src_root)
    public_paths = load_public_paths(repo_path, args.public_paths)

    rows = score_repo(args.repo, src_roots, public_paths)
    if not rows:
        shown = ", ".join(r or "<repo root>" for r in src_roots)
        print(
            f"no source files matched under: {shown}, pass --src-root to point "
            "the lens at your source directories",
            file=sys.stderr,
        )
    md = render_md(args.repo, rows, args.top, src_roots, public_paths)
    if args.md:
        Path(args.md).write_text(md, encoding="utf-8")
        print(f"wrote {args.md}")
    else:
        print(md)
    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=2), encoding="utf-8")
        print(f"wrote {args.json}")


if __name__ == "__main__":
    main()
