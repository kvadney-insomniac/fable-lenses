#!/usr/bin/env python3
"""Self-checks for the lenses.

There is no test framework here on purpose: the toolkit installs nothing, so
its checks should not either. Every case builds a tiny throwaway git repo in a
temp directory, runs a lens against it exactly the way a user would, and
asserts on the output.

    python3 lenses/selftest.py            # run everything
    python3 lenses/selftest.py arch       # run cases whose name contains "arch"

Fixtures are invented. No case reads anything outside its own temp directory.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path

LENSES = Path(__file__).resolve().parent
PY = sys.executable or "python3"

CASES: list[tuple[str, object]] = []


class Skip(Exception):
    """A case that cannot run here (a missing optional dependency), not a failure."""


def case(fn):
    CASES.append((fn.__name__, fn))
    return fn


def need_typescript() -> None:
    """drift_lens_ts.js needs the `typescript` package resolvable from somewhere."""
    probe = subprocess.run(
        ["node", "-e", "const t=require('typescript'); if(!t.createSourceFile) process.exit(9)"],
        capture_output=True, text=True)
    if probe.returncode != 0:
        raise Skip("no 'typescript' package with the 5.x compiler API is "
                   "resolvable to node (npm i typescript@5, or set NODE_PATH)")


# --------------------------------------------------------------------------- #
# fixture helpers
# --------------------------------------------------------------------------- #
def _git(repo: Path, *args: str) -> str:
    """Run git with identity and hooks pinned, so a machine's global config
    (hooksPath, commit signing, a missing user.email) cannot fail a fixture."""
    out = subprocess.run(
        ["git", "-C", str(repo),
         "-c", "user.name=lens selftest",
         "-c", "user.email=selftest@example.invalid",
         "-c", "commit.gpgsign=false",
         "-c", "core.hooksPath=/dev/null",
         *args],
        capture_output=True, text=True)
    if out.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {out.stderr.strip()}")
    return out.stdout


def write_files(repo: Path, files: dict[str, str]) -> None:
    for rel, body in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")


def make_repo(tmp: Path, files: dict[str, str], commits: int = 1) -> Path:
    """A git repo containing `files`, committed `commits` times (for churn)."""
    repo = tmp / "fixture"
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q", "-b", "main")
    write_files(repo, files)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "initial")
    for n in range(1, commits):
        # Touch every file so churn is non-zero and comparable across the tree.
        for rel in files:
            p = repo / rel
            p.write_text(p.read_text(encoding="utf-8") + f"\n# rev {n}\n"
                         if rel.endswith(".py")
                         else p.read_text(encoding="utf-8") + f"\n// rev {n}\n",
                         encoding="utf-8")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", f"rev {n}")
    return repo


def run_lens(script: str, *args: str, expect_ok: bool = True):
    """Run a lens as a subprocess, the way the README tells people to."""
    cmd = ([PY, str(LENSES / script)] if script.endswith(".py")
           else ["node", str(LENSES / script)]) + list(args)
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          env={**os.environ, "PYTHONPATH": str(LENSES)})
    if expect_ok and proc.returncode != 0:
        raise AssertionError(
            f"{script} exited {proc.returncode}\nSTDOUT:\n{proc.stdout}\n"
            f"STDERR:\n{proc.stderr}")
    return proc


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# coverage_gap: repo-path-first CLI, --md / --json, optional --scores
# --------------------------------------------------------------------------- #
COVERAGE_FIXTURE = {
    "pkg/__init__.py": "",
    "pkg/pricing.py": "def quote(a, b):\n    if a > b:\n        return a\n    return b\n",
    "pkg/mailer.py": "def send(to):\n    if not to:\n        return None\n    return to\n",
    "tests/test_mailer.py": "from pkg.mailer import send\n\n\ndef test_send():\n    assert send('x')\n",
}


@case
def coverage_gap_repo_first_cli():
    """The natural invocation: repo path first, --md, --json, no --scores."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        repo = make_repo(tmp, COVERAGE_FIXTURE, commits=3)
        md, js = tmp / "REPORT-coverage.md", tmp / "data-coverage.json"
        run_lens("coverage_gap.py", str(repo), "--since", "10 years ago",
                 "--min-impact", "1", "--md", str(md), "--json", str(js))
        assert md.is_file(), "--md wrote nothing"
        rows = load_json(js)
        files = {r["file"] for r in rows}
        assert "pkg/pricing.py" in files, f"pricing.py missing from {files}"
        by_file = {r["file"]: r for r in rows}
        # mailer is named by a test file, pricing is not: pricing must rank above.
        assert by_file["pkg/mailer.py"]["test_refs"] == 1, by_file["pkg/mailer.py"]
        assert by_file["pkg/pricing.py"]["test_refs"] == 0, by_file["pkg/pricing.py"]
        assert rows[0]["file"] == "pkg/pricing.py", f"wrong top row: {rows[0]}"
        assert "COVERAGE-GAP lens" in md.read_text(encoding="utf-8")


@case
def coverage_gap_prints_to_stdout_by_default():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        repo = make_repo(tmp, COVERAGE_FIXTURE, commits=2)
        proc = run_lens("coverage_gap.py", str(repo), "--since", "10 years ago",
                        "--min-impact", "1")
        assert "COVERAGE-GAP lens" in proc.stdout, proc.stdout[:400]
        assert "pkg/pricing.py" in proc.stdout


@case
def coverage_gap_legacy_positional_order_still_works():
    """The old `<scores.json> <repo>` shape keeps working, with a warning."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        repo = make_repo(tmp, COVERAGE_FIXTURE, commits=3)
        scores = tmp / "data.json"
        run_lens("score_targets.py", str(repo), "--since", "10 years ago",
                 "--json", str(scores), "--md", str(tmp / "t.md"))
        new_json, old_json = tmp / "new.json", tmp / "old.json"
        run_lens("coverage_gap.py", str(repo), "--scores", str(scores),
                 "--min-impact", "1", "--md", str(tmp / "a.md"), "--json", str(new_json))
        proc = run_lens("coverage_gap.py", str(scores), str(repo),
                        "--min-impact", "1", "--md", str(tmp / "b.md"),
                        "--json", str(old_json))
        assert "deprecated" in proc.stderr, proc.stderr
        assert load_json(new_json) == load_json(old_json), "legacy order diverged"


# --------------------------------------------------------------------------- #
# drift: both lenses print to stdout by default and honour --md / --json
# --------------------------------------------------------------------------- #
def _drifted_pair(lang: str) -> dict[str, str]:
    """Two near-identical functions in different files: one grew a guard."""
    if lang == "py":
        a = ("def apply_discount(order, rate):\n"
             "    total = 0\n"
             "    for item in order:\n"
             "        if item.taxable:\n"
             "            total += item.price * rate\n"
             "        else:\n"
             "            total += item.price\n"
             "    if total < 0:\n"
             "        total = 0\n"
             "    return round(total, 2)\n")
        b = ("def apply_rebate(basket, factor):\n"
             "    amount = 0\n"
             "    for line in basket:\n"
             "        if line.taxable:\n"
             "            amount += line.price * factor\n"
             "        else:\n"
             "            amount += line.price\n"
             "    return round(amount, 2)\n")
        return {"pkg/billing/discount.py": a, "pkg/billing/rebate.py": b}
    a = ("export function applyDiscount(order: Line[], rate: number) {\n"
         "  let total = 0;\n"
         "  for (const item of order) {\n"
         "    if (item.taxable) {\n"
         "      total += item.price * rate;\n"
         "    } else {\n"
         "      total += item.price;\n"
         "    }\n"
         "  }\n"
         "  if (total < 0) {\n"
         "    total = 0;\n"
         "  }\n"
         "  return Math.round(total * 100) / 100;\n"
         "}\n")
    b = ("export function applyRebate(basket: Line[], factor: number) {\n"
         "  let amount = 0;\n"
         "  for (const line of basket) {\n"
         "    if (line.taxable) {\n"
         "      amount += line.price * factor;\n"
         "    } else {\n"
         "      amount += line.price;\n"
         "    }\n"
         "  }\n"
         "  return Math.round(amount * 100) / 100;\n"
         "}\n")
    return {"src/billing/discount.ts": a, "src/billing/rebate.ts": b}


@case
def drift_py_stdout_and_md_and_json():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        repo = make_repo(tmp, _drifted_pair("py"))
        proc = run_lens("drift_lens.py", str(repo))
        assert "Drift lens" in proc.stdout, proc.stdout[:400]
        md, js = tmp / "REPORT-drift.md", tmp / "data-drift.json"
        proc = run_lens("drift_lens.py", str(repo), "--md", str(md), "--json", str(js))
        assert md.is_file() and js.is_file()
        assert "Drift lens" not in proc.stdout, "report leaked to stdout despite --md"
        assert f"wrote {md}" in proc.stdout
        assert isinstance(load_json(js), list)


@case
def drift_ts_stdout_and_md_and_json():
    need_typescript()
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        repo = make_repo(tmp, _drifted_pair("ts"))
        cwd_before = set(Path.cwd().iterdir())
        proc = run_lens("drift_lens_ts.js", str(repo))
        assert "Drift lens (TypeScript)" in proc.stdout, proc.stdout[:400]
        assert set(Path.cwd().iterdir()) == cwd_before, \
            "the lens wrote into the current directory with no --md"
        md, js = tmp / "REPORT-drift-ts.md", tmp / "data-drift-ts.json"
        proc = run_lens("drift_lens_ts.js", str(repo), "--md", str(md), "--json", str(js))
        assert md.is_file() and js.is_file()
        assert "Drift lens (TypeScript)" not in proc.stdout, \
            "report leaked to stdout despite --md"
        assert isinstance(load_json(js), list)


# --------------------------------------------------------------------------- #
# arch: TS/JS import resolution (tsconfig paths, index files, .tsx)
# --------------------------------------------------------------------------- #
NEXT_FIXTURE = {
    # JSONC on purpose: comments and a trailing comma, which json.loads rejects.
    "tsconfig.json": (
        "{\n"
        "  // path aliases, as every Next.js app ships them\n"
        '  "compilerOptions": {\n'
        '    "baseUrl": ".",\n'
        '    "paths": { "@/*": ["./src/*"] },\n'
        "  }\n"
        "}\n"
    ),
    "src/app/dashboard/page.tsx": (
        'import { Panel } from "@/components/Panel";\n'
        'import { formatMoney } from "@/lib/format";\n'
        'import { columns } from "./columns";\n'
        "export default function Page() { return <Panel cols={columns} "
        "total={formatMoney(1)} />; }\n"
    ),
    "src/app/dashboard/columns.ts": 'export const columns = ["a", "b"];\n',
    "src/components/Panel/index.tsx": (
        'import { useLedger } from "@/hooks/useLedger";\n'
        "export function Panel(props: any) { return <div>{useLedger().n}</div>; }\n"
    ),
    "src/hooks/useLedger.ts": (
        'import { formatMoney } from "../lib/format";\n'
        "export function useLedger() { return { n: formatMoney(2) }; }\n"
    ),
    # A utility reaching back up into components: the violation the lens exists for.
    "src/lib/format.ts": (
        'import { Panel } from "@/components/Panel";\n'
        "export function formatMoney(n: number) { return String(n) + String(!!Panel); }\n"
    ),
    "src/lib/format.test.ts": 'import { formatMoney } from "./format";\n',
    "src/types/ledger.d.ts": "export type Ledger = { n: number };\n",
}


@case
def arch_resolves_ts_imports():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        repo = make_repo(tmp, NEXT_FIXTURE)
        js = tmp / "data-arch.json"
        run_lens("arch_lens.py", str(repo), "--md", str(tmp / "a.md"), "--json", str(js))
        data = load_json(js)
        assert data["edges"] >= 5, f"expected a connected graph, got {data['edges']} edges"
        assert data["tsconfig_paths"] == ["@/*"], data["tsconfig_paths"]
        mods = {r["module"] for r in data["rows"]}
        # `@/components/Panel` -> Panel/index.tsx: alias + index-file resolution.
        assert "src/components/Panel/index.tsx" in mods, mods
        assert not any(m.endswith(".d.ts") or ".test." in m for m in mods), mods
        by_mod = {r["module"]: r for r in data["rows"]}
        fmt = by_mod.get("src/lib/format.ts")
        assert fmt and fmt["violations"], f"util -> components not flagged: {fmt}"
        assert fmt["layer"] == "util", fmt
        assert by_mod["src/components/Panel/index.tsx"]["fan_in"] >= 2, by_mod


@case
def arch_ts_layer_of_next_app_dirs():
    """app/ components/ hooks/ contexts/ lib/ each land in their own layer."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        files = dict(NEXT_FIXTURE)
        files["src/contexts/ThemeContext.tsx"] = (
            'import { formatMoney } from "@/lib/format";\n'
            "export const Theme = formatMoney;\n")
        repo = make_repo(tmp, files)
        js = tmp / "data-arch.json"
        run_lens("arch_lens.py", str(repo), "--md", str(tmp / "a.md"), "--json", str(js))
        layers = {r["module"]: r["layer"] for r in load_json(js)["rows"]}
        for module, expected in (("src/app/dashboard/page.tsx", "app"),
                                 ("src/components/Panel/index.tsx", "components"),
                                 ("src/hooks/useLedger.ts", "hooks"),
                                 ("src/contexts/ThemeContext.tsx", "hooks"),
                                 ("src/lib/format.ts", "util")):
            if module in layers:  # low-fan-in modules are discarded by design
                assert layers[module] == expected, f"{module}: {layers[module]}"


@case
def arch_ts_app_importing_app_is_not_a_violation_by_default():
    """Next.js colocation inside app/ is normal; --strict-top-layer opts in."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        repo = make_repo(tmp, NEXT_FIXTURE)
        loose, strict = tmp / "loose.json", tmp / "strict.json"
        run_lens("arch_lens.py", str(repo), "--md", str(tmp / "a.md"), "--json", str(loose))
        run_lens("arch_lens.py", str(repo), "--strict-top-layer",
                 "--md", str(tmp / "b.md"), "--json", str(strict))

        def app_self(data):
            return [v for r in data["rows"] for v in r["violations"]
                    if v.startswith("app->app")]

        assert not app_self(load_json(loose)), "app -> app flagged by default"
        assert app_self(load_json(strict)), "--strict-top-layer flagged nothing"


@case
def arch_python_graph_still_works():
    """The Python path must keep resolving package and sibling imports."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        repo = make_repo(tmp, {
            "app/__init__.py": "",
            "app/routes/__init__.py": "",
            "app/routes/billing.py": "from app.services.invoice import build\n\n\ndef get():\n    return build()\n",
            "app/services/__init__.py": "",
            "app/services/invoice.py": "from app.routes.billing import get\n\n\ndef build():\n    return get\n",
        })
        js = tmp / "data-arch.json"
        run_lens("arch_lens.py", str(repo), "--md", str(tmp / "a.md"), "--json", str(js))
        data = load_json(js)
        assert data["edges"] >= 2, data["edges"]
        by_mod = {r["module"]: r for r in data["rows"]}
        # service importing a route reaches up a layer: still a violation.
        assert by_mod["app.services.invoice"]["violations"], by_mod
        assert data["cycles"], "the mutual import should be an SCC"


# --------------------------------------------------------------------------- #
# deadcode: Next.js convention files and build-wired entrypoints are not dead
# --------------------------------------------------------------------------- #
def _filler(n: int, prefix: str = "export const") -> str:
    """Enough lines to clear the lens's 10-LOC floor."""
    return "".join(f"{prefix} pad{prefix[-1]}{i} = {i};\n" for i in range(n))


DEADCODE_FIXTURE = {
    "package.json": json.dumps({
        "name": "fixture",
        "scripts": {"seed": "tsx scripts/seedLedger.ts", "build": "next build"},
    }, indent=2) + "\n",
    "next.config.mjs": (
        "const config = { webpack: (c) => c };\n"
        'export { runtimeShim } from "./src/support/runtimeShim";\n'
        "export default config;\n"
    ),
    "sentry.client.config.ts": (
        'import "./src/support/telemetryInit";\n'
        "export const dsn = String(process.env.DSN);\n"
    ),
    # Next.js loads these by name. None of them is imported anywhere.
    "src/instrumentation-client.ts": "export function onRouterTransitionStart() {}\n" + _filler(12),
    "src/app/global-error.tsx": "export default function GlobalError() { return null; }\n" + _filler(12),
    "src/app/dashboard/page.tsx": "export default function Page() { return null; }\n" + _filler(12),
    "src/middleware.ts": "export function middleware() {}\n" + _filler(12),
    # Referenced only by a config file or an npm script.
    "src/support/runtimeShim.ts": "export const runtimeShim = 1;\n" + _filler(12),
    "src/support/telemetryInit.ts": "export const telemetryInit = 1;\n" + _filler(12),
    "scripts/seedLedger.ts": "export const seed = 1;\n" + _filler(12),
    # Genuinely unreferenced, and named like a convention file but NOT under app/.
    "src/components/error.tsx": "export function ErrorPanel() { return null; }\n" + _filler(12),
    "src/components/OrphanCard.tsx": "export function OrphanCard() { return null; }\n" + _filler(12),
}


@case
def deadcode_skips_next_conventions_and_config_wired_files():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        repo = make_repo(tmp, DEADCODE_FIXTURE)
        js = tmp / "data-deadcode.json"
        run_lens("deadcode_lens.py", str(repo), "--src-root", ".",
                 "--md", str(tmp / "a.md"), "--json", str(js))
        flagged = {r["file"] for r in load_json(js)["files"]}
        for alive in ("src/instrumentation-client.ts", "src/app/global-error.tsx",
                      "src/app/dashboard/page.tsx", "src/middleware.ts",
                      "src/support/runtimeShim.ts", "src/support/telemetryInit.ts",
                      "scripts/seedLedger.ts"):
            assert alive not in flagged, f"{alive} flagged as dead"
        # The recall side must survive: a real orphan is still reported, and a
        # convention NAME outside app/ is an ordinary component, not an entrypoint.
        assert "src/components/OrphanCard.tsx" in flagged, flagged
        assert "src/components/error.tsx" in flagged, flagged


# --------------------------------------------------------------------------- #
def main() -> int:
    wanted = sys.argv[1:]
    selected = [(n, f) for n, f in CASES
                if not wanted or any(w in n for w in wanted)]
    if not selected:
        print(f"no case matches {wanted}", file=sys.stderr)
        return 2
    failures = skipped = 0
    for name, fn in selected:
        try:
            fn()
        except Skip as why:
            skipped += 1
            print(f"skip {name}: {why}")
        except Exception:
            failures += 1
            print(f"FAIL {name}")
            traceback.print_exc()
        else:
            print(f"ok   {name}")
    tail = f", {skipped} skipped" if skipped else ""
    print(f"\n{len(selected) - failures - skipped}/{len(selected)} passed{tail}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
