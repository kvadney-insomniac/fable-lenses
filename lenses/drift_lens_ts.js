#!/usr/bin/env node
/* Drift lens (TypeScript), find copy-pasted code that DIVERGED.
 *
 * The TypeScript sibling of drift_lens.py, which could only read .py. The bug
 * class both exist to catch: one copy of a hand-written mapper or buffer-parser
 * gets a fix and its siblings do not, so the same logic quietly disagrees with
 * itself across the codebase. Nothing fails, the copies just answer
 * differently, and only under the inputs the fix was about.
 *
 * This scans .ts/.tsx with the real TypeScript compiler rather than a regex,
 * so it sees functions the Python lens structurally cannot.
 *
 * Method (mirrors the Python lens): extract every function via the TS AST,
 * NORMALIZE tokens (identifiers->ID, literals->LIT, keep keywords/punctuation)
 * so rename-only clones collapse and real logic diffs surface; shingle prefilter
 * + Jaccard similarity; flag pairs whose similarity is HIGH but < 1.0 (drift).
 *
 * Usage: node drift_lens_ts.js <repo_path> [--md REPORT-drift-ts.md] [--json data-drift-ts.json]
 *
 * Prints the report to stdout by default, like the Python lenses. --md writes
 * it to a path instead; --json writes the drifted groups as data. A bare
 * second positional is still read as the markdown path, the old shape.
 */
const fs = require("fs");
const path = require("path");
const cp = require("child_process");

function parseArgs(argv) {
  const opts = { repo: null, md: null, json: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--md") opts.md = argv[++i];
    else if (a === "--json") opts.json = argv[++i];
    else if (a.startsWith("--md=")) opts.md = a.slice(5);
    else if (a.startsWith("--json=")) opts.json = a.slice(7);
    else if (a === "-h" || a === "--help") opts.help = true;
    else if (opts.repo === null) opts.repo = a;
    else if (opts.md === null) opts.md = a; // legacy positional outFile
  }
  return opts;
}

const ARGS = parseArgs(process.argv.slice(2));
if (ARGS.help || !ARGS.repo) {
  console.error("usage: node drift_lens_ts.js <repo_path> [--md PATH] [--json PATH]");
  process.exit(ARGS.help ? 0 : 2);
}
const REPO = ARGS.repo;

// The TypeScript compiler is the one dependency. Prefer the copy inside the
// repo being scanned (it is the version that repo actually compiles with),
// fall back to whatever resolves for this script (a global install or
// NODE_PATH), and say so plainly rather than dying on a raw MODULE_NOT_FOUND.
let ts;
for (const attempt of [() => require(path.join(path.resolve(REPO), "node_modules", "typescript")), () => require("typescript")]) {
  try {
    const mod = attempt();
    // TypeScript 7 ships the native port, whose JS package exports a version
    // string and nothing else. Keep looking rather than crashing on
    // `ts.SyntaxKind` twenty lines later.
    if (mod && mod.createSourceFile && mod.SyntaxKind) {
      ts = mod;
      break;
    }
  } catch {
    /* try the next resolution */
  }
}
if (!ts) {
  console.error(
    `[drift_lens_ts] no usable 'typescript' package (needs the 5.x JavaScript compiler API: ` +
      `createSourceFile + SyntaxKind). Install one in ${REPO} (npm i -D typescript@5), ` +
      "or make one resolvable to this script via NODE_PATH."
  );
  process.exit(3);
}

const MIN_TOKENS = 40;
const SHINGLE_K = 5;
const MAX_FANOUT = 25; // ignore boilerplate shingles shared by > this many fns
const MIN_SHARED = 8;
const DRIFT_LO = 0.8;
const DENY = [".test.", ".spec.", "/__tests__/", ".d.ts", "/__mocks__/", ".stories.", "/node_modules/"];

function trackedFiles() {
  const out = cp.execSync(`git -C ${REPO} ls-files '*.ts' '*.tsx'`, { encoding: "utf8", maxBuffer: 1 << 26 });
  return out.split("\n").filter((f) => f && !DENY.some((d) => f.includes(d)));
}

// Normalize one function's source text to a token stream.
function normalize(text) {
  const scanner = ts.createScanner(ts.ScriptTarget.Latest, /*skipTrivia*/ true, ts.LanguageVariant.JSX, text);
  const toks = [];
  let k;
  while ((k = scanner.scan()) !== ts.SyntaxKind.EndOfFileToken) {
    if (k === ts.SyntaxKind.Identifier) toks.push("ID");
    else if (
      k === ts.SyntaxKind.StringLiteral ||
      k === ts.SyntaxKind.NumericLiteral ||
      k === ts.SyntaxKind.NoSubstitutionTemplateLiteral ||
      k === ts.SyntaxKind.TemplateHead ||
      k === ts.SyntaxKind.TemplateMiddle ||
      k === ts.SyntaxKind.TemplateTail ||
      k === ts.SyntaxKind.BigIntLiteral
    )
      toks.push("LIT");
    else toks.push(ts.tokenToString(k) || ts.SyntaxKind[k]); // keywords + punctuation
  }
  return toks;
}

const FN_KINDS = new Set([
  ts.SyntaxKind.FunctionDeclaration,
  ts.SyntaxKind.MethodDeclaration,
  ts.SyntaxKind.FunctionExpression,
  ts.SyntaxKind.ArrowFunction,
]);

function fnName(node, sf) {
  if (node.name && node.name.getText) return node.name.getText(sf);
  // arrow/expr assigned to a var: walk to the variable declaration name
  let p = node.parent;
  if (p && p.name && p.name.getText) return p.name.getText(sf);
  return "<anon>";
}

const funcs = [];
for (const rel of trackedFiles()) {
  let src;
  try {
    src = fs.readFileSync(path.join(REPO, rel), "utf8");
  } catch {
    continue;
  }
  let sf;
  try {
    sf = ts.createSourceFile(rel, src, ts.ScriptTarget.Latest, true, rel.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  } catch {
    continue;
  }
  const visit = (node) => {
    if (FN_KINDS.has(node.kind)) {
      const text = node.getText(sf);
      const toks = normalize(text);
      if (toks.length >= MIN_TOKENS) {
        const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
        const end = sf.getLineAndCharacterOfPosition(node.getEnd()).line + 1;
        funcs.push({ file: rel, name: fnName(node, sf), line, end, toks, loc: text.split("\n").length });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
}

// shingle index → candidate pairs
const index = new Map();
const shingles = funcs.map((f) => {
  const s = new Set();
  for (let i = 0; i + SHINGLE_K <= f.toks.length; i++) s.add(f.toks.slice(i, i + SHINGLE_K).join(""));
  return s;
});
shingles.forEach((s, i) => s.forEach((sh) => (index.has(sh) ? index.get(sh).push(i) : index.set(sh, [i]))));
const shared = new Map();
for (const members of index.values()) {
  if (members.length < 2 || members.length > MAX_FANOUT) continue;
  for (let a = 0; a < members.length; a++)
    for (let b = a + 1; b < members.length; b++) {
      const key = members[a] + ":" + members[b];
      shared.set(key, (shared.get(key) || 0) + 1);
    }
}
// One function's line range containing the other's is not drift: it is a
// closure inside its factory, a callback inside the hook that declares it, a
// nested helper. The outer span includes the inner one, so the pair always
// looks near-identical, and there is nothing to reconcile. This lens walks
// every nested arrow function, so without the check these dominate.
function nested(a, b) {
  if (a.file !== b.file) return false;
  return (a.line <= b.line && b.end <= a.end) || (b.line <= a.line && a.end <= b.end);
}

function jaccard(a, b) {
  let inter = 0;
  const small = a.size < b.size ? a : b,
    big = a.size < b.size ? b : a;
  for (const x of small) if (big.has(x)) inter++;
  return inter / (a.size + b.size - inter);
}
const flagged = [];
const exact = [];
for (const [key, n] of shared) {
  if (n < MIN_SHARED) continue;
  const [a, b] = key.split(":").map(Number);
  if (funcs[a].name === funcs[b].name && funcs[a].file === funcs[b].file) continue;
  if (nested(funcs[a], funcs[b])) continue;
  const j = jaccard(shingles[a], shingles[b]);
  if (j >= 0.999) exact.push([a, b]);
  else if (j >= DRIFT_LO) flagged.push([j, a, b]);
}

// union-find cluster
const parent = {};
const find = (x) => {
  while (parent[x] !== undefined && parent[x] !== x) x = parent[x] = parent[parent[x]] ?? parent[x];
  return x;
};
for (const [, a, b] of flagged) {
  if (parent[a] === undefined) parent[a] = a;
  if (parent[b] === undefined) parent[b] = b;
  parent[find(a)] = find(b);
}
const groups = new Map();
const bestSim = new Map();
for (const node of Object.keys(parent).map(Number)) {
  const r = find(node);
  if (!groups.has(r)) groups.set(r, new Set());
  groups.get(r).add(node);
}
for (const [j, a] of flagged) {
  const r = find(a);
  bestSim.set(r, Math.max(bestSim.get(r) || 0, j));
}
const ranked = [...groups.values()].sort((g1, g2) => {
  const m = (g) => Math.max(...[...g].map((i) => funcs[i].loc)) * g.size;
  return m(g2) - m(g1);
});

const lines = [
  `# Drift lens (TypeScript), \`${REPO}\``,
  "",
  `_${funcs.length} functions scanned · **${ranked.length} drifted groups** · ${exact.length} exact clones._`,
  "",
  "Each group is the same normalized logic copied to N sites that then **diverged**. That divergence is the point: identical clones are a tidiness problem, but copies that drifted apart are where one site got a bug fix and the others silently did not. Diff the members, decide which behavior is correct, and unify behind one helper plus a test.",
  "",
  "> **Nesting is excluded.** A pair where one function's line range contains the other's is skipped: a closure and the factory that returns it, a callback and the hook that declares it, a nested helper. The outer span includes the inner one, so they always look like near-identical copies, and there is nothing to reconcile because there is only one piece of code. Copies in the same file at disjoint line ranges are still reported.",
  "",
];
ranked.slice(0, 25).forEach((g, gi) => {
  const members = [...g].sort((x, y) => funcs[x].file.localeCompare(funcs[y].file));
  const sim = bestSim.get(find(members[0])) || 0;
  lines.push(`### ${gi + 1}. ${g.size} drifted copies · max sim ${Math.round(sim * 100)}% · ~${Math.max(...members.map((i) => funcs[i].loc))} LOC`);
  members.forEach((i) => lines.push(`- \`${funcs[i].file}:${funcs[i].line}\` **${funcs[i].name}**(), ${funcs[i].loc} LOC`));
  lines.push("");
});
const report = lines.join("\n") + "\n";
if (ARGS.md) {
  fs.writeFileSync(ARGS.md, report);
  console.log(`wrote ${ARGS.md}`);
} else {
  process.stdout.write(report);
}
if (ARGS.json) {
  const payload = ranked.map((g) =>
    [...g]
      .sort((x, y) => x - y)
      .map((i) => ({ file: funcs[i].file, name: funcs[i].name, line: funcs[i].line }))
  );
  fs.writeFileSync(ARGS.json, JSON.stringify(payload, null, 2));
  console.log(`wrote ${ARGS.json}`);
}
console.error(`[drift_lens_ts] ${funcs.length} fns, ${ranked.length} drifted groups, ${exact.length} exact clones`);
