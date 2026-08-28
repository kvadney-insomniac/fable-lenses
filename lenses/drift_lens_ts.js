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
 * Usage: node drift_lens_ts.js <source_dir> [outFile]
 */
const fs = require("fs");
const path = require("path");
const cp = require("child_process");

const REPO = process.argv[2];
const OUT = process.argv[3] || "REPORT-drift-ts.md";
const ts = require(path.join(path.resolve(REPO), "node_modules", "typescript"));

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
        funcs.push({ file: rel, name: fnName(node, sf), line, toks, loc: text.split("\n").length });
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
];
ranked.slice(0, 25).forEach((g, gi) => {
  const members = [...g].sort((x, y) => funcs[x].file.localeCompare(funcs[y].file));
  const sim = bestSim.get(find(members[0])) || 0;
  lines.push(`### ${gi + 1}. ${g.size} drifted copies · max sim ${Math.round(sim * 100)}% · ~${Math.max(...members.map((i) => funcs[i].loc))} LOC`);
  members.forEach((i) => lines.push(`- \`${funcs[i].file}:${funcs[i].line}\` **${funcs[i].name}**(), ${funcs[i].loc} LOC`));
  lines.push("");
});
fs.writeFileSync(OUT, lines.join("\n"));
console.log(`wrote ${OUT}, ${funcs.length} fns, ${ranked.length} drifted groups, ${exact.length} exact clones`);
