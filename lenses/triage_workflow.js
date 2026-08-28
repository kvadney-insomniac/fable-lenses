// Tier-1 triage, a cheap-model verification pass over the lenses' candidates.
//
// Invoke from a Claude Code session:
//   Workflow({ scriptPath: 'lenses/triage_workflow.js',
//              args: { root: '/path/to/your/checkout',
//                      ref: 'HEAD',
//                      targets: { api: 'services/api', web: 'apps/web' },
//                      ghRepos: { api: 'OWNER/NAME' },
//                      candidates: <contents of candidates.json> } })
//
// `root` is required; everything else has a default:
//   ref             git ref to verify against          (default 'HEAD')
//   targets         { <target name>: <path> }, path is absolute, or relative
//                   to root. Defaults to `${root}/${name}` for every target
//                   name appearing in the candidates, so a single-repo sweep
//                   named after its own directory needs no config at all, and
//                   a target named '.' means root itself.
//   ghRepos         { <target name>: 'OWNER/NAME' } (or one string for all) -
//                   only used to let the v2-riser check look at open issues.
//                   Omitted: that step is skipped, git history alone decides.
//   candidates      the parsed/serialized candidates.json; if absent it is
//                   loaded from candidatesPath.
//   candidatesPath  default `${root}/candidates.json`
//   model, effort   default 'haiku' / 'low', this tier is meant to be cheap.
//
// Every agent is READ-ONLY against the ref (git show / git grep / git log -
// never checkout), so the pass is safe to run while other agents have the
// working tree on their own branches.
//
// POLICY, a cheap model may not bury a security finding. Security-lens rows
// are ANNOTATE-ONLY: the verdict adds context, but the row always appears in
// the triage report and the synthesis step must keep it regardless of status.
// The asymmetry is the whole argument: a false discard on an auth/tenancy issue
// is invisible, nobody ever learns the finding was dropped, while a false
// pass costs exactly one premium-model look. The same asymmetry applies to
// `delete-candidate` verdicts: a deletion that looked safe to a cheap model has
// been wrong before, because the only references were dynamic, so those still
// need a premium-model or human confirmation before anything is removed.

export const meta = {
  name: 'lens-triage',
  description: 'Tier-1: cheaply verify each lens candidate against a git ref',
  whenToUse: 'After a lens sweep, before dispatching premium-model investigators. Needs candidates.json from triage_candidates.py passed as args.candidates.',
  phases: [{ title: 'Triage', detail: 'one cheap verifier agent per candidate', model: 'haiku' }],
}

// args may arrive as an object, a JSON string, or missing pieces, normalize.
const A = typeof args === 'string' ? JSON.parse(args) : (args || {})
const root = A.root
if (!root) {
  throw new Error('triage_workflow: args.root is required, pass the absolute path of the checkout the candidates were scored from')
}
const ref = A.ref || 'HEAD'
const MODEL = A.model || 'haiku'
const EFFORT = A.effort || 'low'
const candidatesPath = A.candidatesPath || `${root}/candidates.json`
let candidates = typeof A.candidates === 'string' ? JSON.parse(A.candidates) : A.candidates

// Where each target's code lives. A configured path may be absolute or relative
// to root; an unconfigured target falls back to a sibling directory of root
// named after it, which is the common monorepo layout.
const targetPaths = A.targets || {}
const pathFor = (target) => {
  const p = targetPaths[target]
  if (!p) return target && target !== '.' ? `${root}/${target}` : root
  return p.startsWith('/') ? p : `${root}/${p}`
}
// Optional per-target GitHub repo for the open-issue check.
const ghRepoFor = (target) =>
  typeof A.ghRepos === 'string' ? A.ghRepos : (A.ghRepos || {})[target] || null

if (!Array.isArray(candidates)) {
  // Fallback: load candidates.json from disk via a loader agent (workflow
  // scripts have no filesystem access; agents do).
  log(`args.candidates missing, loading ${candidatesPath} via loader agent`)
  const loaded = await agent(
    `Run exactly: cat ${candidatesPath}\n` +
    `Return the file's JSON content via structured output as {"json": "<the raw file content as a string>"}. Do not modify it.`,
    {
      label: 'load:candidates.json', phase: 'Triage', model: MODEL, effort: EFFORT,
      schema: {
        type: 'object', required: ['json'], additionalProperties: false,
        properties: { json: { type: 'string', description: 'raw JSON text of candidates.json' } },
      },
    }
  )
  candidates = JSON.parse(loaded.json)
}

const VERDICT = {
  type: 'object',
  additionalProperties: false,
  required: ['status', 'klass', 'evidence', 'priority', 'suggested_action'],
  properties: {
    status: {
      enum: ['real', 'already-fixed', 'false-positive', 'unclear'],
      description: 'real = signal confirmed live on the ref; already-fixed = recent commits addressed it; false-positive = lens misread the code; unclear = could not determine cheaply',
    },
    klass: {
      enum: ['point-fix', 'architectural', 'investigation', 'delete-candidate', 'n/a'],
      description: 'point-fix = small mechanical change; architectural = needs design; investigation = worth a premium-model deep dive; delete-candidate = confirmed dead code; n/a = for non-real statuses',
    },
    evidence: { type: 'string', description: '1-3 sentences citing what you actually saw: commit hashes, grep hit counts, code excerpts. No speculation.' },
    priority: { type: 'integer', minimum: 1, maximum: 5, description: '5 = investigate first' },
    suggested_action: { type: 'string', description: 'one sentence: what the premium model should do here (or "drop")' },
  },
}

const COMMON = (c) => {
  const dir = pathFor(c.target)
  return `You are a cheap, fast triage verifier for a code-quality targeting machine.
A deterministic lens flagged a candidate; your ONLY job is to verify whether the
signal is still real on ${ref} and classify it. Do not fix anything.

Repo: ${dir}  (target "${c.target}")
File: ${c.file}
Lens: ${c.lens}
Lens detail: ${c.detail}

HARD RULES, the working tree may be on another agent's branch:
- Read file content ONLY via:  git -C ${dir} show ${ref}:${c.file}
- Search ONLY via:            git -C ${dir} grep -n <pattern> ${ref} -- '<glob>'
- History via:                git -C ${dir} log ${ref} --oneline -8 -- ${c.file}
- NEVER run checkout, switch, stash, or any write operation. Never edit files.
- Be cheap: a handful of commands, then decide. "unclear" is an acceptable answer.
`
}

const LENS_TASK = {
  techdebt: () => `The lens flagged high churn × high complexity. Decide whether this is debt worth
premium-model attention: skim the file's structure, check recent history for a refactor that
already landed, and classify, point-fix (e.g. one god-function to split), architectural
(layering/ownership problem), or false-positive (complexity is inherent/generated/test-fixture).`,

  security: () => `The lens flagged attack-surface reach × vuln-likelihood patterns. Verify each flagged
pattern still exists on ${ref} (e.g. grep for raw SQL execution, string-interpolated SQL, missing auth
dependencies), and note mitigations you can SEE (parameterization, an auth dependency on the route,
tenancy/row-level-security context). This is a security row: your verdict annotates, it will never
discard the row, so be precise about what is and isn't there.`,

  deadcode: () => `The lens claims this file or symbol is unreferenced. Verify with git grep against
${ref}: direct imports, string-based/dynamic references (getattr, registry dicts, framework
dependency wiring, database migrations, package re-exports, tests, config strings). Only verdict
delete-candidate on ZERO references beyond the definition itself; any dynamic-use doubt =
false-positive or unclear.`,

  drift: () => `The lens flagged a copy-paste clone group that has diverged. Read every member function
listed in the lens detail (git show the files, find the named functions). Judge: are they truly
siblings? Did they diverge in behavior-relevant ways, especially a bugfix or guard applied to one
but not the other? klass: point-fix if one-side backport, architectural if they should be unified,
false-positive if divergence is intentional/domain-driven.`,

  'v2-riser': (c) => {
    const gh = ghRepoFor(c.target)
    const issueStep = gh
      ? `run  gh issue list -R ${gh} --state open --search "<file basename>" --limit 5 --json number,title  and`
      : `no issue tracker is configured for this target, so skip the issue lookup and`
    return `Open-issue/incident evidence promoted this file's rank. Check whether the concern is
still live: ${issueStep} check recent commits to the file for a fix that already landed.
Issues stay open after work ships, an open issue alone does not prove work is undone.`
  },
}

phase('Triage')
log(`Triaging ${candidates.length} candidates from ${new Set(candidates.map(c => c.lens)).size} lenses against ${ref} (${MODEL}, effort ${EFFORT})`)

const results = await parallel(candidates.map((c) => () =>
  agent(
    COMMON(c) + '\n' + (LENS_TASK[c.lens] ? LENS_TASK[c.lens](c) : '') +
    (c.symbol ? `\nTarget symbol: ${c.symbol}` : '') +
    (c.group ? `\nClone group members: ${JSON.stringify(c.group)}` : ''),
    {
      label: `${c.lens}:${c.file.split('/').pop()}${c.symbol ? ':' + c.symbol : ''}`,
      phase: 'Triage',
      model: MODEL,
      effort: EFFORT,
      schema: VERDICT,
    }
  ).then(v => ({ ...c, verdict: v }))
))

const done = results.filter(Boolean)
const counts = {}
for (const r of done) counts[r.verdict.status] = (counts[r.verdict.status] || 0) + 1
log(`Done: ${done.length}/${candidates.length} verdicts, ${JSON.stringify(counts)}`)

return { verdicts: done, ref, failed: candidates.length - done.length }
