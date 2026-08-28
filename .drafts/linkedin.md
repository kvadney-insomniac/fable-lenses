# LinkedIn draft — fable-lenses

## Option A — the targeting framing (recommended)

Coding agents will happily read your entire codebase. That's the problem.

Context is the scarce resource, and an agent left to roam spends it discovering
where to work instead of working. So I stopped asking the expensive model where
to look, and started telling it.

The result is a set of deterministic "lenses" I've now open-sourced. Each scores
every file on impact × opportunity:

• impact = git churn — exact, straight from history. No tokens spent estimating
  what the repo already knows.
• opportunity = real complexity — cyclomatic and nesting depth via Python's ast,
  a line-and-branch heuristic for TS/JS.

Each axis becomes a 1–5 quintile bucket within the repo, multiplied to 1–25.
Low buckets get discarded. What survives is a ranked list to point a premium
model at.

Churn × complexity isn't new — Michael Feathers wrote about turbulence years
ago, and CodeScene productized hotspots. What I think is new is treating it as
an aiming problem for model attention, and the lenses I ended up needing:

• drift — copy-pasted logic that then DIVERGED. This one earns its keep. It
  normalizes tokens (identifiers → ID, literals → LIT) so rename-only clones
  collapse, then flags pairs whose similarity is high but below 1.0. That band
  is where one copy got a bug fix and its siblings quietly didn't. Nothing
  fails. The copies just disagree, and only under the inputs the fix was about,
  which is exactly why it survives review.
• dead code, security reach, architectural coupling, CI failure rate

Two things I'd tell anyone building something similar:

1. Validate before you trust it. Run it and check the top tier reproduces the
   hot spots you already know about. If the files you'd have named yourself
   don't surface unprompted, your weighting is wrong — fix that before you
   dispatch anything.

2. Add a cheap verification tier. My recorded failure mode wasn't bad ranking,
   it was staleness: targets already fixed before anyone looked. Verifying by
   hand burns premium time on exactly the work a cheap model does well. So it's
   a funnel — free deterministic ranking, cheap model verifies, expensive model
   only ever sees survivors.

One rule I'd keep in any version of this: cheap models don't get to bury
security findings. They're annotate-only. A false discard on an auth issue is
invisible; a false pass costs one expensive look. The asymmetry decides it.

MIT, Python stdlib + Node. Extracted from a private codebase, so the honest
caveat is that it's been run in anger on a handful of repos, not hundreds.

https://github.com/kvadney-insomniac/fable-lenses

---

## Option B — shorter, story-first

I asked a coding agent to improve a codebase. It spent most of its context
figuring out where to start.

That's backwards. Deciding where to look is cheap and deterministic. Doing the
work is expensive and needs judgment. So I split them.

Open-sourced the result today: lenses that score every file on impact ×
opportunity — git churn (exact, from history) × real complexity (via ast) —
bucket each axis 1–5 by quintile within the repo, and throw away everything
low. What's left is a ranked list you point the expensive model at.

The one I didn't expect to need most: a drift lens. It finds code that was
copy-pasted and then diverged — where one copy got a fix and the others didn't.
Nothing fails when that happens. The copies just disagree, under exactly the
inputs the fix was about. That's why it survives review and testing.

Hard-won lesson: the failure mode isn't bad ranking, it's staleness. Half of
what a good lens finds is already fixed. So there's a cheap-model verification
tier between the ranking and the expensive work — false positives die cheap.

MIT. Run it on your repo and check the top of the list is where you'd have
pointed yourself. If it isn't, don't trust it yet.

https://github.com/kvadney-insomniac/fable-lenses

---

## Option C — the comparative framing, done honestly (use this if you want the CodeScene reference point)

Behavioral code analysis has been around for a decade. Adam Tornhill's
"Your Code as a Crime Scene" and CodeScene ask a good question: where does this
codebase actually hurt? Churn against complexity, hotspots, knowledge maps.

I needed a narrower thing, for a reason that didn't exist when that work
started: where should I point an expensive model.

Those aren't the same question. CodeScene tells a human where the debt is —
continuously, with trend lines, a hosted UI, and PR gating. I wanted a ranked
list to hand an agent at the start of a session, so it spends its context doing
the work instead of discovering where the work is.

So: twelve scripts, MIT, Python stdlib and Node, no service. Each scores every
file on impact x opportunity — git churn (exact, from history; no tokens spent
estimating what the repo already knows) times real complexity (cyclomatic and
nesting via ast for Python, a line-and-branch heuristic for TS/JS). Each axis
buckets 1-5 by quintile within the repo, multiplied to 1-25. Low buckets get
discarded. What survives is the aim point.

To be clear about what this is not: no UI, no trend tracking, no PR
integration, two language families, and nothing resembling CodeScene's
validated Code Health metric. If you want a product, buy the product. This is a
targeting layer you can read in an afternoon and modify for your own repo.

The lens I didn't expect to need most: drift. It finds code that was copy-pasted
and then DIVERGED — normalize tokens so rename-only clones collapse, then flag
pairs whose similarity is high but below 1.0. That band is where one copy got a
bug fix and its siblings quietly didn't. Nothing fails. The copies just
disagree, under exactly the inputs the fix was about, which is why it survives
review and testing.

Two things I'd tell anyone building something similar:

Validate before you trust it. Run it and check the top tier reproduces hot spots
you already know. If the files you'd have named yourself don't surface
unprompted, the weighting is wrong.

Add a cheap verification tier. The failure mode isn't bad ranking, it's
staleness — targets already fixed before anyone looked. So it's a funnel: free
deterministic ranking, cheap model verifies, expensive model only sees
survivors. And cheap models don't get to bury security findings; those are
annotate-only. A false discard on an auth issue is invisible, a false pass costs
one expensive look.

Run it on your repo. If the top of the list isn't where you'd have pointed
yourself, don't trust it yet.

https://github.com/kvadney-insomniac/fable-lenses

---

## Why NOT to post it as "free open source CodeScene"

Tempting, and it would get reach. It would also be the one framing that costs
you, for three reasons:

1. **You lose the comparison you invited.** CodeScene has a hosted UI, PR-time
   gating, continuous trend tracking, 30+ languages, an IDE plugin, and Code
   Health — a validated composite metric with published research behind it. You
   have twelve CLI scripts, two language families, point-in-time, no UI, no CI
   integration. The first commenter who has used CodeScene will list exactly
   that, in public, and the good ideas here get buried under "it's not really
   that."

2. **It borrows credibility instead of building it.** Tornhill spent a decade on
   behavioral code analysis. Framing an extractable toolkit as his product's
   open-source equivalent reads as trading on his name — a bad look in a small
   field where he is well known and active.

3. **You do not need it.** "Tells a model where to work" is a category nobody
   else is claiming, and it is true. Own that and you rank first in your own
   category instead of a distant second in his.

Reference the lineage, do not claim the mantle. Option C above shows the line.

---

## Notes before you post

- The repo has no stars, no CI badge, and one contributor. That's fine — but
  expect "how is this different from CodeScene / SonarQube?" Honest answer:
  those are products that judge code; this is a targeting layer that ranks
  attention and hands off to a model. Worth having that reply ready.
- Don't claim it's battle-tested at scale. It's been run against a handful of
  repos. Option A says so explicitly; keep that line.
- If you want engagement over reach, end on a question — "what would you point
  a lens at?" — but it reads as engagement-bait to some audiences. Your call.
- Consider posting the drift lens as its own follow-up. It's the most
  independently interesting idea here and doesn't need the rest as setup.
