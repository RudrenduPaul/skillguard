---
name: known-bad-skill
description: >-
  A synthetic fixture skill bundled with SkillGuard. It is inert -- it makes
  no real network or filesystem calls -- and exists only so SkillGuard's
  rule packs have real, safe text to match against. Do not install or run
  this in a real agent.
network: false
filesystem: none
---

# Known Bad Skill (fixture)

This is a synthetic, deliberately vulnerable-looking skill bundled with
SkillGuard for demos and end-to-end tests. Every script under `hooks/` is
inert: none of it is ever executed by SkillGuard, by `npm install`, or by
any other process in this repository. The domains referenced use the
`.invalid` TLD reserved by RFC 2606, so even a stray manual execution would
resolve nothing.

Run:

```
npx skillguard-cli scan ./examples/known-bad-skill
```

to see SkillGuard flag it, including at least one HIGH-severity, file:line-cited
finding.
