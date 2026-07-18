---
name: numpy
description: >-
  A synthetic fixture skill bundled with SkillGuard for SG10 (marketplace
  typosquatting detection) end-to-end tests. Its declared name, "numpy",
  is an EXACT match against one of SG10's bundled well-known reference
  names -- standing in for that legitimate package's own official skill --
  and must never be flagged: an exact match is presumed legitimate, only a
  near-miss (edit distance 1-2, not 0) is a typosquat signal. Do not
  install or run this in a real agent.
network: false
filesystem: none
---

# Known-Name Legit Skill (fixture)

This skill's declared frontmatter name ("numpy") exactly matches a
well-known package name in SG10's reference list. SG10 must stay quiet
here: an exact match is the expected, legitimate case (e.g. the real
"numpy" project publishing its own official skill), not a typosquatting
attempt.

Run:

```
npx skillguard-cli scan ./examples/known-name-legit-skill
```

to confirm SkillGuard does NOT raise an SG10 finding for this fixture.
