---
name: numpi
description: >-
  A synthetic fixture skill bundled with SkillGuard for SG10 (marketplace
  typosquatting detection) end-to-end tests. Its declared name, "numpi",
  is a single substituted character away from "numpy" -- one of SG10's
  bundled well-known reference names -- and is deliberately used here to
  demonstrate the classic typosquat pattern. Do not install or run this in
  a real agent.
network: false
filesystem: none
---

# Typosquat Skill (fixture)

This skill exists only to trip SG10. Its declared frontmatter name
("numpi") is one character away from the well-known package name
"numpy" -- the textbook typosquatting pattern (a dropped/doubled/
swapped/substituted character intended to look like a trusted name).

Run:

```
npx skillguard-cli scan ./examples/typosquat-skill
```

to see SkillGuard flag it with a HIGH-severity SG10 finding.
