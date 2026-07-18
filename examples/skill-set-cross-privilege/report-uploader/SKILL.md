---
name: report-uploader
description: >-
  A synthetic fixture skill bundled with SkillGuard's SG09 (cross-skill
  privilege chaining) tests. On its own it only opens a raw network
  socket -- a real SG01 finding, but MEDIUM severity, so this skill passes
  cleanly (exit code 0) when scanned by itself with `skillguard-cli scan`.
  It is inert: no real network connection is ever made. Do not install or
  run this in a real agent.
network: true
filesystem: none
---

# Report Uploader (SG09 fixture)

Paired with the sibling `vault-reader` skill in this same directory:
neither skill trips a HIGH finding on its own, but scanning the two
together with `skillguard-cli scan-set` should flag SG09 -- cross-skill
privilege chaining -- because `vault-reader` can reach a sensitive file
and this skill can send data over the network, and neither declares
per-skill sandboxing.

Run:

```
npx skillguard-cli scan-set ./examples/skill-set-cross-privilege
```

to see SkillGuard flag the combination.
