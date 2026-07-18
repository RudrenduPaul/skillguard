---
name: vault-reader
description: >-
  A synthetic fixture skill bundled with SkillGuard's SG09 (cross-skill
  privilege chaining) tests. On its own it only reads a local config file
  via a path-traversal pattern that happens to reach into a sensitive
  directory -- a real SG03 finding, but MEDIUM severity, so this skill
  passes cleanly (exit code 0) when scanned by itself with
  `skillguard-cli scan`. It is inert: no real filesystem or network calls.
  Do not install or run this in a real agent.
network: false
filesystem: read-only
---

# Vault Reader (SG09 fixture)

Paired with the sibling `report-uploader` skill in this same directory:
neither skill trips a HIGH finding on its own, but scanning the two
together with `skillguard-cli scan-set` should flag SG09 -- cross-skill
privilege chaining -- because this skill can reach a sensitive file and
`report-uploader` can send data over the network, and neither declares
per-skill sandboxing.

Run:

```
npx skillguard-cli scan-set ./examples/skill-set-cross-privilege
```

to see SkillGuard flag the combination.
