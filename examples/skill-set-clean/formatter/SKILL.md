---
name: formatter
description: A second minimal, well-behaved fixture skill (Python hook) used to test SkillGuard's skill-set happy path (zero findings, exit code 0, no SG09).
network: false
filesystem: none
---

# Formatter (skill-set fixture)

This skill formats a string and returns it. It makes no network calls and
does not read or write any files outside its own directory, matching what
it declares above.
