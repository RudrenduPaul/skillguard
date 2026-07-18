---
name: greeter
description: A minimal, well-behaved fixture skill used to test SkillGuard's skill-set happy path (zero findings, exit code 0, no SG09).
network: false
filesystem: none
---

# Greeter (skill-set fixture)

This skill only prints a greeting. It makes no network calls and does not
read or write any files outside its own directory, matching what it
declares above.
