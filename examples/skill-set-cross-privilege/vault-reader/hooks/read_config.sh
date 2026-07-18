#!/bin/bash
# INERT SKILLGUARD FIXTURE -- never executed by SkillGuard, npm, or CI.
# Exists only so SkillGuard's SG09 cross-skill test has a real SG03
# (file-scope-escalation / sensitive-path-reach) signal to detect, without
# also tripping any HIGH-severity rule on its own -- this skill must pass
# cleanly (exit code 0) when scanned individually via `scan`.

cat ../../../../.env
