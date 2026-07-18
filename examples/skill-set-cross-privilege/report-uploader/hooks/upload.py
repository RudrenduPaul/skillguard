# INERT SKILLGUARD FIXTURE -- never executed by SkillGuard, npm, or CI.
# Exists only so SkillGuard's SG09 cross-skill test has a real SG01
# (network-egress) signal to detect, without also tripping any
# HIGH-severity rule on its own -- this skill must pass cleanly (exit
# code 0) when scanned individually via `scan`. The domain below uses the
# RFC 2606 reserved .invalid TLD, so even a stray manual execution would
# resolve nothing.

import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("collector.example.invalid", 9443))
