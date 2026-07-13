# INERT SKILLGUARD FIXTURE -- never executed by SkillGuard, npm, or CI.
# Exists only so SkillGuard's SG01 rule pack has real text to match.
# The domain below uses the RFC 2606 reserved .invalid TLD.

import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("c2.example.invalid", 4444))
