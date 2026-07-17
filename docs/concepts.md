# Concepts

## The scan pipeline

Both the npm and PyPI packages run the same pipeline (TypeScript:
`src/scan/index.ts`; Python: `skillguard/scan/index.py`):

```
target path
     |
     v
.skillguardignore loaded  -> ignore globs (+ warnings for invalid lines).
     |                       Only loaded when the caller explicitly supplies
     |                       a path -- never auto-derived from inside the
     |                       (untrusted) scan target.
     v
walker                     -> SKILL.md path, scannable files, unscanned files
     |
     v
rule-pack loader            -> loaded packs (invalid packs skipped + warned,
     |                          never a hard failure)
 +---+-----------------------------+
 v                                 v
pattern engine (SG01-06,       structural module (SG07: declared vs
partial SG05), per-file        actual scope, read-only)
timeout enforced
 |                                 |
 +-----------------+---------------+
                    v
           inline suppression filter (# skillguard-ignore: SGxx),
           off by default -- opt in via --allow-inline-suppression
                    v
           severity threshold -> exit code (0 clean / 1 fail / 2 error)
```

A `ScanResult` (TypeScript) / `ScanResult` dataclass (Python) always comes
back as a structured value, never a thrown exception, so a caller embedding
SkillGuard as a library gets a consistent contract regardless of what went
wrong during the scan itself (a bad rule pack, an unreadable file, an empty
target) -- those become `warnings`, not crashes.

## Severity taxonomy

| Severity | Meaning |
| --- | --- |
| HIGH | Confirmed executable impact: the pattern is a direct path to running attacker-influenced code, or exfiltrating a credential. |
| MEDIUM | A declared-scope violation without a confirmed exploit path (e.g. a raw socket that *could* be used for C2, but isn't confirmed to be). |
| LOW | Best-effort, higher-false-negative-rate detection -- currently only SG05 (obfuscated payloads). |

The default `--severity-threshold` is `HIGH`: only HIGH findings fail a
scan (exit code 1) unless you lower the threshold explicitly.

## The seven rule packs

Each pack is a directory with a `pack.json` manifest plus (for "pattern"
packs) a `rules.yml` file of regex rules scoped to one or more of the four
supported languages (JavaScript/TypeScript, Python, shell). SG07 is the one
"structural" pack -- its logic needs a parsed view of both SKILL.md and the
script set together, not a single-file pattern match, so it ships as core
code rather than a rules file.

### SG01 -- network mismatch (MEDIUM)

Flags raw/low-level network primitives that bypass a skill's typical
HTTP-only scope: Python's `socket.socket()`, Node's `net.connect`/
`dgram.createSocket`, direct `nc`/`ncat`/`netcat` invocation, and bash's
`/dev/tcp/host/port` pseudo-device redirection (a classic dependency-free
reverse-shell technique). These are rarely needed by a legitimate skill and
are a common building block for a covert command-and-control channel.

### SG02 -- remote code execution (HIGH)

Flags confirmed executable-impact patterns: `curl`/`wget` piped directly
into `bash`/`sh`/`zsh`; `eval()`/`exec()` of a Python `requests`/`urlopen`
response; `eval()`/`Function()` of a fetched JS response body;
`child_process.exec`/`execSync` invoked with a variable that looks
populated from network data; and `os.system()`/`subprocess` calls combined
with a `curl`/`wget` download in the same command. Every one of these hands
network-controlled content directly to an interpreter or shell with no
verification step.

### SG03 -- file-scope escalation (MEDIUM)

Flags writes, deletes, or permission changes reaching outside a skill's own
working directory: `rm -rf` targeting a system path (`/etc`, `/usr`,
`/home`, `~`), `chmod 777` (or similarly permissive) on a system path,
`fs.writeFile`/`open(..., "w")` targeting an absolute system path
(`/etc`, `~/.ssh`, `~/.aws`), and repeated `../` path-traversal segments.

### SG04 -- hook supply-chain (HIGH)

Flags install-time hooks or dependency declarations that fetch and execute
remote code, or pin to a mutable reference instead of a fixed version:
a `postinstall`/`preinstall` hook that downloads and runs a script,
`pip install git+https://...` without a pinned commit SHA, `npm install
pkg.git#main` (or `#master`/`#head`/`#latest`), and `require()`/`import()`
of a bare `https://` URL. Install-time hooks run automatically and silently
for every consumer of a skill, making this category a supply-chain
compromise vector specifically.

### SG05 -- obfuscated payloads (LOW)

Flags known obfuscation idioms used to hide a payload from plain-text
review: a base64-decoded string passed into `eval()`/`exec()`/`Function()`,
a `String.fromCharCode()`/`chr()` reassembly chain, chained string
concatenation feeding into `eval()`/`exec()`, and the `Function()`
constructor used to build a function from a runtime-assembled string.

**Documented limitation, not an oversight**: this category has a
materially higher false-negative rate than the other six under pure static
analysis. Obfuscation techniques evolve faster than any fixed regex list,
and a sufficiently determined author can always reshape a payload to slip
past pattern matching. SG05's findings are scored LOW specifically to
reflect that lower confidence honestly rather than overstating it. A
behavioral sandbox-diff would catch more but is out of scope for the
current architecture (both CLIs are static analyzers that never execute
scan-target content).

### SG06 -- credential harvesting (HIGH)

Flags reads of credential-shaped environment variables (matching
`KEY`/`SECRET`/`TOKEN`/`PASSWORD`/`CREDENTIAL`/`PRIVATE` in the name) or
well-known credential files (`~/.ssh/id_rsa` and friends, `~/.aws/credentials`,
a `service-account*.json` key), and a dedicated rule for a credential-shaped
variable appearing in the same statement as an outbound network call
(`curl`/`fetch`/`requests`/`axios`) -- a direct exfiltration pattern.

### SG07 -- frontmatter spoofing (MEDIUM)

The one structural pack: parses SKILL.md's YAML frontmatter for its
declared scope --

```yaml
---
name: my-skill
network: false          # does this skill need network access?
filesystem: none        # "none" | "read-only" | "read-write"
---
```

-- then compares it against the *actual* behavior implied by the skill's
hooks/scripts (a read-only, evidence-gathering pass: it looks for network-
call idioms and filesystem-write idioms in the script content, never
executes anything). A mismatch -- the script does more than what's
declared -- produces a MEDIUM finding citing the exact file and line the
undeclared behavior was found on. This is the mechanism that catches a
skill lying about its own permission scope, as distinct from SG01-SG06
which flag suspicious patterns regardless of what the skill claims about
itself.

## Verdict model: findings, warnings, and exit codes

- **Findings** are specific, file:line-cited matches against a rule. They
  carry a `ruleId`, `category` (SG01-SG07), `severity`, `message`, `file`,
  `line`, and an optional `snippet` (the matched text, truncated to 200
  characters).
- **Warnings** are scan-level diagnostics that are *not* about the scan
  target's content -- a skipped invalid rule pack, an unreadable
  `.skillguardignore`, a target path that doesn't exist. They never
  silently fail the whole scan; a bad rule pack is skipped with a warning
  and the remaining valid packs still run.
- **Exit code** is derived from findings only, compared against
  `--severity-threshold`: `0` if no surviving finding meets the threshold,
  `1` if at least one does, `2` for a target/config-level error (before any
  rule ever runs).

## Suppression: two mechanisms, both off by default

**Trust model**: SkillGuard's job is to vet directories you did *not*
write. Both suppression mechanisms below can silence a finding, so neither
is ever trusted automatically from inside the thing being scanned -- each
requires an explicit, deliberate opt-in from whoever runs the scan.

- **`.skillguardignore`** -- a glob-based path suppression file, same
  mental model as `.gitignore`. Only honored when you pass
  `--skillguardignore <path>` (CLI) or `ignoreFilePath`/`ignore_file_path`
  (library). Never auto-loaded from inside the scan target.
- **Inline `# skillguard-ignore: SGxx`** comments, on the same line as a
  match or the line directly above it. Only honored with
  `--allow-inline-suppression` (CLI) or `allowInlineSuppression`/
  `allow_inline_suppression` (library) set. Off by default because the
  comment lives inside the exact untrusted content being vetted.

Both mechanisms exist for the legitimate self-scan case -- an author
suppressing known false positives in their own skill pre-publish -- they
just require deliberate action rather than being auto-trusted.
