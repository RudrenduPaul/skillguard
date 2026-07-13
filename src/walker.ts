import * as fs from 'node:fs';
import * as path from 'node:path';
import { minimatch } from 'minimatch';

/**
 * File discovery: finds SKILL.md plus hooks/scripts under a target path, then
 * applies .skillguardignore glob suppression. v0.1 supported script languages
 * are JavaScript/TypeScript, Python, and shell (the languages the bundled
 * pattern rule packs have coverage for). Anything else found under a
 * hooks/ or scripts/ directory is reported as "unscanned" rather than
 * silently dropped.
 */

const ALWAYS_IGNORED_DIRS = new Set(['.git', 'node_modules', '.skillguard-cache']);

export type SupportedLanguage = 'javascript' | 'typescript' | 'python' | 'shell';

const EXTENSION_LANGUAGE: Record<string, SupportedLanguage> = {
  '.js': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.jsx': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.py': 'python',
  '.sh': 'shell',
  '.bash': 'shell',
  '.zsh': 'shell',
};

/** Directories whose contents are treated as hooks/scripts even without a recognized extension. */
const SCRIPT_ROLE_DIRS = new Set(['hooks', 'scripts']);

export interface ScannableFile {
  /** Absolute path on disk. */
  absPath: string;
  /** Path relative to the scan target, used in output. */
  relPath: string;
  language: SupportedLanguage;
}

export interface WalkResult {
  skillMdPath: string | null;
  files: ScannableFile[];
  /** Files under a hooks/scripts role directory with an unrecognized language. */
  unscannedFiles: string[];
}

function collectAllFiles(root: string, dir: string, out: string[], symlinks: string[]): void {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    // BUGFIX (security completeness gap): fs.Dirent#isDirectory() and
    // #isFile() both check the dirent's OWN type without following a
    // symlink -- for a symlink entry, both return false. The previous
    // version of this loop had no symlink branch, so a symlink anywhere
    // under the scan target (e.g. hooks/setup.sh -> /elsewhere/payload.sh)
    // was silently invisible: not scanned, not even reported in
    // unscannedFiles, contradicting this walker's own documented "never
    // silently dropped" principle and giving a trivial scanner-evasion
    // vector for a tool whose entire job is scanning untrusted third-party
    // content. This deliberately does NOT resolve/follow the symlink (doing
    // so safely requires deciding a real security policy -- containment
    // within the target tree, cycle detection -- flagged separately as
    // needing a design decision, not guessed at here). It only makes the
    // symlink's existence visible instead of invisible.
    if (entry.isSymbolicLink()) {
      symlinks.push(path.join(dir, entry.name));
      continue;
    }
    if (entry.isDirectory()) {
      if (ALWAYS_IGNORED_DIRS.has(entry.name)) continue;
      collectAllFiles(root, path.join(dir, entry.name), out, symlinks);
    } else if (entry.isFile()) {
      out.push(path.join(dir, entry.name));
    }
  }
}

function isUnderScriptRoleDir(relPath: string): boolean {
  const segments = relPath.split(path.sep);
  return segments.slice(0, -1).some((segment) => SCRIPT_ROLE_DIRS.has(segment));
}

/**
 * Walks `targetDir`, applies `ignoreGlobs` (already-parsed .skillguardignore
 * patterns) against paths relative to targetDir, and classifies each
 * surviving file as SKILL.md, a scannable script, or unscanned.
 */
export function walk(targetDir: string, ignoreGlobs: string[] = []): WalkResult {
  const absTarget = path.resolve(targetDir);
  const allFiles: string[] = [];
  const symlinks: string[] = [];
  collectAllFiles(absTarget, absTarget, allFiles, symlinks);

  let skillMdPath: string | null = null;
  const files: ScannableFile[] = [];
  const unscannedFiles: string[] = [];

  for (const absPath of allFiles) {
    const relPath = path.relative(absTarget, absPath).split(path.sep).join('/');

    if (ignoreGlobs.some((glob) => minimatch(relPath, glob, { dot: true }))) {
      continue;
    }

    const base = path.basename(absPath);
    if (base.toUpperCase() === 'SKILL.MD') {
      skillMdPath = absPath;
      continue;
    }

    const ext = path.extname(absPath).toLowerCase();
    const language = EXTENSION_LANGUAGE[ext];
    if (language) {
      files.push({ absPath, relPath, language });
    } else if (isUnderScriptRoleDir(relPath)) {
      unscannedFiles.push(relPath);
    }
  }

  // Symlinks are never followed (see collectAllFiles) but are always
  // reported as unscanned rather than silently vanishing, regardless of
  // which directory they're in -- a symlink is a security-relevant
  // evasion vector wherever it appears, not just inside hooks/scripts.
  for (const absPath of symlinks) {
    const relPath = path.relative(absTarget, absPath).split(path.sep).join('/');
    if (ignoreGlobs.some((glob) => minimatch(relPath, glob, { dot: true }))) {
      continue;
    }
    unscannedFiles.push(relPath);
  }

  return { skillMdPath, files, unscannedFiles };
}
