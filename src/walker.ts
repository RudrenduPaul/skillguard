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

function collectAllFiles(root: string, dir: string, out: string[]): void {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (ALWAYS_IGNORED_DIRS.has(entry.name)) continue;
      collectAllFiles(root, path.join(dir, entry.name), out);
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
  collectAllFiles(absTarget, absTarget, allFiles);

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

  return { skillMdPath, files, unscannedFiles };
}
