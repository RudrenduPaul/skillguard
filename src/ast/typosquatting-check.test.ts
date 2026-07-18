import { describe, it, expect } from 'vitest';
import {
  parseDeclaredName,
  levenshteinDistance,
  findTyposquatMatches,
  loadKnownNames,
} from './typosquatting-check';

describe('ast/typosquatting-check', () => {
  describe('parseDeclaredName', () => {
    it('extracts the declared name and its line number', () => {
      const content = '---\nname: numpi\nnetwork: false\n---\nbody\n';
      const declared = parseDeclaredName(content);
      expect(declared).toEqual({ name: 'numpi', line: 2 });
    });

    it('returns null when there is no frontmatter block', () => {
      expect(parseDeclaredName('# just a heading\n')).toBeNull();
    });

    it('returns null when no name field is declared', () => {
      const content = '---\nnetwork: false\nfilesystem: none\n---\nbody\n';
      expect(parseDeclaredName(content)).toBeNull();
    });

    it('returns null for an empty name field', () => {
      const content = '---\nname: ""\n---\nbody\n';
      expect(parseDeclaredName(content)).toBeNull();
    });

    it('returns null for malformed YAML frontmatter', () => {
      const content = '---\nname: [unterminated\n---\nbody\n';
      expect(parseDeclaredName(content)).toBeNull();
    });
  });

  describe('levenshteinDistance', () => {
    it('is 0 for identical strings', () => {
      expect(levenshteinDistance('numpy', 'numpy')).toBe(0);
    });

    it('counts a single substitution as distance 1', () => {
      expect(levenshteinDistance('numpy', 'numpi')).toBe(1);
    });

    it('counts insertions/deletions correctly', () => {
      expect(levenshteinDistance('flask', 'flasky')).toBe(1);
      expect(levenshteinDistance('', 'abc')).toBe(3);
      expect(levenshteinDistance('abc', '')).toBe(3);
    });

    it('handles fully unrelated strings', () => {
      expect(levenshteinDistance('numpy', 'zzzzz')).toBe(5);
    });
  });

  describe('findTyposquatMatches', () => {
    const knownNames = ['numpy', 'requests', 'flask', 'django'];

    it('flags a near-miss (edit distance 1-2) as a typosquat match', () => {
      const matches = findTyposquatMatches('numpi', knownNames);
      expect(matches).toEqual([{ knownName: 'numpy', distance: 1 }]);
    });

    it('does not flag an exact match', () => {
      expect(findTyposquatMatches('numpy', knownNames)).toEqual([]);
      expect(findTyposquatMatches('NumPy', knownNames)).toEqual([]); // case-insensitive exact match
    });

    it('does not flag an unrelated name', () => {
      expect(findTyposquatMatches('zzzxyzzy12345', knownNames)).toEqual([]);
    });

    it('does not flag short names even at edit distance 1', () => {
      expect(findTyposquatMatches('cat', ['car', 'cap'])).toEqual([]);
    });
  });

  describe('loadKnownNames', () => {
    it('loads the real bundled seed list', () => {
      const names = loadKnownNames();
      expect(names.length).toBeGreaterThan(0);
      expect(names).toContain('numpy');
    });

    it('fails soft (returns an empty list) for a missing file', () => {
      expect(loadKnownNames('/nonexistent/known-names.json')).toEqual([]);
    });
  });
});
