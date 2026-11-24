/**
 * Guard: this repository is public and its history starts here. No tracked file, and no
 * tracked file NAME, may carry either of the two names the package was developed under.
 * There is no allowlist. The words are built from fragments so this file does not contain
 * them itself. (The wider list of names a public file must never carry is held by a private
 * check, and `tests/privateNames.test.ts` covers what this repository can state publicly.)
 */
import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { trackedFiles } from '../tools/private-scan';

const ROOT = path.resolve(__dirname, '..');
const LEAK = new RegExp([['pri', 'sm'].join(''), ['cor', 'tex'].join('')].join('|'), 'i');

describe('no former name appears anywhere', () => {
  const tracked = trackedFiles(ROOT);

  it('checks a non-trivial set of tracked files (non-vacuity)', () => {
    expect(tracked.length).toBeGreaterThan(50);
  });

  it('has no tracked path containing a former name', () => {
    expect(tracked.filter((f) => LEAK.test(f))).toEqual([]);
  });

  it('has no tracked file (text or binary, lockfile included) containing a former name', () => {
    const hits = tracked.filter((f) => {
      const p = path.join(ROOT, f);
      return fs.existsSync(p) && LEAK.test(fs.readFileSync(p).toString('latin1'));
    });
    expect(hits, hits.join('\n')).toEqual([]);
  });

  it('would notice one (the detector is live)', () => {
    expect(LEAK.test('x' + ['cor', 'tex'].join('').toUpperCase() + 'y')).toBe(true);
  });
});
