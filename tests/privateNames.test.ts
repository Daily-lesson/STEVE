/**
 * Private-name scan (tools/private-scan.ts): the repository is public, so the names it must
 * never carry are held as sha256 digests. The scan covers every tracked path and file, and
 * every commit message.
 */
import { describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { ALLOWED_STRINGS, DENY, scanCommits, scanText, scanTree } from '../tools/private-scan';

const ROOT = path.resolve(__dirname, '..');
const j = (...p: string[]): string => p.join('');

describe('private-name scan', () => {
  it('is live: each rule fires on a synthetic input built from fragments', () => {
    expect(scanText('by ' + j('sc', 'ot') + ' here').length).toBeGreaterThan(0);
    expect(scanText(j('Sc', 'ot') + 'Config').length).toBeGreaterThan(0); // camelCase
    expect(scanText(j('someone', '@', 'example.org')).length).toBeGreaterThan(0);
    expect(scanText(j('WO', '-', '999')).length).toBeGreaterThan(0);
    expect(DENY.size).toBeGreaterThanOrEqual(7);
  });

  it('refuses a person in author, committer and tag fields of a scratch repository', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'steve-scan-'));
    const git = (...a: string[]): string => execFileSync('git', a, { cwd: dir, encoding: 'utf8' });
    git('init', '-q');
    fs.writeFileSync(path.join(dir, 'a.txt'), 'x');
    git('add', '.');
    const env = { ...process.env, GIT_AUTHOR_NAME: 'A', GIT_AUTHOR_EMAIL: j('a', '@', 'example.org'), GIT_COMMITTER_NAME: 'A', GIT_COMMITTER_EMAIL: 'noreply@' + 'anthropic.com' };
    execFileSync('git', ['commit', '-q', '-m', 'm'], { cwd: dir, env });
    expect(scanCommits(dir).length).toBeGreaterThan(0); // author e-mail
    execFileSync('git', ['commit', '-q', '--amend', '--reset-author', '-m', 'm'], { cwd: dir, env: { ...env, GIT_AUTHOR_EMAIL: 'noreply@' + 'anthropic.com' } });
    expect(scanCommits(dir)).toEqual([]);
    execFileSync('git', ['tag', '-a', 't', '-m', 'for ' + j('sc', 'ot')], { cwd: dir, env });
    expect(scanCommits(dir).length).toBeGreaterThan(0); // tag message
  });

  it('allows exactly the package scope and this repository address', () => {
    expect(ALLOWED_STRINGS).toEqual(['@daily-lesson/steve', 'daily-lesson/steve']);
    expect(scanText('"name": "@daily-lesson/steve"')).toEqual([]);
    expect(scanText('https://github.com/Daily-lesson/steve')).toEqual([]);
  });

  it('finds nothing in any tracked path or file', () => {
    const hits = scanTree(ROOT);
    expect(hits, hits.join('\n')).toEqual([]);
  });

  it('finds nothing in any commit message', () => {
    const hits = scanCommits(ROOT);
    expect(hits, hits.join('\n')).toEqual([]);
  });
});
