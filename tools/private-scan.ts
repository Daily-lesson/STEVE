/**
 * Private-name scan. This repository is public, so the scan holds only what an existing public
 * precedent already holds: word digests (sha256, first 16 hex) of a person's name and its
 * spellings, a mail host and two database project refs. The fuller list of names this
 * repository must never carry is checked by a private script that is not published here.
 *
 * A text is split into word tokens (letters+digits; with "_"; with "_" and "-"; with "_", "-"
 * and "."; and camelCase words), and every token is hashed and looked up. Separate rules refuse
 * an e-mail address and a work-order id. The one legitimate use of the organisation name is the
 * npm scope and this repository's own address; exactly those strings are removed first.
 *
 * Run as a script (`npx tsx tools/private-scan.ts`) it scans every tracked file's path and
 * bytes plus every commit message, author and committer, and every tag message, and exits 1
 * on any hit.
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

export const DENY: ReadonlySet<string> = new Set([
  'ccb71b663e383032', '3fe52df0c21fa28f', 'ea5e5cdbccb765e0', 'a67f8eb35b59c847',
  '576ba7c2e4abb718', '5ecec73dd71edcbb', '7772e1e25e61f131',
]);

/** Exactly these strings may contain the organisation name. Nothing else may. */
export const ALLOWED_STRINGS: readonly string[] = ['@daily-lesson/steve', 'daily-lesson/steve'];

const EMAIL_RE = /[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+/i;
const WO_RE = /\bwo-\d+\b/i;
const sha = (s: string): string => createHash('sha256').update(s).digest('hex').slice(0, 16);
const TOKENIZERS: readonly RegExp[] = [/[a-z0-9]+/g, /[a-z0-9_]+/g, /[a-z0-9_-]+/g, /[a-z0-9_.-]+/g];

/** Returns human-readable reasons (never the offending term itself, which would republish it). */
export function scanText(text: string): string[] {
  let orig = text;
  for (const a of ALLOWED_STRINGS) orig = orig.replace(new RegExp(a.replace(/[/.]/g, '\\$&'), 'gi'), ' ');
  const t = orig.toLowerCase();
  const hits: string[] = [];
  const seen = new Set<string>();
  const check = (tok: string): void => {
    if (!tok || seen.has(tok)) return;
    seen.add(tok);
    if (DENY.has(sha(tok))) hits.push('denied term (' + tok.length + ' chars)');
  };
  const camel = orig.match(/[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])/g) || [];
  for (const w of camel) check(w.toLowerCase());
  for (const re of TOKENIZERS) {
    for (const m of t.matchAll(re)) {
      check(m[0].replace(/^[-_.]+|[-_.]+$/g, ''));
    }
  }
  const em = EMAIL_RE.exec(t);
  if (em) hits.push('an e-mail address shape');
  if (WO_RE.test(t)) hits.push('a work-order id');
  return hits;
}

export function trackedFiles(root: string): string[] {
  try {
    const out = execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8', maxBuffer: 1 << 28 });
    const files = out.split('\0').filter(Boolean);
    if (files.length) return files;
  } catch { /* not a git checkout: walk */ }
  const res: string[] = [];
  const skip = new Set(['node_modules', '.git', 'build', '.vitest', '__pycache__', '.venv']);
  const walk = (d: string): void => {
    for (const e of fs.readdirSync(path.join(root, d), { withFileTypes: true })) {
      const rel = path.join(d, e.name);
      if (e.isDirectory()) { if (!skip.has(e.name)) walk(rel); } else res.push(rel);
    }
  };
  walk('');
  return res;
}

/** Every tracked file: its path and its bytes. */
export function scanTree(root: string): string[] {
  const problems: string[] = [];
  for (const f of trackedFiles(root)) {
    for (const h of scanText(f)) problems.push(f + ' (path): ' + h);
    const p = path.join(root, f);
    if (!fs.existsSync(p)) continue;
    const text = fs.readFileSync(p).toString('latin1');
    for (const h of scanText(text)) problems.push(f + ': ' + h);
  }
  return problems;
}

const NO_REPLY = '<noreply@' + 'anthropic.com>';
const NO_REPLY_BARE = 'noreply@' + 'anthropic.com';

export function scanCommits(root: string): string[] {
  let msgs = '';
  try { msgs = execFileSync('git', ['log', '--all', '--format=%an%n%ae%n%cn%n%ce%n%B%x00'], { cwd: root, encoding: 'utf8' }); }
  catch { return []; }
  let tags = '';
  try { tags = execFileSync('git', ['for-each-ref', 'refs/tags', '--format=%(refname)%0a%(taggername)%0a%(taggeremail)%0a%(contents)%00'], { cwd: root, encoding: 'utf8' }); }
  catch { /* no tags */ }
  // The attribution no-reply address is the one e-mail a commit may carry.
  return (msgs + tags).split('\0').map((m) => m.split(NO_REPLY).join('').split(NO_REPLY_BARE).join('')).flatMap((m, i) => scanText(m).map((h) => 'commit #' + i + ': ' + h));
}

if (require.main === module) {
  const root = path.resolve(__dirname, '..');
  const problems = [...scanTree(root), ...scanCommits(root)];
  if (problems.length) { console.error(problems.join('\n')); process.exit(1); }
  console.log('private-name scan: clean');
}
