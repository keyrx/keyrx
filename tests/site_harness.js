/* Minimal DOM, real renderer. Loads the site script from site/index.html,
   boots it, drives every text command IN BOTH MODES, and MEASURES the
   rendered rows - the page's width invariant broke once as arithmetic and
   once as a glyph, and both were only ever caught by measuring.

   Desktop is a 78-column grid; mobile is 42. Panel rows must measure the
   grid exactly; loose lines must fit inside it. The one exemption is the
   `cmd` class - a copyable string longer than the mobile grid (an install
   command, the donation address) that CSS soft-wraps while the text stays
   one selectable line. Those are exempt from width, never from glyphs.

   Run: node tests/site_harness.js site/index.html
   Exit 0 = every measured row obeys its mode's grid and carries no
   fallback-risk glyph. Nonzero = the failure list is on stdout. */
'use strict';
const fs = require('fs'), crypto = require('crypto');

const html = fs.readFileSync(process.argv[2] || 'site/index.html', 'utf8');
const m = html.match(/<script>([\s\S]*)<\/script>/);
if (!m) { console.error('no <script> block found'); process.exit(2); }

// Source-level invariants that the minimal DOM below cannot emulate. These
// guard the real browser semantics around the measured terminal renderer.
const sourceBad = [];
const count = re => (html.match(re) || []).length;
// This pins the exact embedded KXMono subset whose cmap was independently
// inspected: 134 encoded glyphs and one 600-unit advance for every glyph. A
// font-byte change must be accompanied by a fresh cmap/advance review instead
// of silently changing which fallback font renders a terminal cell.
const fontMatch = html.match(/src:url\(data:font\/woff2;base64,([^)]*)\)/);
if (!fontMatch) sourceBad.push('embedded KXMono font is missing');
else if (crypto.createHash('sha256').update(Buffer.from(fontMatch[1], 'base64')).digest('hex') !==
         'd309e0680ecb01faa02684947f132f72e72c0b968bbfced107bc9e3d4fb82f2a')
  sourceBad.push('embedded KXMono bytes changed without a fresh cmap/advance review');
if (/<i\b[^>]*data-c=/.test(html)) sourceBad.push('toolbar commands must be native buttons, not role=button shims');
if (count(/<button\b[^>]*data-c=/g) !== 8) sourceBad.push('expected eight native command buttons');
if (count(/<a\b[^>]*target="_blank"[^>]*rel="noopener noreferrer"/g) < 2)
  sourceBad.push('GitHub and X must be real, noopener external links');
if (/id="out"[^>]*aria-live=/.test(html)) sourceBad.push('#out must not duplicate the status live region');
if (!/id="sr"[^>]*role="status"[^>]*aria-atomic="true"/.test(html))
  sourceBad.push('the one live region must be an atomic status');
if (!/setAttribute\('role','heading'\)/.test(m[1]) || !/setAttribute\('aria-level','2'\)/.test(m[1]) ||
    !/setAttribute\('aria-label'/.test(m[1]))
  sourceBad.push('rendered panel titles must expose a clean heading name and level');
if (!/@media \(prefers-reduced-motion:reduce\)/.test(html)) sourceBad.push('reduced motion must stop cursor blinking');
if (!/\.copy:focus-visible/.test(html)) sourceBad.push('copy controls need a visible keyboard focus rule');
if (!/function copyify\([\s\S]*document\.createElement\('button'\)/.test(m[1]))
  sourceBad.push('copy targets must become native buttons');
if (/git clone github\.com\/keyrx\/keyrx/.test(html)) sourceBad.push('mobile source clone command is not a URL');
if (/real random keys|JS, real keys|real toy grind/.test(html)) sourceBad.push('browser demo must not claim it creates keys');
if (/\b\d+ tests, clippy clean|each release:|carry Sigstore provenance/.test(html))
  sourceBad.push('VERIFIED must not freeze a test count or make a blanket release-artifact claim');
if (/aria-keyshortcuts=|var FK=\{|e\.key\s*===?\s*['"]F\d/.test(html))
  sourceBad.push('the page must preserve native browser function keys');
if (/20-60x|8 clicks max|at most 8 ["']add account["'] clicks/.test(html))
  sourceBad.push('measured speed and Phantom click bounds must not be rounded into false claims');
if (/a seed will not recover it|file IS the backup/.test(html))
  sourceBad.push('backup copy must distinguish an unrelated receiving-wallet seed from keyRX recovery material');
for (const outcome of ['Suffix demo started', 'Suffix demo timed out', 'Suffix hit', 'Suffix demo stopped']) {
  if (!html.includes(outcome)) sourceBad.push(`live region must announce async outcome: ${outcome}`);
}
if (!/return startGrind\(p,ic\)/.test(m[1]) || !/C\[c\]\(arg\)!==true/.test(m[1]))
  sourceBad.push('an async grind must suppress the premature command-complete announcement');
if (!/og:image:alt/.test(html) || !/og:image:width/.test(html) || !/og:image:height/.test(html))
  sourceBad.push('social image metadata must carry alt text and dimensions');

const grindAt = m[1].indexOf('C.grind=function');
const stopAt = m[1].indexOf('C.stop=function', grindAt);
const grindSource = m[1].slice(grindAt, stopAt);
if (/grind KEYRX/.test(grindSource)) sourceBad.push('four-character browser demo must not advertise five-character KEYRX');
if (!/grind EYRX/.test(grindSource)) sourceBad.push('browser demo must carry the four-character EYRX example');
const toyAt = m[1].indexOf('function startGrind');
const toyEnd = m[1].indexOf('function stopGrind', toyAt);
const toySource = m[1].slice(toyAt, toyEnd);
if (/kv\('(path|seed|keys)'/.test(toySource)) sourceBad.push('browser demo must not invent recovery material');
if (!/no keypair, signer, seed or derivation path exists/.test(toySource))
  sourceBad.push('browser demo must state that it creates no recovery material');
const startAt = m[1].indexOf('function start(){');
const startEnd = m[1].indexOf('\n}', startAt);
const startSource = m[1].slice(startAt, startEnd);
if (/bottom\(\)/.test(startSource) || !/scr\.scrollTop=0/.test(startSource))
  sourceBad.push('initial render must open at the masthead, not the prompt');

const allElements = [];
function makeEl(tag) {
  const e = {
    tag, className: '', style: {}, dataset: {}, value: '',
    children: [], _html: '', parent: null, attrs: {},
    set innerHTML(v) { this._html = String(v); this.children = []; },
    get innerHTML() { return this._html; },
    set textContent(v) {
      this._html = String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;');
      this.children = [];
    },
    get textContent() {
      let t = this._html.replace(/<[^>]*>/g, '')
        .replace(/&lt;/g, '<').replace(/&gt;/g, '>')
        .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&');
      return t + this.children.map(c => c.textContent).join('');
    },
    appendChild(c) {
      if (c.parent) c.parent.removeChild(c);
      this.children.push(c); c.parent = this; return c;
    },
    removeChild(c) {
      const i = this.children.indexOf(c);
      if (i >= 0) { this.children.splice(i, 1); c.parent = null; }
      return c;
    },
    remove() { if (this.parent) this.parent.removeChild(this); }, focus() {}, click() {}, blur() {},
    addEventListener() {}, removeEventListener() {},
    closest() { return null; }, hasAttribute(k) { return Object.hasOwn(this.attrs, k); },
    getAttribute(k) { return Object.hasOwn(this.attrs, k) ? this.attrs[k] : null; },
    querySelector() { return null; }, querySelectorAll() { return []; },
    getBoundingClientRect() { return { width: 4680, left: 0, bottom: 20 }; },
    setAttribute(k, v) { this.attrs[k] = String(v); },
    get lastChild() { return this.children[this.children.length - 1] || null; },
    get isConnected() { return true; },
  };
  e.classList = {
    add(c) { e.className += ' ' + c; },
    remove() {}, contains() { return false; },
  };
  allElements.push(e);
  return e;
}

const ids = {};
global.document = {
  getElementById: id => (ids[id] = ids[id] || makeEl('div')),
  createElement: t => makeEl(t),
  addEventListener() {}, removeEventListener() {},
  documentElement: { clientWidth: 1200, style: { setProperty() {} } },
  body: makeEl('body'),
  hidden: false, fonts: undefined,
  querySelectorAll() { return []; },
  get activeElement() { return makeEl('div'); },
};
global.window = global;
global.matchMedia = () => ({ matches: true });   // reduced motion: boot instantly
global.addEventListener = () => {};
global.removeEventListener = () => {};
global.setInterval = () => 0;                     // clock/saver must not hold the process
// node's own navigator/performance are getter-only globals; shadow them
Object.defineProperty(global, 'navigator', { configurable: true, value:
  { clipboard: { writeText: () => ({ then: f => { if (f) f(); } }) } } });
Object.defineProperty(global, 'performance', { configurable: true, value:
  { now: () => 0 } });
global.requestAnimationFrame = () => {};
global.getComputedStyle = () => ({ paddingLeft: '8px' });
global.open = () => {};

const mockWorkers = [], createdUrls = [], revokedUrls = [];
global.Blob = class MockBlob { constructor(parts, options) { this.parts = parts; this.options = options; } };
global.URL = {
  createObjectURL() { const url = `blob:keyrx-${createdUrls.length + 1}`; createdUrls.push(url); return url; },
  revokeObjectURL(url) { revokedUrls.push(url); },
};
global.Worker = class MockWorker {
  constructor(url) {
    this.url = url; this.onmessage = null; this.posts = []; this.terminations = 0;
    mockWorkers.push(this);
  }
  postMessage(message) { this.posts.push(message); }
  terminate() { this.terminations++; }
};

eval(m[1]);

const CMDS = ['help', 'what', 'install', 'match', 'wallets', 'verified',
              'grind', 'donate', 'evm',
              ];

// The ban covers EVERY emitted line, loose ones included - checking only
// panel rows left five survivors, one of them in a panel header.
// ▀ and ▄ are IN the embedded subset since v0.2.2 - the masthead seal is drawn with them.
const banned = /[…—–“”→▟▛▎▋▁▂▃▅▆▇]/;

function measure(og, label, width, bad) {
  let rows = 0, loose = 0;
  for (const child of og.out.children) {
    if (/\bpan\b/.test(child.className)) {
      for (const r of child.children) {
        const t = r.textContent;
        rows++;
        if (t.length !== width)
          bad.push(`${label} len ${t.length} (want ${width}): ${JSON.stringify(t)}`);
        const g = t.match(banned);
        if (g) bad.push(`${label} glyph ${JSON.stringify(g[0])}: ${JSON.stringify(t)}`);
      }
    } else {
      const t = child.textContent;
      loose++;
      const g = t.match(banned);
      if (g) bad.push(`${label} glyph ${JSON.stringify(g[0])} in loose line: ${JSON.stringify(t)}`);
      if (!/\bcmd\b/.test(child.className) && t.trimEnd().length > width)
        bad.push(`${label} loose len ${t.trimEnd().length} > ${width}: ${JSON.stringify(t)}`);
    }
  }
  if (rows < 40) bad.push(`${label}: only ${rows} panel rows measured - the drive did not run`);
  return { rows, loose };
}

function assertDonateSolanaBlock(og, label, expected, bad) {
  const panels = og.out.children.filter(child => /\bpan\b/.test(child.className));
  const donate = panels.filter(panel => panel.children.some(row =>
    /^(?:DONATE|DONATE: )/.test(row.getAttribute('aria-label') || '')));
  if (donate.length !== 1) {
    bad.push(`${label} donate panel count=${donate.length}, expected 1`);
    return;
  }
  const rows = donate[0].children.map(row => {
    const text = row.textContent;
    return (text.startsWith('║') && text.endsWith('║') ? text.slice(1, -1) : text).trim();
  });
  const solana = rows.indexOf('Solana');
  const actual = solana < 0 ? [] : rows.slice(solana, solana + expected.length);
  if (JSON.stringify(actual) !== JSON.stringify(expected))
    bad.push(`${label} Solana donation block=${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`);
  if (rows.filter(row => row.includes('keyrx.sol')).length !== 1)
    bad.push(`${label} donate panel must contain exactly one keyrx.sol row`);
}

// The POST chain steps through zero-delay timeouts; measure after it drains.
setTimeout(() => {
  const og = global.__kx;
  if (!og) { console.error('window.__kx hook missing'); process.exit(2); }
  const bad = sourceBad.slice();

  if (ids.scr.scrollTop !== 0) bad.push(`initial scrollTop=${ids.scr.scrollTop}, expected 0`);
  if (og.toyOdds('EYRX', false) !== 11_316_496)
    bad.push(`EYRX odds=${og.toyOdds('EYRX', false)}, expected 11316496`);
  if (og.toyOdds('KEYRX', false) !== 656_356_768)
    bad.push(`KEYRX odds=${og.toyOdds('KEYRX', false)}, expected 656356768`);
  if (og.toyOdds('io', true) !== 3_364)
    bad.push(`case-insensitive io odds=${og.toyOdds('io', true)}, expected 3364 (I/O are not base58)`);

  // Drive the real async boundary with hostile late callbacks. Source grep
  // cannot prove that an old worker is unable to inject into a new panel.
  const snapshot = () => `${ids.out.textContent}\nSTATUS:${ids.sr.textContent}`;
  const stoppedPosts = worker => worker.posts.filter(message => message && message.cmd === 'stop').length;
  const revokeCount = url => revokedUrls.filter(value => value === url).length;
  og.mode(true);
  og.run('grind EYRX');
  const worker1 = mockWorkers.at(-1), url1 = worker1 && worker1.url;
  const late1 = worker1 && worker1.onmessage;
  if (!worker1 || typeof late1 !== 'function') bad.push('mobile grind did not create a live worker callback');
  og.runNav('what');
  if (stoppedPosts(worker1) !== 1 || worker1.terminations !== 1 || revokeCount(url1) !== 1)
    bad.push('mobile navigation did not stop, terminate and revoke worker 1 exactly once');
  if (og.grinding()) bad.push('mobile navigation left grinding=true');
  if (ids.out.textContent.includes('starting...')) bad.push('mobile navigation left a stale starting row');
  if (!ids.out.textContent.includes('stopped')) bad.push('mobile navigation did not settle the stopped demo');
  if (ids.sr.textContent !== 'what command complete')
    bad.push(`mobile navigation final status=${JSON.stringify(ids.sr.textContent)}`);
  let stable = snapshot();
  if (late1) for (const data of [
    { hit: false, tried: 20, ms: 10 },
    { timeout: true, tried: 30, ms: 90_001 },
    { hit: true, value: '1'.repeat(40) + 'EYRX', tried: 40, ms: 20 },
  ]) {
    late1({ data });
    if (snapshot() !== stable) bad.push('worker 1 injected output/status after mobile navigation');
  }

  og.run('grind ab');
  const worker2 = mockWorkers.at(-1), url2 = worker2 && worker2.url;
  const late2 = worker2 && worker2.onmessage;
  og.run('grind cd');
  const worker3 = mockWorkers.at(-1), url3 = worker3 && worker3.url;
  if (stoppedPosts(worker2) !== 1 || worker2.terminations !== 1 || revokeCount(url2) !== 1)
    bad.push('replacement grind did not stop, terminate and revoke worker 2 exactly once');
  if ((ids.out.textContent.match(/previous demo stopped/g) || []).length !== 1)
    bad.push('replacement grind did not retain exactly one settled previous-demo row');
  if ((ids.out.textContent.match(/starting\.\.\./g) || []).length !== 1 || !og.grinding())
    bad.push('replacement grind did not leave exactly one current starting row');
  if (ids.sr.textContent !== 'Suffix demo started for cd')
    bad.push(`replacement status=${JSON.stringify(ids.sr.textContent)}`);
  stable = snapshot();
  if (late2) late2({ data: { hit: true, value: '1'.repeat(42) + 'ab', tried: 2, ms: 1 } });
  if (snapshot() !== stable) bad.push('worker 2 injected output/status after replacement');
  if (!worker3 || typeof worker3.onmessage !== 'function') bad.push('replacement did not create worker 3');
  else worker3.onmessage({ data: { hit: true, value: '1'.repeat(42) + 'cd', tried: 12, ms: 100 } });
  if (stoppedPosts(worker3) !== 1 || worker3.terminations !== 1 || revokeCount(url3) !== 1)
    bad.push('hit did not stop, terminate and revoke current worker exactly once');
  if (og.grinding() || ids.out.textContent.includes('starting...'))
    bad.push('hit left a live worker or stale starting row');
  if (ids.sr.textContent !== 'Suffix hit after 12 values')
    bad.push(`hit status=${JSON.stringify(ids.sr.textContent)}`);

  const headings = allElements.filter(el => el.getAttribute('role') === 'heading');
  if (!headings.length) bad.push('no generated headings were observed');
  for (const heading of headings) {
    const name = heading.getAttribute('aria-label') || '';
    if (!name || /[╔═▌▐╗]/.test(name))
      bad.push(`unclean generated heading name: ${JSON.stringify(name)}`);
  }

  og.mode(false);

  for (const c of CMDS) og.run(c);
  if (og.W() !== 78) bad.push(`desktop mode W=${og.W()}, expected 78`);
  assertDonateSolanaBlock(og, 'desktop', [
    'Solana',
    '2pSgpgA6TqdynuAdVpFEZbyVRrKi5oTyvxGL9gjKEYRX',
    'the literal address above is authoritative',
    'keyrx.sol  the same address, by name',
  ], bad);
  const d = measure(og, 'desktop', 78, bad);

  og.mode(true);
  if (og.W() !== 42) bad.push(`mobile mode W=${og.W()}, expected 42`);
  for (const c of CMDS) og.run(c);
  assertDonateSolanaBlock(og, 'mobile', [
    'Solana',
    '2pSgp...KEYRX  tap to copy',
    'literal address is authoritative',
    'keyrx.sol  by name',
  ], bad);
  const mo = measure(og, 'mobile', 42, bad);
  og.mode(false);

  if (bad.length) {
    console.error(`FAIL: ${bad.length} problem(s) across desktop ${d.rows}+${d.loose} / mobile ${mo.rows}+${mo.loose} rows`);
    for (const b of bad.slice(0, 25)) console.error('  ' + b);
    process.exit(1);
  }
  console.log(`OK: desktop ${d.rows} panel rows at 78 cols, mobile ${mo.rows} panel rows at 42 cols; ` +
              `${d.rows + d.loose + mo.rows + mo.loose} total lines free of fallback-risk glyphs`);
  process.exit(0);
}, 150);
