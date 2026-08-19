// keyRX banner + OG image, composed in HTML around the mark (assets/logo.svg is the only source of the
// mark) and rasterised with Chromium. Not a dependency of the crate or the site; run by hand.
//   PW=<path to playwright> node assets/render_banner.cjs --font /path/JetBrainsMono-Regular.ttf \
//        --display /path/outfit-600.woff2 --text /path/outfit-400.woff2
// Writes assets/x-header-1500x500.png and site/og.png (1200x630). Words (the wordmark, the tagline)
// are set in Outfit - the same face keyRX Deploy uses for everything a person wrote; values and the
// panel stay in JetBrains Mono. The fonts are not committed.
const fs = require('fs'), path = require('path');
const { chromium } = require(process.env.PW || 'playwright');
const args = process.argv.slice(2);
const arg = (k) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : null; };
const fontPath = arg('--font'), displayPath = arg('--display'), textPath = arg('--text');
// composition knobs (defaults are the shipped banner); --out renders only the banner to that path
const MARK = Number(arg('--mark') || 340), WORD = Number(arg('--word') || 96), TAGPX = Number(arg('--tagpx') || 28);
const TAG = (arg('--tag') || 'Solana vanity addresses\nkeys for every wallet').replace(/\\n/g, '\n');
const MONO_LINE = arg('--mono') || null; // an optional third line in the CLI face, e.g. "cargo install keyrx"
const OUT = arg('--out') || null;
if (!fontPath || !displayPath || !textPath) { console.error('need --font <JetBrains Mono ttf> --display <Outfit 600 woff2> --text <Outfit 400 woff2>'); process.exit(2); }
const root = path.join(__dirname, '..');
const svg = fs.readFileSync(path.join(__dirname, 'logo.svg'), 'utf8');
const font = fs.readFileSync(fontPath).toString('base64');
const display = fs.readFileSync(displayPath).toString('base64'), text = fs.readFileSync(textPath).toString('base64');
// the faint field marks: the same seal, dimmed, scattered like a watermark
const water = (x, y, s, r) => `<div class="w" style="left:${x}px;top:${y}px;width:${s}px;height:${s}px;transform:rotate(${r}deg)">${svg}</div>`;
const waters = [[30, 10, 96, -8], [430, -30, 96, 6], [860, 5, 90, -5], [1290, 20, 96, 7], [70, 400, 96, 5], [420, 410, 90, -6], [900, 400, 96, 8], [1310, 400, 96, -7]].map((a) => water(...a)).join('');

// the panel: every line exactly W characters, so the frame closes
const IN = 40, W = IN + 2;
const B = (t) => `<span class="b">${t}</span>`, WT = (t) => `<span class="wt">${t}</span>`, AM = (t) => `<span class="am">${t}</span>`;
const len = (segs) => segs.reduce((n, [t]) => n + t.length, 0);
const render = (segs) => segs.map(([t, c]) => (c ? c(t) : t)).join('');
function head(t, sub) { const l = [['╔══▌ ', B], [t, WT], [' ▐', B]]; const r = [[` ${sub} `, null], ['╗', B]]; return render([...l, ['═'.repeat(W - len(l) - len(r)), B], ...r]); }
function row(...inner) { const n = len(inner); if (n > IN) throw new Error('row too long: ' + n); return render([['║', B], ...inner, [' '.repeat(IN - n), null], ['║', B]]); }
function foot(t) { const l = [['╚══', B], [` ${t} `, null]]; return render([...l, ['═'.repeat(W - len(l) - 1), B], ['╝', B]]); }
const panel = [
  head('KEYRX', '5 exact letters'),
  row(),
  row(['  solana-keygen     13h      median', null]),
  row(['  key', null], ['RX', AM], ['             ', null], ['13m', WT], ['      ', null], ['a match', AM]),
  row(),
  row(['  same box, same odds', null]),
  row(['  1 in 656,356,768', null]),
  row(),
  foot('one seed, unlimited addresses'),
].join('\n');
const html = `<!doctype html><html><head><meta charset="utf-8"><style>
@font-face{font-family:KXMono;src:url(data:font/ttf;base64,${font}) format('truetype')}
@font-face{font-family:KXDisplay;src:url(data:font/woff2;base64,${display}) format('woff2')}
@font-face{font-family:KXText;src:url(data:font/woff2;base64,${text}) format('woff2')}
html,body{margin:0;width:1500px;height:500px;overflow:hidden;background:#091228;font-family:KXMono,monospace;color:#dbe3f2}
.field{position:absolute;inset:0;background:
  radial-gradient(ellipse 320px 260px at 300px 250px, rgba(28,60,110,.55), rgba(28,60,110,0) 70%),
  radial-gradient(ellipse 320px 240px at 1150px 250px, rgba(20,44,90,.45), rgba(20,44,90,0) 70%),
  repeating-linear-gradient(0deg, rgba(255,255,255,.016) 0 1px, transparent 1px 4px)}
.w{position:absolute;opacity:.10;filter:saturate(.4)}
.w svg{width:100%;height:100%}
.mark{position:absolute;left:${Math.round(210 - MARK / 2)}px;top:${Math.round(250 - MARK / 2)}px;width:${MARK}px;height:${MARK}px}
.mark svg{width:100%;height:100%;filter:drop-shadow(0 10px 18px rgba(1,4,14,.6))}
.word{position:absolute;left:432px;top:${Math.round(250 - WORD * 0.62 - TAGPX * 1.5 - (MONO_LINE ? 22 : 0))}px;font-family:KXDisplay,sans-serif;font-size:${WORD}px;line-height:1;letter-spacing:-.015em;color:#dbe3f2}
.word b{font-weight:inherit;color:#c9974f}
.tag{position:absolute;left:436px;top:${Math.round(250 - WORD * 0.62 - TAGPX * 1.5 - (MONO_LINE ? 22 : 0) + WORD * 1.12)}px;font-family:KXText,sans-serif;font-size:${TAGPX}px;line-height:1.5;color:#8a98b6;white-space:pre}
.mono{position:absolute;left:438px;top:${Math.round(250 - WORD * 0.62 - TAGPX * 1.5 - 22 + WORD * 1.12 + TAGPX * 1.5 * (TAG.split('\n').length) + 14)}px;font-family:KXMono,monospace;font-size:22px;color:#5aa6c9;white-space:pre}
.panel{position:absolute;left:936px;top:100px;width:490px;height:296px;background:#0e1b3c;border:1px solid #22345f;box-shadow:0 12px 40px rgba(1,4,14,.55)}
.panel pre{margin:0;padding:12px 0 0 8px;font-size:19px;line-height:31.5px;color:#8a98b6;white-space:pre}
.b{color:#5aa6c9}.wt{color:#dbe3f2}.am{color:#c9974f}
</style></head><body>
<div class="field"></div>${waters}
<div class="mark">${svg}</div>
<div class="word">key<b>RX</b></div>
<div class="tag">${TAG}</div>${MONO_LINE ? `<div class="mono">${MONO_LINE}</div>` : ''}
<div class="panel"><pre>${panel}</pre></div>
</body></html>`;
(async () => {
  const b = await chromium.launch();
  const p = await b.newPage({ viewport: { width: 1500, height: 500 }, deviceScaleFactor: 1 });
  await p.setContent(html); await p.evaluate(() => document.fonts.ready);
  const banner = OUT || path.join(__dirname, 'x-header-1500x500.png');
  await p.screenshot({ path: banner, clip: { x: 0, y: 0, width: 1500, height: 500 } });
  if (OUT) { await b.close(); console.log('rendered ' + OUT); return; }
  // og: the banner scaled to 1200x400 on the field, letterboxed to 1200x630
  const og = await b.newPage({ viewport: { width: 1200, height: 630 }, deviceScaleFactor: 1 });
  const b64 = fs.readFileSync(banner).toString('base64');
  await og.setContent(`<!doctype html><html><body style="margin:0;background:#091228;width:1200px;height:630px;overflow:hidden"><img src="data:image/png;base64,${b64}" style="position:absolute;left:0;top:115px;width:1200px;height:400px"></body></html>`);
  await og.screenshot({ path: path.join(root, 'site', 'og.png'), clip: { x: 0, y: 0, width: 1200, height: 630 } });
  await b.close();
  console.log('rendered assets/x-header-1500x500.png and site/og.png');
})();
