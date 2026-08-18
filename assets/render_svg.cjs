// keyRX mark - rasterise assets/logo.svg with Chromium (the SVG is the only source).
// Usage: node assets/render_svg.cjs [outdir]   needs: npm i playwright && npx playwright install chromium
// Not a dependency of the crate or the site; run by hand when the mark changes.
const fs = require('fs'), path = require('path');
const { chromium } = require(process.env.PW || 'playwright');
const svgPath = process.argv[2] || path.join(__dirname, 'logo.svg');
const out = process.argv[3] || path.dirname(svgPath);
(async () => {
  const svg = fs.readFileSync(svgPath, 'utf8');
  const b = await chromium.launch();
  async function shoot(size, file, bg) {
    const p = await b.newPage({ viewport: { width: size, height: size }, deviceScaleFactor: 1 });
    await p.setContent(`<!doctype html><html><head><style>html,body{margin:0;background:${bg || 'transparent'}}svg{display:block;width:${size}px;height:${size}px}</style></head><body>${svg}</body></html>`);
    await p.screenshot({ path: path.join(out, file), omitBackground: !bg, clip: { x: 0, y: 0, width: size, height: size } });
    await p.close();
  }
  for (const s of [16, 32, 64, 128, 256, 512, 1024]) await shoot(s, `logo-${s}.png`);
  await shoot(1024, 'avatar-1024.png');            // transparent - GitHub keeps alpha
  await shoot(1024, 'avatar-1024-white.png', '#fff'); // for uploaders that flatten alpha
  await b.close();
  console.log('rendered logo-{16..1024}.png, avatar-1024.png, avatar-1024-white.png ->', out);
})();
