# Reproducing the raster brand assets

The committed banner and Open Graph image are rendered locally from `assets/logo.svg` and two
OFL-1.1 fonts. The renderer refuses any font bytes other than the reviewed inputs below.

Source repository: `google/fonts`, commit
`f6b2b7e8545e086ad3f821af21895d732b6485cf`.

| Role | File at that commit | SHA-256 |
| --- | --- | --- |
| Terminal panel | `ofl/jetbrainsmono/JetBrainsMono[wght].ttf` | `48715a42ec242c21e9f02692891e147d022299a52e48d5e413e1a942193ffeda` |
| Wordmark and prose | `ofl/outfit/Outfit[wght].ttf` | `fc7287273e66929776e2ba54f144fe699080bec29f61bf649d70d871468aeade` |

The corresponding `OFL.txt` in each directory is the font license source. Download the files by
their immutable commit URLs, verify the hashes, then run:

```sh
PW=/path/to/playwright CHROME=/path/to/chromium node assets/render_banner.cjs \
  --font /path/to/JetBrainsMono-wght.ttf \
  --display /path/to/Outfit-wght.ttf \
  --text /path/to/Outfit-wght.ttf
```

`CHROME` is optional when the selected Playwright package already owns a compatible Chromium.

This writes `assets/x-header-1500x500.png` and `site/og.png`. The remaining logo rasters come only
from `assets/logo.svg` through `assets/render_svg.cjs`; `assets/make_mark.py` regenerates the SVG
geometry from its 64-character SHA-256 value.
