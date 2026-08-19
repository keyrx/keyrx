#!/usr/bin/env python3
"""The keyRX Deploy mark, generated from a record's hash - the SVG is the only source; rasters come from it.

    python3 assets/make_mark.py <sha256 hex64> [--label "..."] [--out assets/logo.svg]

Sixty-four hex digits on an 8x8 grid, one per cell, row by row; a cell is lit when its digit is 8 or
above. That is the same rule that draws the seal of every deployment record's manifest, so the mark
IS a record's seal. Rows 0-3 in the site's blue, rows 4-7 in its amber; each tile a small cylinder,
one soft shadow under the whole glyph; the glyph inset so nothing falls outside the inscribed circle
(it survives a round avatar crop on any ground). Stdlib only.
"""
import argparse, sys

def make(hexhash: str, label: str, title: str = "keyRX Deploy") -> str:
    h = hexhash.strip().lower()
    if len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
        sys.exit("need a 64-char lowercase hex sha256")
    lit = [(i // 8, i % 8) for i, ch in enumerate(h) if int(ch, 16) >= 8]
    o, pitch, size = 44.0, 21.0, 19.53
    out = []
    out.append(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" width="256" height="256" role="img" aria-label="{title}">')
    out.append(f'  <title>{title}</title>')
    out.append('  <!--')
    for line in label.splitlines():
        out.append('    ' + line if line else '')
    out.append('')
    out.append('    Sixty-four hex digits on an 8x8 grid, one per cell, row by row; a cell is')
    out.append('    lit when its digit is 8 or above - the same rule that draws the seal of')
    out.append('    every deployment record. The pattern is the truth and never changes; the')
    out.append('    dressing is free: rows 0-3 in the site\'s blue, rows 4-7 in its amber (the')
    out.append('    two tones keyRX has always used - blue and amber), each tile a small cylinder, one soft shadow')
    out.append('    under the whole glyph, inset inside the inscribed circle. Regenerate with')
    out.append('    assets/make_mark.py; rasterise with assets/render_svg.cjs.')
    out.append('  -->')
    out.append('  <defs>')
    out.append('    <linearGradient id="bl" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#96d0e8"/><stop offset=".5" stop-color="#5aa6c9"/><stop offset="1" stop-color="#286080"/></linearGradient>')
    out.append('    <linearGradient id="am" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#eecc8c"/><stop offset=".5" stop-color="#c9974f"/><stop offset="1" stop-color="#845c28"/></linearGradient>')
    out.append('    <filter id="soft" x="-20%" y="-20%" width="140%" height="140%"><feGaussianBlur stdDeviation="3"/></filter>')
    out.append('  </defs>')
    out.append('  <!-- shadow: one, under the whole glyph, kept inside the circle -->')
    out.append('  <g filter="url(#soft)" opacity=".42">')
    for r, c in lit:
        x, y = o + c * pitch + 2, o + r * pitch + 5
        out.append(f'    <rect x="{x:.2f}" y="{y:.2f}" width="{size}" height="{size}" rx="1.4" fill="#01040e"/>')
    out.append('  </g>')
    out.append('  <!-- tiles: rows 0-3 blue, rows 4-7 amber -->')
    for r, c in lit:
        x, y = o + c * pitch, o + r * pitch
        fill = "url(#bl)" if r < 4 else "url(#am)"
        out.append(f'  <rect x="{x:.2f}" y="{y:.2f}" width="{size}" height="{size}" rx="1.4" fill="{fill}"/>')
        out.append(f'  <rect x="{x + 2.34:.2f}" y="{y + 1.95:.2f}" width="14.84" height="3.12" rx="1" fill="#fff" fill-opacity=".18"/>')
        out.append(f'  <rect x="{x + 0.5:.2f}" y="{y + 0.5:.2f}" width="{size - 1:.2f}" height="{size - 1:.2f}" rx="1.1" fill="none" stroke="#fff" stroke-opacity=".14"/>')
    out.append('</svg>')
    return "\n".join(out) + "\n"

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("sha256")
    ap.add_argument("--label", default="The seal of a deployment record's manifest.")
    ap.add_argument("--out", default="assets/logo.svg")
    ap.add_argument("--title", default="keyRX Deploy")
    a = ap.parse_args()
    svg = make(a.sha256, a.label, a.title)
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(svg)
    print(f"wrote {a.out}: {sum(1 for ch in a.sha256 if int(ch, 16) >= 8)} lit cells of 64")
