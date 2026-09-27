# Serberus sigil — three-chevron mark

Three stacked chevrons, rising. One geometry at every size; only stroke weight changes.

## Geometry (40 x 40 box)
    M9 17 L20 7  L31 17
    M9 25 L20 15 L31 25
    M9 33 L20 23 L31 33
Round caps and joins. Stroke 3.4 default (2.4 light / 4.4 heavy under 20px or over 200px).
Chevron pitch 8 units, span 22 units, inset 9 units each side.
Optical box is 72% of an app-icon tile, 82% of a bare glyph tile.

## Contents
- `svg/sigil.svg` — currentColor, the one to ship in UI. `sigil-accent.svg` (#3ee0a1),
  `sigil-light.svg`, `sigil-heavy.svg` for extreme sizes.
- `Serberus.iconset/` — app icon, 10 standard macOS entries (16pt-512pt @1x/@2x).
  Superellipse (n=5) mask, background `radial-gradient(130% 130% at 30% 12%, #12563f, #081c18 72%)`,
  flat #4fe4ab sigil, no glow.
- `menubar/sigilTemplate*.png` — black-on-transparent template images, 18/36/54 px.
  Set `image.isTemplate = true` so macOS tints them with the menu bar.
- `png-accent/` — transparent accent-green rasters, 16-1024 px, for docs and web.

## Build the .icns
The `@2x` files export as `-2x`; rename first:

    cd Serberus.iconset
    for f in *-2x.png; do mv "$f" "${f/-2x/@2x}"; done
    cd .. && iconutil -c icns Serberus.iconset

## Colour
| Context | Value |
|---|---|
| Accent (dark UI) | `#3ee0a1` |
| Accent (light UI) | `#0f9d67` |
| On-icon glyph | `#4fe4ab` |
| Menu bar | template — never a fixed colour |
