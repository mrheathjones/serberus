from PIL import Image
import numpy as np, os, json

SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
tile = Image.open("/tmp/serberus_src/agent_tile.png").convert("RGB")
# Inset-crop to drop the tile's bright rounded rim (the mark doesn't reach the edges).
W, H = tile.size
inset = int(W * 0.085)
tile = tile.crop((inset, inset, W - inset, H - inset))
arr = np.asarray(tile).astype(np.float32)
r, g, b = arr[..., 0], arr[..., 1], arr[..., 2]
lum = 0.2126 * r + 0.7152 * g + 0.0722 * b
chroma = np.clip(g - 0.5 * (r + b), 0, 255)            # emerald-ness
# alpha: emerald facets via chroma; bright glow via high-luminance only
# (threshold 78 keeps the tile's faint rim highlight out)
alpha = np.clip(chroma * 6.0 + np.clip(lum - 78, 0, 255) * 2.2, 0, 255)
out = np.dstack([r, g, b, alpha]).astype(np.uint8)
im = Image.fromarray(out)

bbox = im.getbbox()
im = im.crop(bbox)
w, h = im.size
s = int(max(w, h) * 1.12)
mark = Image.new("RGBA", (s, s), (0, 0, 0, 0))
mark.alpha_composite(im, ((s - w) // 2, (s - h) // 2))

def write_imageset(catalog):
    d = os.path.join(catalog, "BrandMark.imageset")
    os.makedirs(d, exist_ok=True)
    for scale, px in [(1, 132), (2, 264), (3, 396)]:
        mark.resize((px, px), Image.LANCZOS).save(os.path.join(d, f"mark{'' if scale==1 else '@'+str(scale)+'x'}.png"))
    contents = {
        "images": [
            {"idiom": "universal", "filename": "mark.png", "scale": "1x"},
            {"idiom": "universal", "filename": "mark@2x.png", "scale": "2x"},
            {"idiom": "universal", "filename": "mark@3x.png", "scale": "3x"},
        ],
        "info": {"author": "serberus-icongen", "version": 1},
    }
    with open(os.path.join(d, "Contents.json"), "w") as f:
        json.dump(contents, f, indent=2)

write_imageset(os.path.join(SRC, "Sources/SerberusCommander/Assets.xcassets"))
write_imageset(os.path.join(SRC, "Sources/SerberusSentinel/Assets.xcassets"))

for name, bg in [("dark", (14, 17, 20, 255)), ("light", (235, 235, 235, 255)), ("menubar", (40, 42, 46, 255))]:
    rv = Image.new("RGBA", (s, s), bg); rv.alpha_composite(mark)
    rv.convert("RGB").save(f"/tmp/serberus_src/brandmark_{name}.png")
print("wrote BrandMark imagesets to both catalogs; mark size", mark.size)
