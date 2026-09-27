from PIL import Image, ImageDraw
import os

SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
agent = Image.open("/tmp/serberus_src/agent_tile.png").convert("RGB")
admin = Image.open("/tmp/serberus_src/admin_tile.png").convert("RGB")

def rounded(tile):
    """Mask the tile's outer-corner triangles to transparent."""
    t = tile.convert("RGBA")
    w, h = t.size
    mask = Image.new("L", (w, h), 0)
    d = ImageDraw.Draw(mask)
    d.rounded_rectangle([0, 0, w - 1, h - 1], radius=int(w * 0.225), fill=255)
    t.putalpha(mask)
    return t

agent_r = rounded(agent)
admin_r = rounded(admin)

# macOS AppIcon entries -> pixel sizes
entries = [
    ("appicon-16", 16), ("appicon-16@2x", 32), ("appicon-32", 32), ("appicon-32@2x", 64),
    ("appicon-128", 128), ("appicon-128@2x", 256), ("appicon-256", 256),
    ("appicon-256@2x", 512), ("appicon-512", 512), ("appicon-512@2x", 1024),
]
CONTENT = 0.80  # Apple icon grid: rounded rect fills ~80% of the canvas

def write_set(tile, outdir):
    os.makedirs(outdir, exist_ok=True)
    for name, n in entries:
        canvas = Image.new("RGBA", (n, n), (0, 0, 0, 0))
        c = max(1, round(n * CONTENT))
        art = tile.resize((c, c), Image.LANCZOS)
        off = (n - c) // 2
        canvas.alpha_composite(art, (off, off))
        canvas.save(os.path.join(outdir, name + ".png"))

write_set(admin_r, os.path.join(SRC, "Sources/SerberusCommander/Assets.xcassets/AppIcon.appiconset"))
write_set(agent_r, os.path.join(SRC, "Sources/SerberusSentinel/Assets.xcassets/AppIcon.appiconset"))

# review sheet
sheet = Image.new("RGBA", (560, 300), (10, 11, 13, 255))
for i, (tile, n) in enumerate([(agent_r, 256), (admin_r, 256)]):
    art = tile.resize((n, n), Image.LANCZOS)
    sheet.alpha_composite(art, (20 + i * 270, 22))
sheet.convert("RGB").save("/tmp/serberus_src/appicon_review.png")
print("wrote admin + agent AppIcon sets from provided pixels; review at /tmp/serberus_src/appicon_review.png")
