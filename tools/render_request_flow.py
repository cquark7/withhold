#!/usr/bin/env python3
"""Render the README animation with Pillow: python3 tools/render_request_flow.py.

This optional development tool needs Pillow (python3 -m pip install Pillow).
The example credential and placeholder use the same synthetic values as the
local demo. Font substitutions on other platforms can change the rendering.
"""

import hashlib
import hmac
import math
from functools import lru_cache
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "docs/assets/request-flow.gif"
WIDTH, HEIGHT = 1120, 520
SCALE = 2
FPS = 10
SECONDS = 12

BG = "#111d26"
SURFACE = "#192a34"
SURFACE_ACTIVE = "#203a34"
BORDER = "#30434d"
MUTED = "#a9bcc7"
TEXT = "#edf4f5"
MINT = "#8ce5b5"
AMBER = "#f2bd88"
AMBER_BG = "#49392f"

SYNTHETIC_KEY = "AKIA4X7Q2W8K9MNDZZZZ"
MARKER = (
    "<WITHHELD_"
    + hmac.new(
        b"withhold-demo-synthetic-key", SYNTHETIC_KEY.encode(), hashlib.sha256
    ).hexdigest()[:16]
    + ">"
)


@lru_cache
def font(size, face="regular"):
    if face == "mono":
        choices = (
            ("/System/Library/Fonts/Menlo.ttc", 0),
            ("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 0),
            ("C:/Windows/Fonts/consola.ttf", 0),
        )
    else:
        choices = (
            ("/System/Library/Fonts/Avenir Next.ttc", 2 if face == "bold" else 7),
            (
                "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
                if face == "bold"
                else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
                0,
            ),
            (
                "C:/Windows/Fonts/segoeuib.ttf"
                if face == "bold"
                else "C:/Windows/Fonts/segoeui.ttf",
                0,
            ),
        )
    for path, index in choices:
        if Path(path).exists():
            return ImageFont.truetype(path, size * SCALE, index=index)
    raise RuntimeError(f"No suitable {face} font found for rendering the animation")


def points(values):
    return tuple(round(value * SCALE) for value in values)


def rounded(draw, box, radius, fill, outline=None, width=1):
    draw.rounded_rectangle(
        points(box), radius * SCALE, fill=fill, outline=outline, width=width * SCALE
    )


def line(draw, coords, fill, width=1):
    draw.line(points(coords), fill=fill, width=width * SCALE, joint="curve")


def label(draw, xy, text, size, color=TEXT, face="regular", anchor="lt"):
    draw.text(points(xy), text, font=font(size, face), fill=color, anchor=anchor)


def draw_brand(draw, x, y, size):
    """Draw the brackets and bars from the project mark."""
    unit = size / 42
    stroke = max(1, round(2.4 * unit))
    line(draw, (x + 10 * unit, y + 7 * unit, x + 5 * unit, y + 7 * unit), MINT, stroke)
    line(draw, (x + 5 * unit, y + 7 * unit, x + 5 * unit, y + 35 * unit), MINT, stroke)
    line(
        draw, (x + 5 * unit, y + 35 * unit, x + 10 * unit, y + 35 * unit), MINT, stroke
    )
    line(draw, (x + 32 * unit, y + 7 * unit, x + 37 * unit, y + 7 * unit), MINT, stroke)
    line(
        draw, (x + 37 * unit, y + 7 * unit, x + 37 * unit, y + 35 * unit), MINT, stroke
    )
    line(
        draw, (x + 37 * unit, y + 35 * unit, x + 32 * unit, y + 35 * unit), MINT, stroke
    )
    for offset in (14, 20, 26):
        rounded(
            draw,
            (x + offset * unit, y + 16 * unit, x + (offset + 3) * unit, y + 26 * unit),
            max(1, round(unit)),
            MINT,
        )


def dashed_box(draw, box, color):
    x1, y1, x2, y2 = box
    dash, gap = 8, 7
    for x in range(x1, x2, dash + gap):
        line(draw, (x, y1, min(x + dash, x2), y1), color)
        line(draw, (x, y2, min(x + dash, x2), y2), color)
    for y in range(y1, y2, dash + gap):
        line(draw, (x1, y, x1, min(y + dash, y2)), color)
        line(draw, (x2, y, x2, min(y + dash, y2)), color)


def arrow(draw, start, end):
    line(draw, (start, 269, end, 269), "#607984", 2)
    line(draw, (end - 7, 263, end, 269, end - 7, 275), "#607984", 2)


def draw_packet(draw, x, color):
    rounded(draw, (x - 11, 260, x + 11, 278), 4, color)
    line(draw, (x - 5, 266, x + 5, 266), BG, 1)
    line(draw, (x - 5, 272, x + 2, 272), BG, 1)


def ease(value):
    value = max(0, min(1, value))
    return value * value * (3 - 2 * value)


def base_canvas():
    image = Image.new("RGB", (WIDTH * SCALE, HEIGHT * SCALE), BG)
    draw = ImageDraw.Draw(image)
    rounded(draw, (1, 1, WIDTH - 1, HEIGHT - 1), 22, BG, BORDER, 2)
    line(draw, (1, 79, WIDTH - 1, 79), BORDER)
    draw_brand(draw, 35, 20, 42)
    label(draw, (87, 27), "withhold", 23, TEXT, "bold")
    label(draw, (197, 31), "/  REQUEST FLOW", 14, MUTED, "mono")
    rounded(draw, (908, 27, 1082, 57), 7, SURFACE, BORDER)
    label(draw, (995, 35), "LOCAL  /  OFFLINE", 12, MINT, "mono", "mt")

    label(draw, (40, 104), "Inspect context before it leaves.", 31, TEXT, "bold")
    label(
        draw,
        (41, 151),
        "Supported request bodies are scanned on your machine.",
        18,
        MUTED,
    )

    dashed_box(draw, (40, 195, 742, 346), "#49616a")
    draw.rectangle(points((58, 186, 191, 205)), fill=BG)
    label(draw, (65, 187), "YOUR MACHINE", 13, MUTED, "mono")

    arrow(draw, 271, 418)
    arrow(draw, 638, 839)
    rounded(draw, (58, 224, 271, 314), 12, SURFACE, BORDER)
    rounded(draw, (849, 224, 1080, 314), 12, SURFACE, BORDER)

    rounded(draw, (76, 244, 108, 289), 4, "#223843", "#6f8a92")
    line(draw, (83, 253, 100, 253), MUTED, 1)
    line(draw, (83, 261, 98, 261), MUTED, 1)
    line(draw, (83, 269, 100, 269), MUTED, 1)
    label(draw, (121, 244), "Coding agent", 20, TEXT, "bold")
    label(draw, (121, 273), "Request context", 15, MUTED)

    rounded(draw, (867, 244, 901, 289), 5, "#223843", "#6f8a92")
    for y in (252, 263, 274):
        line(draw, (874, y, 894, y), MUTED, 2)
    label(draw, (916, 244), "AI provider", 20, TEXT, "bold")
    label(draw, (916, 273), "Allowed context", 15, MUTED)
    return image


BASE = base_canvas()


def draw_state(t):
    image = BASE.copy()
    draw = ImageDraw.Draw(image)
    redact = t < 7.2
    blocked = not redact and t >= 9.4
    scanning = (1.6 <= t < 3.1) or (8.6 <= t < 9.4)
    redacted = redact and t >= 3.1

    if redact:
        if t < 1.6:
            message = "A request enters withhold"
        elif t < 3.1:
            message = "The offline scanner finds a secret"
        elif t < 4.6:
            message = "The detected value becomes a marker"
        else:
            message = "Redacted context continues to the provider"
    elif t < 8.6:
        message = "Another request enters withhold"
    elif t < 9.4:
        message = "The offline scanner finds a secret"
    else:
        message = "The request is stopped locally"

    active = scanning or blocked or redacted
    rounded(
        draw,
        (418, 217, 638, 321),
        13,
        SURFACE_ACTIVE if active else SURFACE,
        MINT if active and not blocked else (AMBER if blocked else BORDER),
        2 if active else 1,
    )
    draw_brand(draw, 434, 248, 42)
    label(draw, (485, 242), "withhold", 21, TEXT, "bold")
    label(draw, (485, 274), "Offline scan", 15, MUTED)

    if t < 1.6:
        draw_packet(draw, 280 + 126 * ease(t / 1.6), AMBER)
    elif 3.4 <= t < 5.8:
        draw_packet(draw, 650 + 184 * ease((t - 3.4) / 2.4), MINT)
    elif 7.2 <= t < 8.6:
        draw_packet(draw, 280 + 126 * ease((t - 7.2) / 1.4), AMBER)

    if scanning:
        radius = 4 + 1.5 * (1 + math.sin(t * 8))
        draw.ellipse(
            points((615 - radius, 235 - radius, 615 + radius, 235 + radius)), fill=MINT
        )
    if blocked:
        rounded(draw, (660, 253, 695, 285), 7, AMBER_BG, AMBER)
        line(draw, (671, 263, 684, 276), AMBER, 2)
        line(draw, (684, 263, 671, 276), AMBER, 2)

    rounded(draw, (40, 371, 1080, 488), 12, SURFACE, BORDER)
    pill_color = SURFACE_ACTIVE if redact else AMBER_BG
    pill_text = MINT if redact else AMBER
    rounded(draw, (60, 389, 196, 416), 6, pill_color)
    label(
        draw,
        (128, 395),
        "REDACT MODE" if redact else "BLOCK MODE",
        14,
        pill_text,
        "mono",
        "mt",
    )
    label(draw, (214, 389), message, 19, TEXT, "bold")
    label(draw, (1060, 395), "SYNTHETIC EXAMPLE", 12, MUTED, "mono", "rt")
    label(draw, (61, 436), "token =", 20, MUTED, "mono")
    label(
        draw,
        (171, 436),
        MARKER if redacted else SYNTHETIC_KEY,
        20,
        MINT if redacted else AMBER,
        "mono",
    )
    return image


def frame_at(t):
    if 6.8 <= t < 7.2:
        return Image.blend(draw_state(6.79), draw_state(7.2), ease((t - 6.8) / 0.4))
    if t >= 11.6:
        return Image.blend(draw_state(11.59), draw_state(0), ease((t - 11.6) / 0.4))
    return draw_state(t)


def main():
    frames = [
        frame_at(frame / FPS).resize((WIDTH, HEIGHT), Image.Resampling.LANCZOS)
        for frame in range(FPS * SECONDS)
    ]
    samples = Image.new("RGB", (WIDTH // 2 * 3, HEIGHT // 2 * 2))
    for index, frame_number in enumerate((0, 23, 40, 65, 90, 110)):
        sample = frames[frame_number].resize((WIDTH // 2, HEIGHT // 2))
        samples.paste(sample, ((index % 3) * WIDTH // 2, (index // 3) * HEIGHT // 2))
    palette = samples.quantize(colors=256, method=Image.Quantize.MEDIANCUT)
    indexed = [
        frame.quantize(palette=palette, dither=Image.Dither.NONE) for frame in frames
    ]
    indexed[0].save(
        OUTPUT,
        save_all=True,
        append_images=indexed[1:],
        duration=1000 // FPS,
        loop=0,
        disposal=1,
        optimize=True,
    )
    print(f"Wrote {OUTPUT} ({OUTPUT.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
