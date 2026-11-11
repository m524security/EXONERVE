#!/usr/bin/env python3
"""Regenerate media/demo.gif from a REAL demo.py run — replaces the stale
recording whose banner frame still baked in the pre-rename ASCII art.

Usage:
    python3 demo.py --no-browser --speed 6.0 > /tmp/demo_raw_output.txt 2>&1
    python3 scripts/generate_demo_gif.py
"""
import os
import re
from PIL import Image, ImageDraw, ImageFont

RAW_PATH = "/tmp/demo_raw_output.txt"
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_PATH = os.path.join(_REPO_ROOT, "media", "demo.gif")

FONT_REG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fonts", "JetBrainsMono-Regular.ttf")
FONT_BOLD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fonts", "JetBrainsMono-Bold.ttf")

W, H = 1000, 620
TITLEBAR_H = 40
MARGIN_X = 24
MARGIN_TOP = 16
FONT_SIZE = 15
LINE_H = 22
WRAP_COLS = 104

BG = (10, 14, 20)
TITLEBAR_BG = (23, 27, 36)
DOT_RED, DOT_YLW, DOT_GRN = (255, 95, 86), (255, 189, 46), (39, 201, 63)
TITLE_TEXT = (150, 158, 170)

ANSI_COLORS = {
    "91": (255, 110, 110),   # red
    "92": (94, 234, 143),    # grn
    "93": (245, 222, 90),    # ylw
    "96": (52, 211, 235),    # cyn
    "95": (219, 130, 240),   # mag
    "2":  (110, 122, 138),   # dim
    "1":  (225, 230, 236),   # bold -> bright default
    "0":  (196, 204, 214),   # reset -> default fg
}
DEFAULT_FG = (196, 204, 214)

font_reg = ImageFont.truetype(FONT_REG, FONT_SIZE)
font_bold = ImageFont.truetype(FONT_BOLD, FONT_SIZE)


def parse_ansi_stream(text):
    """Parse the ENTIRE raw stream into a flat [(char, color, bold), ...]
    list, including '\\n' as explicit characters, so color state correctly
    carries across newlines.

    Real bug found and fixed here: an earlier version split the raw text
    into lines FIRST (str.split('\\n')) and then parsed ANSI codes on each
    line independently. That's wrong whenever a color code precedes a
    MULTI-LINE block on its own line (exactly what demo.py's banner() does
    — paint("cyn", ...) wraps the whole multi-line banner in one \\x1b[96m
    ... \\x1b[0m pair) — the escape code ends up alone on its own split
    line, and every subsequent banner line has no escape code on it at
    all, so per-line-independent parsing silently rendered the whole
    banner in the default color instead of cyan. Caught by actually
    rendering and inspecting the output, not assumed correct from the code.
    """
    result = []
    cur_color, cur_bold = DEFAULT_FG, False
    pos = 0
    for m in re.finditer(r"\x1b\[([0-9;]*)m", text):
        if m.start() > pos:
            for ch in text[pos:m.start()]:
                result.append((ch, cur_color, cur_bold))
        codes = m.group(1).split(";") if m.group(1) else ["0"]
        for code in codes:
            if code in ("", "0"):
                cur_color, cur_bold = DEFAULT_FG, False
            elif code == "1":
                cur_bold = True
            elif code in ANSI_COLORS:
                cur_color = ANSI_COLORS[code]
        pos = m.end()
    for ch in text[pos:]:
        result.append((ch, cur_color, cur_bold))
    return result


def split_into_lines(flat_chars):
    lines, cur = [], []
    for ch, color, bold in flat_chars:
        if ch == "\n":
            lines.append(cur)
            cur = []
        else:
            cur.append((ch, color, bold))
    lines.append(cur)
    return lines


def wrap_line(chars, width):
    """Wrap one line's [(char,color,bold), ...] onto multiple lines at
    `width` visible characters, preserving color per character, word-aware."""
    if not chars:
        return [[]]
    lines_out = []
    cur = []
    col = 0
    idx = 0
    text_only = "".join(c for c, _, _ in chars)
    words = re.findall(r"\S+|\s+", text_only)
    for word in words:
        wlen = len(word)
        if col + wlen > width and col > 0 and not word.isspace():
            lines_out.append(cur)
            cur = []
            col = 0
        for _ in range(wlen):
            cur.append(chars[idx])
            idx += 1
        col += wlen
    lines_out.append(cur)
    return lines_out


def render_frame(all_wrapped_lines, visible_count):
    img = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(img)

    draw.rectangle([0, 0, W, TITLEBAR_H], fill=TITLEBAR_BG)
    for i, color in enumerate([DOT_RED, DOT_YLW, DOT_GRN]):
        cx = 22 + i * 22
        draw.ellipse([cx - 6, TITLEBAR_H // 2 - 6, cx + 6, TITLEBAR_H // 2 + 6], fill=color)
    title = "exonerve — demo"
    tw = draw.textlength(title, font=font_reg)
    draw.text(((W - tw) / 2, TITLEBAR_H // 2 - FONT_SIZE // 2 - 1), title,
              font=font_reg, fill=TITLE_TEXT)

    visible = all_wrapped_lines[max(0, visible_count - 25):visible_count]
    y = TITLEBAR_H + MARGIN_TOP
    for line_chars in visible:
        x = MARGIN_X
        # merge consecutive same-style chars into runs for faster/cleaner draw
        if not line_chars:
            y += LINE_H
            continue
        run_text, run_color, run_bold = line_chars[0][0], line_chars[0][1], line_chars[0][2]
        for ch, color, bold in line_chars[1:]:
            if color == run_color and bold == run_bold:
                run_text += ch
            else:
                f = font_bold if run_bold else font_reg
                draw.text((x, y), run_text, font=f, fill=run_color)
                x += draw.textlength(run_text, font=f)
                run_text, run_color, run_bold = ch, color, bold
        f = font_bold if run_bold else font_reg
        draw.text((x, y), run_text, font=f, fill=run_color)
        y += LINE_H
    return img


def main():
    with open(RAW_PATH, "r", encoding="utf-8", errors="replace") as f:
        raw_text = f.read()

    flat = parse_ansi_stream(raw_text)
    raw_lines = split_into_lines(flat)

    all_wrapped = []
    for line_chars in raw_lines:
        for wrapped in wrap_line(line_chars, WRAP_COLS):
            all_wrapped.append(wrapped)

    print(f"total wrapped terminal lines: {len(all_wrapped)}")

    # Reveal schedule: cumulative reveal, banner+narrative line-by-line-ish,
    # then the long detection table in larger chunks so the gif doesn't
    # balloon to 90+ frames for a README asset.
    reveal_points = list(range(1, 45))          # banner + full narrative, ~1 line/frame
    reveal_points += list(range(46, len(all_wrapped) + 1, 4))   # detection table in chunks of 4
    if reveal_points[-1] != len(all_wrapped):
        reveal_points.append(len(all_wrapped))
    # hold on the final frame a bit longer by repeating it
    reveal_points += [len(all_wrapped)] * 3

    frames = [render_frame(all_wrapped, n) for n in reveal_points]
    durations = [140] * (len(frames) - 3) + [1800, 1800, 1800]

    frames[0].save(OUT_PATH, save_all=True, append_images=frames[1:],
                    duration=durations, loop=0, optimize=True)
    print(f"wrote {OUT_PATH}: {len(frames)} frames")


if __name__ == "__main__":
    main()
