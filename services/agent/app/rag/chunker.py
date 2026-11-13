"""Split markdown runbooks into heading-scoped chunks for embedding."""

from __future__ import annotations

import re

_HEADING = re.compile(r"^(#{1,3})\s+(.+?)\s*#*\s*$")
_FENCE = re.compile(r"^\s*(```|~~~)")
_SEP = " › "


def _paragraphs(body: str) -> list[str]:
    """Split on blank lines, keeping fenced code blocks intact."""
    paras: list[str] = []
    current: list[str] = []
    in_fence = False
    for line in body.splitlines():
        if _FENCE.match(line):
            in_fence = not in_fence
        if not line.strip() and not in_fence:
            if current:
                paras.append("\n".join(current).strip())
                current = []
            continue
        current.append(line)
    if current:
        paras.append("\n".join(current).strip())
    return [p for p in paras if p]


def _hard_split(text: str, max_chars: int) -> list[str]:
    """Break an oversized paragraph on line boundaries, then on raw length."""
    pieces: list[str] = []
    buf = ""
    for line in text.splitlines():
        while len(line) > max_chars:
            if buf:
                pieces.append(buf)
                buf = ""
            pieces.append(line[:max_chars])
            line = line[max_chars:]
        candidate = f"{buf}\n{line}" if buf else line
        if len(candidate) > max_chars and buf:
            pieces.append(buf)
            buf = line
        else:
            buf = candidate
    if buf.strip():
        pieces.append(buf)
    return pieces


def _pack(body: str, max_chars: int) -> list[str]:
    """Greedily pack paragraphs into pieces no longer than ``max_chars``."""
    pieces: list[str] = []
    buf = ""
    for para in _paragraphs(body):
        parts = [para] if len(para) <= max_chars else _hard_split(para, max_chars)
        for part in parts:
            candidate = f"{buf}\n\n{part}" if buf else part
            if len(candidate) > max_chars and buf:
                pieces.append(buf)
                buf = part
            else:
                buf = candidate
    if buf.strip():
        pieces.append(buf)
    return pieces


def chunk_markdown(text: str, source: str, max_chars: int = 900) -> list[dict]:
    """Split a markdown document into ``{"source", "title", "text"}`` chunks.

    Sections start at ``#``, ``##`` and ``###`` headings (ignored inside code fences).
    Each chunk's title is the document H1 joined with the section heading path, e.g.
    ``"DNS resolution failures › Diagnose"``. Sections longer than ``max_chars`` are
    split on paragraph boundaries; empty sections are skipped.
    """
    doc_title = ""
    h2 = ""
    h3 = ""
    sections: list[tuple[str, list[str]]] = []
    lines: list[str] = []
    in_fence = False

    def section_title() -> str:
        path = [p for p in (doc_title, h2, h3) if p]
        return _SEP.join(path) if path else source

    def flush() -> None:
        sections.append((section_title(), lines.copy()))
        lines.clear()

    for line in text.splitlines():
        if _FENCE.match(line):
            in_fence = not in_fence
        match = None if in_fence else _HEADING.match(line)
        if not match:
            lines.append(line)
            continue
        flush()
        level, heading = len(match.group(1)), match.group(2).strip()
        if level == 1:
            doc_title, h2, h3 = heading, "", ""
        elif level == 2:
            h2, h3 = heading, ""
        else:
            h3 = heading
    flush()

    chunks: list[dict] = []
    for title, body_lines in sections:
        body = "\n".join(body_lines).strip()
        if not body:
            continue
        for piece in _pack(body, max_chars):
            chunks.append({"source": source, "title": title, "text": piece.strip()})
    return chunks
