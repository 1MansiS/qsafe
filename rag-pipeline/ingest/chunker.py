"""Section-aware chunking. Cuts at markdown heading boundaries produced by
loader.py's pymupdf4llm conversion, not fixed-size windows — NIST section
numbering already aligns with coherent algorithm/topic units (see
ARCHITECTURE.md's "Retrieval" section and qsafe.md's 2026-08-26/09-16
entries for the curation reasoning).

Scoped to FIPS 203 only for now (step 4 of the Phase 2 build-out); the
other four corpus documents get their own include lists once this one's
proven out end to end.
"""

import re

from .schema import Chunk

HEADING_LINE_RE = re.compile(r"^(#{1,6})\s+(.*)$")

# Real, numbered section headings, e.g. "**1.1 Purpose and Scope**" ->
# number "1.1". Deliberately not a general "is this a real heading"
# classifier: pymupdf4llm's font-size-based heading detection sometimes
# misfires on figure/diagram callout text (FIPS 203's Alice/Bob
# key-exchange diagram produced stray "### Alice Bob" and "### 𝐾 [′] 𝐾"
# headings mid-section) — text that doesn't match this pattern is folded
# back into the surrounding chunk instead of treated as a boundary.
NUMBERED_HEADING_RE = re.compile(r"^\**\s*(\d+(?:\.\d+)*)\.?\**\s*(.*)$")

# Headings besides numbered ones that still need to act as a stop
# boundary for whatever chunk precedes them, even though nothing after
# them is included — otherwise a trailing excluded section (here,
# References) merges into the last included chunk. Extend this set if a
# later document's curation needs more (e.g. "Appendix A").
OTHER_BOUNDARY_HEADINGS = {"References"}

# FIPS 203's step-2 curation call (qsafe.md 2026-09-16): §1 (Purpose/
# Scope, Context), §2.1 (Terms and Definitions), §3 (Overview, the
# scheme, Requirements), §8 (Parameter Sets). Everything else —
# §2.2-2.4, §4-7's algorithm internals, References, Appendices — out.
FIPS_203_INCLUDE = {"1", "1.1", "1.2", "2.1", "3", "3.1", "3.2", "3.3", "8"}

# Page furniture and dead figure captions — safe, general patterns (no
# reliance on guessing which short lines are "real" content), unlike the
# heading-noise problem above which is heading-specific. A figure's
# caption is dead weight in a text-only chunk since the image itself
# never makes it into the corpus; the running header repeats on every
# page; a bare page number is never itself content.
FIPS_203_RUNNING_HEADER = "FIPS 203 MODULE-LATTICE-BASED KEY-ENCAPSULATION MECHANISM"
PAGE_NUMBER_RE = re.compile(r"^\d{1,4}$")
FIGURE_CAPTION_RE = re.compile(r"^\*\*Figure\*\*")


def _clean_title(raw: str) -> str:
    return re.sub(r"\*+", "", raw).strip()


def _strip_page_furniture(markdown: str) -> str:
    kept = [
        line
        for line in markdown.splitlines()
        if line.strip() != FIPS_203_RUNNING_HEADER
        and not PAGE_NUMBER_RE.match(line.strip())
        and not FIGURE_CAPTION_RE.match(line.strip())
    ]
    # Collapse runs of 2+ blank lines (now more common post-strip) down
    # to one, so removed lines don't leave visible gaps.
    text = "\n".join(kept)
    return re.sub(r"\n{3,}", "\n\n", text)


def chunk_fips_203(markdown: str) -> list[Chunk]:
    markdown = _strip_page_furniture(markdown)
    chunks = []
    number = None
    title = None
    body: list[str] = []

    def flush():
        if number is None or number not in FIPS_203_INCLUDE:
            return
        text = "\n".join(body).strip()
        if not text:  # bare numbered wrapper with no content of its own
            return
        chunks.append(
            Chunk(
                id=f"fips-203#{number}",
                text=text,
                source="fips-203",
                section=f"{number} {title}".strip(),
                algorithm="ML-KEM",
                doc_type="standard",
            )
        )

    for line in markdown.splitlines():
        m = HEADING_LINE_RE.match(line)
        if not m:
            body.append(line)
            continue

        heading_text = m.group(2)
        num_m = NUMBERED_HEADING_RE.match(heading_text)
        if num_m:
            flush()
            number, title = num_m.group(1), _clean_title(num_m.group(2))
            body = []
            continue

        if _clean_title(heading_text) in OTHER_BOUNDARY_HEADINGS:
            flush()
            number, title, body = None, None, []
            continue

        # Not a recognized boundary — fold back into the current chunk's
        # text rather than dropping it, in case it's ever real prose.
        body.append(heading_text)

    flush()
    return chunks
