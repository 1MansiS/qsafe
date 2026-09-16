"""PDF -> Markdown conversion. Offline, maintainer-run only.

pymupdf4llm chosen over unstructured after comparing real output against
FIPS 203 — unstructured's PDF module hard-imports pi_heif (HEIC image
support, irrelevant to a text-only spec PDF) and needs the system
libheif library just to install. See qsafe.md's 2026-09-16 entry.
"""

import pymupdf4llm


def load_markdown(pdf_path: str) -> str:
    return pymupdf4llm.to_markdown(pdf_path)
