"""Chunk schema shared by chunker.py (produces Chunks) and embedder.py
(attaches a vector to each one, writes the flat-file index).

Two different tagging schemes on purpose, not an oversight — standards
chunks (FIPS/CNSA/RFC) have no notion of which classical primitive they
replace (FIPS 203 never says "RSA," it says "SP 800-56A/B"), so they're
tagged by the PQC algorithm they actually describe. Playbook chunks are
the one thing we author ourselves that legitimately talks about both
sides, so they're tagged by the classical (primitive, usage) they're
migration guidance for, using the same vocabulary as
internal/scanner/rules/go/direct/shor.yaml and findings.Finding.

`algorithm` is the join key between the two: internal/rag.Retrieve
(primitive, usage, topK) resolves (primitive, usage) -> algorithm via
migration_map.yaml first — a deterministic lookup, not something
embedding similarity is asked to infer — then filters standards chunks
by that algorithm. See qsafe.md's chunk-metadata-schema entry for the
full reasoning trail.
"""

from dataclasses import dataclass
from typing import Literal, Optional

DocType = Literal["standard", "playbook"]
Algorithm = Literal["ML-KEM", "ML-DSA", "SLH-DSA"]


@dataclass
class Chunk:
    id: str  # stable reference, e.g. "fips-203#8"
    text: str  # the chunk's content
    source: str  # which document, e.g. "fips-203", "rsa-to-mlkem"
    section: str  # heading text/number, for citation
    algorithm: Algorithm
    doc_type: DocType

    # Playbook chunks only. Standards chunks leave these None — a FIPS
    # document doesn't know which classical primitive it replaces, so
    # tagging it with one would be asserting a relationship the source
    # text never states.
    primitive: Optional[str] = None  # matches Finding.Primitive, e.g. "RSA"
    usage: Optional[str] = None  # matches Finding.Usage, "_migration"-suffixed, e.g. "encryption_migration"

    # Filled in later by embedder.py — a Chunk from chunker.py always
    # has this None; the flat-file index chunker.py's output eventually
    # feeds into always has it populated.
    embedding: Optional[list] = None

    def __post_init__(self):
        if self.doc_type == "standard" and (self.primitive or self.usage):
            raise ValueError(
                f"{self.id}: standard chunks must not carry primitive/usage "
                f"(the source document doesn't know which classical primitive "
                f"it replaces) — got primitive={self.primitive!r} usage={self.usage!r}"
            )
        if self.doc_type == "playbook" and not (self.primitive and self.usage):
            raise ValueError(
                f"{self.id}: playbook chunks must carry both primitive and usage "
                f"— got primitive={self.primitive!r} usage={self.usage!r}"
            )
