import pytest

from ingest.schema import Chunk


def test_standard_chunk_valid():
    c = Chunk(id="fips-203#8", text="...", source="fips-203", section="8 Parameter Sets", algorithm="ML-KEM", doc_type="standard")
    assert c.primitive is None and c.usage is None


def test_playbook_chunk_valid():
    c = Chunk(
        id="rsa-to-mlkem#1",
        text="...",
        source="rsa-to-mlkem",
        section="Overview",
        algorithm="ML-KEM",
        doc_type="playbook",
        primitive="RSA",
        usage="encryption_migration",
    )
    assert c.primitive == "RSA" and c.usage == "encryption_migration"


def test_standard_chunk_rejects_primitive():
    with pytest.raises(ValueError):
        Chunk(id="bad", text="x", source="fips-203", section="x", algorithm="ML-KEM", doc_type="standard", primitive="RSA")


def test_playbook_chunk_requires_primitive_and_usage():
    with pytest.raises(ValueError):
        Chunk(id="bad", text="x", source="rsa-to-mlkem", section="x", algorithm="ML-KEM", doc_type="playbook", primitive="RSA")
