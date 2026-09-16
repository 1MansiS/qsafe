"""Regression tests for chunker.py, using a small synthetic markdown
fixture rather than the real downloaded FIPS 203 PDF — self-contained,
no network/corpus-file dependency, same reasoning as the Go side keeping
interface-dispatch tests off live external repos. The fixture
deliberately reproduces every real artifact found reviewing the actual
pymupdf4llm output: a false heading from a figure/diagram (Alice/Bob), a
bare numbered wrapper with no content of its own, a figure caption, page
furniture, and an excluded-but-real heading (References) that must still
act as a boundary.
"""

from ingest.chunker import chunk_fips_203

FIXTURE = """\
### **1. Introduction**

#### **1.1 Purpose and Scope**

This standard specifies ML-KEM.

### **3. Overview of the ML-KEM Scheme**

This section gives a high-level overview.

#### **3.1 Key-Encapsulation Mechanisms**

A KEM has three algorithms.

### Alice Bob

FIPS 203 MODULE-LATTICE-BASED KEY-ENCAPSULATION MECHANISM

12

**Figure** **1.** **A** **simple** **view** **of** **key** **establishment**

### 𝐾 [′] 𝐾

Alice and Bob complete the exchange.

#### **8. Parameter Sets**

NIST recommends ML-KEM-768 as the default parameter set.

#### **References**

[1] Some citation that must never appear in section 8's chunk.
"""


def test_include_list_matches_fixture_sections():
    # Fixture deliberately covers only a subset of FIPS_203_INCLUDE (1,
    # 1.1, 3, 3.1, 8 — enough to exercise every artifact) plus the
    # excluded-but-real "References" heading. "1" has no content of its
    # own in the fixture (same as the real document) and must not
    # produce a chunk.
    got = {c.id for c in chunk_fips_203(FIXTURE)}
    assert got == {"fips-203#1.1", "fips-203#3", "fips-203#3.1", "fips-203#8"}, got


def test_bare_wrapper_with_no_content_is_dropped():
    ids = {c.id for c in chunk_fips_203(FIXTURE)}
    assert "fips-203#1" not in ids


def test_false_heading_folds_into_surrounding_chunk_not_a_boundary():
    chunks = {c.id: c for c in chunk_fips_203(FIXTURE)}
    text = chunks["fips-203#3.1"].text
    assert "Alice Bob" in text
    assert "Alice and Bob complete the exchange." in text
    assert "#" not in text  # no leaked markdown heading marker


def test_page_furniture_and_figure_caption_stripped():
    chunks = {c.id: c for c in chunk_fips_203(FIXTURE)}
    text = chunks["fips-203#3.1"].text
    assert "FIPS 203 MODULE-LATTICE-BASED" not in text
    assert "\n12\n" not in text
    assert "Figure" not in text


def test_excluded_heading_still_acts_as_boundary():
    chunks = {c.id: c for c in chunk_fips_203(FIXTURE)}
    text = chunks["fips-203#8"].text
    assert "citation that must never appear" not in text
    assert "NIST recommends ML-KEM-768" in text


def test_every_chunk_is_well_formed():
    for c in chunk_fips_203(FIXTURE):
        assert c.source == "fips-203"
        assert c.algorithm == "ML-KEM"
        assert c.doc_type == "standard"
        assert c.primitive is None and c.usage is None
        assert c.text.strip() == c.text and c.text  # no leading/trailing whitespace, non-empty
