"""Tests for the markdown chunker and the Qdrant knowledge base."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.rag.chunker import chunk_markdown

RUNBOOKS_DIR = Path(__file__).resolve().parents[1] / "runbooks"


# ── chunker ──
DOC = """# DNS resolution failures

Intro paragraph.

## Symptoms

- getaddrinfo ENOTFOUND

## Diagnose

```bash
# this is a shell comment, not a heading
dig +short api.example.com
```

### Delegation

Check NS records.

## Empty

## Remediate

Fix the record.
"""


def test_chunks_follow_headings_with_doc_title_prefix() -> None:
    chunks = chunk_markdown(DOC, "dns.md")
    titles = [c["title"] for c in chunks]
    assert titles == [
        "DNS resolution failures",
        "DNS resolution failures › Symptoms",
        "DNS resolution failures › Diagnose",
        "DNS resolution failures › Diagnose › Delegation",
        "DNS resolution failures › Remediate",
    ]
    assert all(c["source"] == "dns.md" for c in chunks)
    assert all(c["text"] for c in chunks)


def test_headings_inside_code_fences_are_ignored() -> None:
    diagnose = next(c for c in chunk_markdown(DOC, "dns.md") if c["title"].endswith("Diagnose"))
    assert "# this is a shell comment" in diagnose["text"]
    assert "dig +short" in diagnose["text"]


def test_long_sections_split_on_paragraphs() -> None:
    paras = [f"Paragraph {i}. " + "word " * 40 for i in range(10)]
    text = "# Title\n\n## Long\n\n" + "\n\n".join(paras)
    chunks = chunk_markdown(text, "long.md", max_chars=500)
    assert len(chunks) > 1
    assert all(len(c["text"]) <= 500 for c in chunks)
    assert all(c["title"] == "Title › Long" for c in chunks)
    assert all(c["text"].startswith("Paragraph") for c in chunks)
    joined = " ".join(c["text"] for c in chunks)
    assert all(f"Paragraph {i}." in joined for i in range(10))


def test_oversized_paragraph_is_hard_split() -> None:
    text = "# T\n\n" + "x" * 2500
    chunks = chunk_markdown(text, "big.md", max_chars=900)
    assert len(chunks) == 3
    assert all(len(c["text"]) <= 900 for c in chunks)


def test_empty_and_headingless_docs() -> None:
    assert chunk_markdown("", "empty.md") == []
    assert chunk_markdown("# Only a title\n\n## Nothing\n", "t.md") == []
    chunks = chunk_markdown("plain text, no headings", "plain.md")
    assert chunks == [{"source": "plain.md", "title": "plain.md", "text": "plain text, no headings"}]


def test_seed_runbooks_have_required_sections() -> None:
    files = sorted(RUNBOOKS_DIR.glob("*.md"))
    assert {f.name for f in files} == {
        "timeout.md",
        "dns.md",
        "tls.md",
        "server-errors-5xx.md",
        "auth-401-403.md",
        "not-found-404-deploy.md",
        "connection-refused.md",
    }
    for f in files:
        text = f.read_text(encoding="utf-8")
        assert text.startswith("# "), f.name
        for section in ("## Symptoms", "## Likely causes", "## Diagnose", "## Remediate"):
            assert section in text, f"{f.name} missing {section}"
        assert "## When to pause the monitor / escalate" in text, f.name


# ── knowledge base ──
@pytest.fixture(scope="module")
def kb():
    from app.rag.store import KnowledgeBase

    base = KnowledgeBase(url=":memory:")
    base.ensure_collections()
    assert base.index_runbooks_dir(RUNBOOKS_DIR) > 7
    return base


def _count(kb, collection: str) -> int:
    return kb.client.count(collection_name=collection, exact=True).count


def test_embedding_dim_is_derived_from_model(kb) -> None:
    assert kb.dim == 384


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("getaddrinfo ENOTFOUND api.example.com", "dns.md"),
        ("certificate has expired", "tls.md"),
        ("Expected 200, got 503 Service Unavailable", "server-errors-5xx.md"),
        ("ECONNABORTED timeout of 5000ms exceeded", "timeout.md"),
        ("connect ECONNREFUSED 10.0.0.5:443", "connection-refused.md"),
    ],
)
def test_search_top_hit(kb, query: str, expected: str) -> None:
    docs = kb.search(query, k=3)
    assert docs, query
    assert docs[0].source == expected, [(d.source, d.title, round(d.score, 3)) for d in docs]


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("Expected 200, got 401 Unauthorized", "auth-401-403.md"),
        ("Expected 200, got 404 after deploy", "not-found-404-deploy.md"),
        ("UNABLE_TO_VERIFY_LEAF_SIGNATURE", "tls.md"),
        ("getaddrinfo EAI_AGAIN", "dns.md"),
    ],
)
def test_search_hit_at_3(kb, query: str, expected: str) -> None:
    sources = [d.source for d in kb.search(query, k=3)]
    assert expected in sources, sources


def test_search_results_are_sorted_and_typed(kb) -> None:
    docs = kb.search("server returns 502 bad gateway", k=5)
    assert len(docs) == 5
    assert [d.score for d in docs] == sorted((d.score for d in docs), reverse=True)
    assert all(d.title and d.text for d in docs)


def test_reindexing_same_source_replaces_points(kb) -> None:
    before = _count(kb, "runbooks")
    text = (RUNBOOKS_DIR / "dns.md").read_text(encoding="utf-8")
    kb.index_runbook(text, "dns.md")
    assert _count(kb, "runbooks") == before

    assert kb.index_runbook("# Tiny\n\n## Only\n\nOne section.", "tiny.md") == 1
    assert kb.index_runbook("# Tiny\n\n## Only\n\nStill one section.", "tiny.md") == 1
    assert _count(kb, "runbooks") == before + 1
    kb.index_runbook("", "tiny.md")
    assert _count(kb, "runbooks") == before


def test_past_incidents_are_scoped_to_their_user(kb) -> None:
    text = (
        "Monitor 'billing-api' DOWN: getaddrinfo ENOTFOUND billing.internal.example. "
        "Root cause: the CNAME was deleted during a DNS provider migration. Restored the record."
    )
    kb.index_incident("evt-123", "user-a", text, "dns")
    kb.index_incident("evt-123", "user-a", text, "dns")
    assert _count(kb, "past_incidents") == 1

    query = "billing-api ENOTFOUND billing.internal.example CNAME deleted"
    owner = kb.search(query, k=5, user_id="user-a")
    assert "incident:evt-123" in [d.source for d in owner]
    hit = next(d for d in owner if d.source == "incident:evt-123")
    assert hit.text == text

    other = kb.search(query, k=5, user_id="user-b")
    anonymous = kb.search(query, k=5)
    assert all(not d.source.startswith("incident:") for d in other + anonymous)
