"""Tests for the hybrid ATT&CK retriever (Phase 2).

These run fully offline against the tracked 14-record **seed** corpus
(``data/attack/attack_corpus.seed.jsonl``) — no OpenAI embeddings and no model download on
the default path. The BM25 leg and the RRF fusion are exercised directly; the cross-encoder
rerank (which downloads ``cross-encoder/ms-marco-MiniLM-L6-v2``) is marked ``integration``
and skipped unless ``--run-integration`` is passed (mirrors the ``--run-docker`` pattern).
"""

import pytest

from agents.retrieval import (
    SEED_CORPUS_PATH,
    build_bm25_retriever,
    build_ensemble_retriever,
    document_to_record,
    load_attack_documents,
    rerank_documents,
)


def _ids(docs) -> list[str]:
    return [d.metadata.get("id") for d in docs]


def test_seed_corpus_loads():
    docs = load_attack_documents(SEED_CORPUS_PATH)
    assert len(docs) == 14
    # The page_content and record round-trip carry the technique id.
    ids = _ids(docs)
    assert "T1566.001" in ids
    assert document_to_record(docs[0])["id"] == docs[0].metadata["id"]


def test_bm25_spearphishing_query_returns_t1566_001():
    """A 'spearphishing attachment macro' query surfaces T1566.001 in the top-k."""
    docs = load_attack_documents(SEED_CORPUS_PATH)
    retriever = build_bm25_retriever(docs, k=5)
    results = retriever.invoke("spearphishing attachment macro email")
    assert "T1566.001" in _ids(results)


def test_rrf_returns_union_of_legs():
    """EnsembleRetriever (weighted RRF) fuses the union of both legs' results.

    Two BM25 legs over disjoint document subsets stand in for the sparse+dense legs so the
    fusion behavior is verified without OpenAI embeddings. The fused result must contain ids
    contributed by *both* legs.
    """
    docs = load_attack_documents(SEED_CORPUS_PATH)
    by_id = {d.metadata["id"]: d for d in docs}
    leg_a_docs = [by_id["T1566.001"], by_id["T1204.002"]]  # phishing / user-execution
    leg_b_docs = [by_id["T1486"], by_id["T1490"]]  # ransomware impact

    leg_a = build_bm25_retriever(leg_a_docs, k=5)
    leg_b = build_bm25_retriever(leg_b_docs, k=5)

    from langchain_classic.retrievers import EnsembleRetriever

    ensemble = EnsembleRetriever(retrievers=[leg_a, leg_b], weights=[0.5, 0.5])
    fused_ids = set(_ids(ensemble.invoke("phishing attachment encrypts files for ransom")))

    # Union: at least one id from each leg is present in the fused output.
    assert fused_ids & {"T1566.001", "T1204.002"}, "leg A contribution missing"
    assert fused_ids & {"T1486", "T1490"}, "leg B contribution missing"


def test_build_ensemble_retriever_wires_both_legs(monkeypatch):
    """build_ensemble_retriever wires a BM25 leg + a (stubbed) dense leg with RRF weights."""
    docs = load_attack_documents(SEED_CORPUS_PATH)

    # Stub the dense leg so no OpenAI/Chroma is touched.
    sentinel = build_bm25_retriever(docs, k=5)
    monkeypatch.setattr("agents.retrieval.build_dense_retriever", lambda k=10: sentinel)

    ensemble = build_ensemble_retriever(docs, k=10, weights=(0.5, 0.5))
    assert len(ensemble.retrievers) == 2
    assert ensemble.weights == [0.5, 0.5]


@pytest.mark.integration
def test_cross_encoder_rerank_reorders():
    """The cross-encoder rerank reorders fused candidates by query relevance.

    Opt-in (``--run-integration``): downloads ``cross-encoder/ms-marco-MiniLM-L6-v2``.
    """
    docs = load_attack_documents(SEED_CORPUS_PATH)
    by_id = {d.metadata["id"]: d for d in docs}
    # Feed candidates in a deliberately wrong order (relevant doc last).
    candidates = [by_id["T1486"], by_id["T1059.001"], by_id["T1566.001"]]
    reranked = rerank_documents("spearphishing attachment macro email", candidates, k=3)
    # The most relevant technique should be promoted to the top after reranking.
    assert reranked[0].metadata["id"] == "T1566.001"
