"""Hybrid ATT&CK retrieval (Phase 2).

Shared grounding for the ``threatgraph`` pipeline: BM25 (sparse) + Chroma (dense) fused
via ``EnsembleRetriever`` weighted RRF, then a ``CrossEncoder`` rerank of the fused
candidates. The whole pipeline is isolated behind :func:`build_attack_retriever` /
:func:`retrieve_attack_context` so a dense-only fallback is a one-line swap for the timed
live run, and so the graph can *fail open* to a BM25-only offline path when the Chroma
index or the OpenAI key is unavailable (mirroring the ``Safeguard`` fail-open idiom).

**Explicit path resolution (not CWD-relative).** The full corpus lives at repo-root
``data/attack/attack_corpus.jsonl`` (produced by ``scripts/fetch_attack_corpus.py``) and
the Chroma index at ``agent-service-toolkit/chroma_db``. Both the BM25 and dense legs, plus
``scripts/index_attack_corpus.py``, resolve these paths from this module's location so they
read the same files regardless of the launch directory (the service runs from
``agent-service-toolkit/`` while the corpus sits one level up).
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from functools import cache
from pathlib import Path
from typing import Any

from langchain_core.documents import Document

logger = logging.getLogger(__name__)

# --- Explicit, launch-directory-independent paths --------------------------------------
# retrieval.py lives at agent-service-toolkit/src/agents/retrieval.py
_AST_ROOT = Path(__file__).resolve().parents[2]  # agent-service-toolkit/
_REPO_ROOT = _AST_ROOT.parent  # perficient/ (repo root)

CORPUS_PATH = _REPO_ROOT / "data" / "attack" / "attack_corpus.jsonl"
SEED_CORPUS_PATH = _REPO_ROOT / "data" / "attack" / "attack_corpus.seed.jsonl"
CHROMA_DIR = _AST_ROOT / "chroma_db"
ATTACK_COLLECTION = "attack"
RERANKER_MODEL = "cross-encoder/ms-marco-MiniLM-L6-v2"

DEFAULT_K = 5
CANDIDATE_K = 20  # per-leg fan-out before fusion + rerank (broadened for multi-technique recall)
# Reranked context size used to GROUND the extractor. A single incident snippet usually
# describes several distinct techniques (initial access, credential access, lateral movement,
# exfiltration, ...). A small k (e.g. 5) only surfaces the neighbors of the single most salient
# technique, so real techniques get dropped at the "ground-only-what's-retrieved" step. A wider
# window keeps enough distinct techniques in the grounding set for enumerate-then-ground to work.
CONTEXT_K = 15


def resolve_corpus_path() -> Path:
    """Prefer the full fetched corpus; fall back to the tracked 14-record seed corpus."""
    return CORPUS_PATH if CORPUS_PATH.exists() else SEED_CORPUS_PATH


def record_to_document(rec: dict[str, Any]) -> Document:
    """Turn one distilled ATT&CK record into a retrieval ``Document``.

    ``page_content`` = name + tactics + description + mitigations (the text the BM25 and
    dense legs score against); ``metadata`` carries the technique id, tactics, mitigation
    ids, and a JSON round-trip of the full record so callers can reconstruct it losslessly
    (Chroma metadata values must be scalar, so lists are serialized to strings).
    """
    tactics = rec.get("tactics") or []
    mitigations = rec.get("mitigations") or []
    mit_text = "; ".join(f"{m.get('id')} {m.get('name')}" for m in mitigations)
    page_content = "\n".join(
        [
            f"{rec.get('id')} {rec.get('name')}",
            f"Tactics: {', '.join(tactics)}",
            (rec.get("description") or "").strip(),
            f"Mitigations: {mit_text}",
        ]
    )
    metadata = {
        "id": rec.get("id") or "",
        "name": rec.get("name") or "",
        "tactics": ", ".join(tactics),
        "mitigation_ids": ",".join(m.get("id", "") for m in mitigations),
        "record": json.dumps(rec, ensure_ascii=False),
    }
    return Document(page_content=page_content, metadata=metadata)


def load_attack_documents(path: Path | str | None = None) -> list[Document]:
    """Read the ATT&CK JSONL corpus into ``Document``s (offline, no embeddings)."""
    src = Path(path) if path is not None else resolve_corpus_path()
    docs: list[Document] = []
    with src.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            docs.append(record_to_document(json.loads(line)))
    return docs


def document_to_record(doc: Document) -> dict[str, Any]:
    """Reconstruct the distilled ATT&CK record from a retrieved ``Document``."""
    raw = doc.metadata.get("record")
    if raw:
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            logger.debug("Malformed record metadata; reconstructing from fields.")
    return {
        "id": doc.metadata.get("id"),
        "name": doc.metadata.get("name"),
        "tactics": [t for t in (doc.metadata.get("tactics") or "").split(", ") if t],
        "description": doc.page_content,
        "mitigations": [],
    }


# --- Individual retrieval legs (each constructable in isolation for testing) -----------


def build_bm25_retriever(docs: list[Document], k: int = CANDIDATE_K):
    """The sparse leg — pure lexical BM25 (offline, no embeddings/network)."""
    from langchain_community.retrievers import BM25Retriever

    retriever = BM25Retriever.from_documents(docs)
    retriever.k = k
    return retriever


def build_dense_retriever(k: int = CANDIDATE_K):
    """The dense leg — Chroma over OpenAI embeddings from the persisted ``attack`` index."""
    from langchain_chroma import Chroma
    from langchain_openai import OpenAIEmbeddings

    chroma = Chroma(
        persist_directory=str(CHROMA_DIR),
        collection_name=ATTACK_COLLECTION,
        embedding_function=OpenAIEmbeddings(),
    )
    return chroma.as_retriever(search_kwargs={"k": k})


def build_ensemble_retriever(
    docs: list[Document],
    k: int = CANDIDATE_K,
    weights: tuple[float, float] = (0.5, 0.5),
):
    """Fuse the sparse + dense legs with weighted Reciprocal Rank Fusion."""
    from langchain_classic.retrievers import EnsembleRetriever

    sparse = build_bm25_retriever(docs, k=k)
    dense = build_dense_retriever(k=k)
    return EnsembleRetriever(retrievers=[sparse, dense], weights=list(weights))


@cache
def _get_reranker():
    """Lazily load (and cache) the cross-encoder. First call downloads the model."""
    from sentence_transformers import CrossEncoder

    return CrossEncoder(RERANKER_MODEL)


def rerank_documents(query: str, docs: list[Document], k: int = DEFAULT_K) -> list[Document]:
    """Cross-encoder rerank of fused candidates; returns the top ``k``."""
    if not docs:
        return []
    reranker = _get_reranker()
    scores = reranker.predict([(query, d.page_content) for d in docs])
    ranked = sorted(zip(scores, docs), key=lambda pair: pair[0], reverse=True)
    return [doc for _, doc in ranked[:k]]


# --- Composed hybrid retriever + top-level grounding function --------------------------


@cache
def build_attack_retriever() -> Callable[[str, int], list[Document]]:
    """Cached hybrid retriever: BM25 + dense RRF fusion, then cross-encoder rerank.

    Returns a callable ``(query, k) -> list[Document]``. Isolated here so the live run can
    swap in a dense-only (or BM25-only) leg by editing this one function.
    """
    docs = load_attack_documents()
    ensemble = build_ensemble_retriever(docs)

    def _retrieve(query: str, k: int = DEFAULT_K) -> list[Document]:
        fused = ensemble.invoke(query)
        # RRF fusion is the recall/DIVERSITY mechanism here: it interleaves the
        # sparse + dense legs so distinct techniques (initial access, credential
        # access, lateral movement, exfiltration, ...) each surface. A single-query
        # cross-encoder rerank over the *whole* fused set instead collapses to the one
        # most salient cluster (e.g. every credential-dump sub-technique), starving a
        # multi-technique incident of its other techniques and causing the extractor
        # to under-extract. So take the RRF-diverse top-k as the grounding *membership*
        # and use the cross-encoder only to *reorder* that already-diverse window.
        diverse = fused[:k]
        return rerank_documents(query, diverse, k=k)

    return _retrieve


def _bm25_only(query: str, k: int) -> list[Document]:
    """Offline fail-open leg — BM25 over whatever corpus is on disk (full or seed)."""
    try:
        docs = load_attack_documents()
        return build_bm25_retriever(docs, k=k).invoke(query)[:k]
    except Exception:
        logger.exception("BM25 fallback retrieval failed")
        return []


def retrieve_attack_context(query: str, k: int = DEFAULT_K) -> list[dict[str, Any]]:
    """Return fused + reranked ATT&CK records for ``query``.

    Tries the full hybrid pipeline; **fails open** to a BM25-only offline path when the
    dense leg is unavailable (no Chroma index / no OpenAI key / network down) so the graph
    never hard-crashes — consistent with the toolkit's ``Safeguard`` fail-open philosophy.
    """
    try:
        retriever = build_attack_retriever()
        docs = retriever(query, k)
    except Exception as exc:  # noqa: BLE001 — fail open, log and degrade gracefully
        logger.warning(
            "Hybrid ATT&CK retrieval unavailable (%s); falling back to BM25-only.", exc
        )
        docs = _bm25_only(query, k)
    return [document_to_record(doc) for doc in docs]
