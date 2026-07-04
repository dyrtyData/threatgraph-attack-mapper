#!/usr/bin/env python3
"""Build the dense Chroma index for the ATT&CK corpus (Phase 2).

Reads the distilled ATT&CK JSONL (``data/attack/attack_corpus.jsonl`` at repo root,
produced by ``scripts/fetch_attack_corpus.py``), turns each technique into a retrieval
``Document`` (name + tactics + description + mitigations), embeds it with
``OpenAIEmbeddings``, and persists it to a dedicated ``attack`` collection in
``agent-service-toolkit/chroma_db``.

This adapts the toolkit's ``create_chroma_db.py`` scaffold (which only loads pdf/docx from
``./data``) to the structured ATT&CK JSONL corpus, and reuses the exact same document
shaping + path resolution as ``src/agents/retrieval.py`` so the dense leg and the BM25 leg
index identical text regardless of launch directory.

Usage:
    uv run python scripts/index_attack_corpus.py
    # → persists agent-service-toolkit/chroma_db  (collection "attack")

Requires ``OPENAI_API_KEY`` (embeddings are called for every record). The wall-clock build
time is printed for the PROGRESS.md timing table.
"""

from __future__ import annotations

import shutil
import sys
import time
from pathlib import Path

from dotenv import find_dotenv, load_dotenv

# Load the env (OPENAI_API_KEY) *before* importing the agents package: its __init__
# eagerly constructs models at import time, which needs the key present.
load_dotenv(find_dotenv())

# Make ``src`` importable when run as a plain script from the toolkit root.
_AST_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_AST_ROOT / "src"))

from agents.retrieval import (  # noqa: E402
    ATTACK_COLLECTION,
    CHROMA_DIR,
    load_attack_documents,
    resolve_corpus_path,
)


def build_index(delete_existing: bool = True) -> int:
    """Embed + persist the ATT&CK corpus into the ``attack`` Chroma collection.

    Returns the number of indexed records.
    """
    from langchain_chroma import Chroma
    from langchain_openai import OpenAIEmbeddings

    corpus_path = resolve_corpus_path()
    docs = load_attack_documents(corpus_path)
    print(f"Loaded {len(docs)} ATT&CK records from {corpus_path}")

    if delete_existing and CHROMA_DIR.exists():
        shutil.rmtree(CHROMA_DIR)
        print(f"Deleted existing Chroma index at {CHROMA_DIR}")

    started = time.perf_counter()
    Chroma.from_documents(
        documents=docs,
        embedding=OpenAIEmbeddings(),
        collection_name=ATTACK_COLLECTION,
        persist_directory=str(CHROMA_DIR),
    )
    elapsed = time.perf_counter() - started
    print(
        f"Indexed {len(docs)} records into collection '{ATTACK_COLLECTION}' at "
        f"{CHROMA_DIR} in {elapsed:.2f}s"
    )
    return len(docs)


def main() -> None:
    build_index()


if __name__ == "__main__":
    main()
