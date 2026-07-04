#!/usr/bin/env python3
"""Fetch the official MITRE Enterprise ATT&CK STIX bundle and distill it into a
compact JSONL corpus (one technique per line, with its linked mitigations) for RAG.

Why distill: the raw STIX bundle is ~35 MB of nested JSON — too heavy and noisy to
embed directly. The distilled JSONL is a few MB and matches the schema the pipeline
expects (same shape as data/attack/attack_corpus.seed.jsonl).

Usage:
    uv run python scripts/fetch_attack_corpus.py
    # → writes data/attack/attack_corpus.jsonl  (comprehensive, ~650+ techniques)

The raw bundle is cached at data/attack/enterprise-attack.json (git-ignored).
No API key required — the data is public.
"""
from __future__ import annotations

import json
import pathlib
import urllib.request

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
DATA_DIR = pathlib.Path(__file__).resolve().parent.parent / "data" / "attack"
RAW = DATA_DIR / "enterprise-attack.json"
OUT = DATA_DIR / "attack_corpus.jsonl"


def download() -> dict:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not RAW.exists():
        print(f"Downloading Enterprise ATT&CK STIX → {RAW} ...")
        urllib.request.urlretrieve(STIX_URL, RAW)  # noqa: S310 (trusted MITRE URL)
    return json.loads(RAW.read_text())


def distill(bundle: dict) -> list[dict]:
    objs = bundle["objects"]

    def attack_id(o: dict) -> str | None:
        for ref in o.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id")
        return None

    # Index mitigations (course-of-action) and technique↔mitigation relationships.
    mitigations = {
        o["id"]: {"id": attack_id(o), "name": o.get("name")}
        for o in objs
        if o.get("type") == "course-of-action"
    }
    mitigates: dict[str, list[dict]] = {}
    for o in objs:
        if o.get("type") == "relationship" and o.get("relationship_type") == "mitigates":
            tgt, src = o.get("target_ref"), o.get("source_ref")
            if tgt and src in mitigations:
                mitigates.setdefault(tgt, []).append(mitigations[src])

    rows = []
    for o in objs:
        if o.get("type") != "attack-pattern" or o.get("x_mitre_deprecated") or o.get("revoked"):
            continue
        tid = attack_id(o)
        if not tid:
            continue
        rows.append(
            {
                "id": tid,
                "name": o.get("name"),
                "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", [])],
                "description": (o.get("description") or "").strip(),
                "mitigations": mitigates.get(o["id"], []),
            }
        )
    rows.sort(key=lambda r: r["id"])
    return rows


def main() -> None:
    rows = distill(download())
    with OUT.open("w") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"Wrote {len(rows)} techniques → {OUT}")


if __name__ == "__main__":
    main()
