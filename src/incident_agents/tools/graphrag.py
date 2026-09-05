"""GraphRAG retrieval tool: hybrid Voyage AI vector search + Neo4j graph
traversal over the CVE/CWE/CAPEC/ATT&CK knowledge graph.

See PROJECT_DOCUMENTATION.md §5.10 for the design rationale (why GraphRAG
instead of plain vector RAG) and scripts/load_cve_graph.py for how the
graph gets populated.
"""

from __future__ import annotations

import time
from functools import lru_cache
from typing import Any

from ..config import get_neo4j_driver, get_voyage_key

EMBEDDING_MODEL = "voyage-4-lite"
VECTOR_INDEX_NAME = "cve_embedding_index"
TOP_K = 3
_MAX_RETRIES = 3


@lru_cache(maxsize=256)
def _embed_query(text: str) -> list[float] | None:
    """Returns None (never raises) if Voyage AI isn't configured or the call
    fails for any reason — including the free tier's reduced 3 RPM limit
    without a payment method on file (a real Voyage AI behavior confirmed
    live 2026-09-05; retried with backoff since Classify may call this
    several times per run, one per finding).
    """
    voyage_key = get_voyage_key()
    if not voyage_key:
        return None

    import voyageai

    client = voyageai.Client(api_key=voyage_key)
    for attempt in range(_MAX_RETRIES):
        try:
            result = client.embed(texts=[text], model=EMBEDDING_MODEL, input_type="query")
            return result.embeddings[0]
        except Exception:  # noqa: BLE001 — degrade gracefully, never crash the pipeline
            if attempt < _MAX_RETRIES - 1:
                time.sleep(20)  # Voyage free-tier limit is 3 RPM -> ~20s between requests
    return None


def cve_graph_retrieval_tool(finding_description: str) -> dict[str, Any]:
    """Retrieves CVE/CWE/CAPEC/ATT&CK context relevant to a finding.

    Hybrid retrieval: (1) embed the finding description via Voyage AI and
    vector-search the nearest CVE node(s) in Neo4j, then (2) traverse the
    graph from those nodes to pull in the connected CWE, CAPEC, and ATT&CK
    technique context vector similarity alone would miss.

    Returns an empty result (never raises) if Neo4j or Voyage AI aren't
    configured — Classify proceeds on rule-based severity alone, same
    graceful-degradation pattern as every other external service here.
    """
    try:
        driver = get_neo4j_driver()
    except Exception as exc:  # noqa: BLE001 — e.g. malformed URI — degrade gracefully
        return {"available": False, "reason": f"Neo4j driver init failed: {exc}", "matches": []}
    if driver is None:
        return {"available": False, "reason": "Neo4j not configured", "matches": []}

    query_embedding = _embed_query(finding_description)
    if query_embedding is None:
        driver.close()
        return {"available": False, "reason": "Voyage AI not configured", "matches": []}

    try:
        # NOTE: db.index.vector.queryNodes is deprecated (Neo4j 2026.04) in
        # favor of the Cypher 25 SEARCH clause, but confirmed still
        # functional (deprecation warning only, not removed) and this exact
        # query is verified working end-to-end against live data. The new
        # SEARCH clause's documented syntax (FOR node.property) is built for
        # node-to-node similarity, not searching by an ad-hoc query vector
        # like ours (a fresh embedding not tied to any stored node) — left
        # as-is pending clearer documentation of that syntax's raw-vector
        # form, rather than risk breaking a working, tested integration.
        records, _, _ = driver.execute_query(
            f"""
            CALL db.index.vector.queryNodes('{VECTOR_INDEX_NAME}', $top_k, $embedding)
            YIELD node AS cve, score
            MATCH (cve)-[:HAS_WEAKNESS]->(cwe:CWE)
            OPTIONAL MATCH (cwe)-[:RELATED_TO]->(capec:CAPEC)-[:MAPS_TO]->(attack:AttackTechnique)
            RETURN cve.id AS cve_id, cve.description AS cve_description,
                   cve.cvss_score AS cvss_score, score,
                   cwe.id AS cwe_id,
                   collect(DISTINCT {{capec_id: capec.id, capec_name: capec.name,
                                      attack_id: attack.id, attack_name: attack.name}}) AS attack_context
            """,
            embedding=query_embedding,
            top_k=TOP_K,
        )
    except Exception as exc:  # noqa: BLE001 — graph query failure degrades gracefully
        driver.close()
        return {"available": False, "reason": str(exc), "matches": []}

    driver.close()

    matches = []
    for r in records:
        seen_attack_ids: set[str] = set()
        deduped_attack_context = []
        for a in r["attack_context"]:
            if a.get("attack_id") and a["attack_id"] not in seen_attack_ids:
                seen_attack_ids.add(a["attack_id"])
                deduped_attack_context.append(a)
        matches.append(
            {
                "cve_id": r["cve_id"],
                "cve_description": r["cve_description"],
                "cvss_score": r["cvss_score"],
                "similarity_score": r["score"],
                "cwe_id": r["cwe_id"],
                "attack_context": deduped_attack_context,
            }
        )
    return {"available": True, "matches": matches}
