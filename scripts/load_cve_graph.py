"""Loads the CVE/CWE/CAPEC/ATT&CK dataset (data/cve_graph_data.json) into
Neo4j, embedding each CVE's description via Voyage AI and creating a
vector index for GraphRAG's hybrid retrieval (tools/graphrag.py).

Run scripts/build_cve_graph_data.py first to produce the input file.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import voyageai
from neo4j import GraphDatabase

from incident_agents.config import get_neo4j_config, get_voyage_key
from incident_agents.tools.graphrag import EMBEDDING_MODEL, VECTOR_INDEX_NAME

EMBEDDING_DIMENSIONS = 1024


def load_dataset() -> dict:
    path = Path("data") / "cve_graph_data.json"
    if not path.exists():
        raise SystemExit(f"{path} not found — run scripts/build_cve_graph_data.py first.")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def embed_cves(cves: list[dict]) -> list[dict]:
    voyage_key = get_voyage_key()
    if not voyage_key:
        raise SystemExit("VOYAGE_API_KEY not set — add it to .env first.")

    client = voyageai.Client(api_key=voyage_key)
    texts = [f"{c['id']}: {c['description']}" for c in cves]

    # Voyage AI batch limits are generous, but chunk defensively for large datasets.
    embedded = []
    batch_size = 100
    for i in range(0, len(texts), batch_size):
        batch = texts[i : i + batch_size]
        result = client.embed(texts=batch, model=EMBEDDING_MODEL, input_type="document")
        for cve, embedding in zip(cves[i : i + batch_size], result.embeddings):
            embedded.append({**cve, "embedding": embedding})
    return embedded


def load_into_neo4j(dataset: dict, embedded_cves: list[dict]) -> None:
    config = get_neo4j_config()
    if not config:
        raise SystemExit("NEO4J_URI / NEO4J_USERNAME / NEO4J_PASSWORD not fully set in .env.")
    uri, username, password = config
    driver = GraphDatabase.driver(uri, auth=(username, password))

    try:
        driver.execute_query("CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (c:CVE) REQUIRE c.id IS UNIQUE")
        driver.execute_query("CREATE CONSTRAINT cwe_id IF NOT EXISTS FOR (c:CWE) REQUIRE c.id IS UNIQUE")
        driver.execute_query("CREATE CONSTRAINT capec_id IF NOT EXISTS FOR (c:CAPEC) REQUIRE c.id IS UNIQUE")
        driver.execute_query(
            "CREATE CONSTRAINT attack_id IF NOT EXISTS FOR (a:AttackTechnique) REQUIRE a.id IS UNIQUE"
        )

        driver.execute_query(
            "UNWIND $cwes AS cwe MERGE (c:CWE {id: cwe.id}) SET c.detection_pattern = cwe.detection_pattern",
            cwes=dataset["cwes"],
        )

        driver.execute_query(
            """
            UNWIND $cves AS cve
            MERGE (c:CVE {id: cve.id})
            SET c.description = cve.description,
                c.cvss_score = cve.cvss_score,
                c.published = cve.published,
                c.embedding = cve.embedding
            WITH c, cve
            MATCH (w:CWE {id: cve.cwe_id})
            MERGE (c)-[:HAS_WEAKNESS]->(w)
            """,
            cves=embedded_cves,
        )

        driver.execute_query(
            """
            UNWIND $mappings AS m
            MERGE (capec:CAPEC {id: m.capec_id})
            SET capec.name = m.capec_name
            MERGE (attack:AttackTechnique {id: m.attack_id})
            SET attack.name = m.attack_name
            MERGE (capec)-[:MAPS_TO]->(attack)
            WITH capec, m
            UNWIND m.cwe_ids AS cwe_id
            MATCH (w:CWE {id: cwe_id})
            MERGE (w)-[:RELATED_TO]->(capec)
            """,
            mappings=dataset["capec_attack_mappings"],
        )

        driver.execute_query(
            f"""
            CREATE VECTOR INDEX {VECTOR_INDEX_NAME} IF NOT EXISTS
            FOR (c:CVE) ON c.embedding
            OPTIONS {{indexConfig: {{
                `vector.dimensions`: {EMBEDDING_DIMENSIONS},
                `vector.similarity_function`: 'cosine'
            }}}}
            """
        )

        counts, _, _ = driver.execute_query(
            "MATCH (c:CVE) RETURN count(c) AS cve_count "
            "UNION ALL MATCH (w:CWE) RETURN count(w) AS cve_count "
            "UNION ALL MATCH (p:CAPEC) RETURN count(p) AS cve_count "
            "UNION ALL MATCH (a:AttackTechnique) RETURN count(a) AS cve_count"
        )
        print(f"Loaded — CVE: {counts[0][0]}, CWE: {counts[1][0]}, CAPEC: {counts[2][0]}, AttackTechnique: {counts[3][0]}")
    finally:
        driver.close()


def main() -> None:
    dataset = load_dataset()
    print(f"Embedding {len(dataset['cves'])} CVE descriptions via Voyage AI ({EMBEDDING_MODEL})...")
    embedded_cves = embed_cves(dataset["cves"])
    print("Loading into Neo4j...")
    load_into_neo4j(dataset, embedded_cves)
    print("Done.")


if __name__ == "__main__":
    main()
