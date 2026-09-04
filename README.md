# Aegis

AI Cyber Defense Multi-Agent System — a 6-stage LangGraph pipeline (Ingest → Detect → Classify → Reflect → Respond → Report) built on Anthropic Claude, with a GraphRAG layer (Neo4j + Voyage AI) grounding threat classification in real CVE/CWE/ATT&CK data.

Aegis is a decision-support system: it detects and triages security incidents from log data and produces a prioritized incident report for a human analyst to act on. The one narrow exception is auto-blocking a confirmed-malicious IP to a local blocklist — every other recommended action always waits for a human.

## Status

Design and planning phase — see [PROJECT_DOCUMENTATION.md](./PROJECT_DOCUMENTATION.md) for the full architecture, all scope decisions, and the phased build plan. No implementation code yet.

## Planned stack

- **Orchestration:** LangGraph
- **LLM:** Anthropic Claude
- **RAG:** GraphRAG — Neo4j knowledge graph (CVE→CWE→ATT&CK) + Voyage AI embeddings for hybrid retrieval
- **Threat intel:** AbuseIPDB
- **Interfaces:** CLI + Gradio web app
- **Alerting:** Slack webhook

## Build phases

1. Core 6-stage pipeline on Claude (CSV+JSON ingestion, configurable thresholds, PII anonymization, reflection loop, bounded auto-block)
2. Real integrations (AbuseIPDB, Slack)
3. GraphRAG layer (Neo4j + Voyage AI)
4. Persistent cross-run memory

Tracked on the [project board](https://github.com/users/dineshyadav03/projects/1).
