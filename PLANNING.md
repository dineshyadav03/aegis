# Aegis — Build Plan

This is the execution plan. For *why* each decision was made, see [PROJECT_DOCUMENTATION.md](./PROJECT_DOCUMENTATION.md) — this file is about *what to do, in what order*.

---

## 0. Prerequisites Checklist (before writing any code)

| # | Item | Status | Blocks |
|---|---|---|---|
| 1 | Anthropic API key | ❌ **Not yet obtained** — get one at [console.anthropic.com](https://console.anthropic.com) | Phase 1 (everything) |
| 2 | Python 3.11+ installed locally | Assumed present — verify with `python --version` | Phase 1 |
| 3 | Synthetic test dataset (`data/security_logs.csv` / `.json`) | ❌ **Does not exist** — the reference tutorial's dataset was never captured in the screenshots, only its output. Must generate our own (Task 1.1 below). | Phase 1 testing |
| 4 | `.env` file with real secrets, based on `.env.example` | ❌ Not created (correctly — never commit this) | Phase 1 |
| 5 | AbuseIPDB API key | Not yet obtained — free signup at [abuseipdb.com](https://www.abuseipdb.com/) | Phase 2 |
| 6 | Slack incoming webhook URL | Not yet created — needs a Slack workspace + an app with Incoming Webhooks enabled | Phase 2 |
| 7 | Voyage AI API key | Not yet obtained — free signup at [voyageai.com](https://www.voyageai.com/) | Phase 3 |
| 8 | Neo4j instance (local Community Edition or Aura free tier) | Not yet set up | Phase 3 |
| 9 | NVD/CWE/ATT&CK data downloaded | Not yet sourced — need to pick and download a subset | Phase 3 |

**Bottom line: only items 1-4 block starting.** Items 5-9 are Phase 2/3 concerns — don't get them yet, get them when their phase starts. This avoids collecting API keys for services you won't touch for weeks.

**Your action before I write any Phase 1 code:** get an Anthropic API key and have it ready to paste into `.env`. Everything else in Phase 1 (dataset generation, code, structure) I can do without waiting on you.

---

## 1. Repository Structure (target — built incrementally per phase)

```
aegis/
├── src/
│   └── incident_agents/
│       ├── __init__.py
│       ├── state.py              # AgentState schema (Phase 1)
│       ├── config.py             # env/config accessors, get_llm(), thresholds (Phase 1)
│       ├── anonymize.py          # PII hashing + local reverse-lookup (Phase 1)
│       ├── graph.py              # StateGraph wiring, incl. reflection loop (Phase 1)
│       ├── run.py                # CLI entrypoint (Phase 1)
│       ├── nodes/
│       │   ├── __init__.py
│       │   ├── ingest.py         # Phase 1
│       │   ├── detect.py         # Phase 1
│       │   ├── classify.py       # Phase 1 (GraphRAG tool added Phase 3)
│       │   ├── reflect.py        # Phase 1
│       │   ├── respond.py        # Phase 1 (bounded auto-block only)
│       │   └── report.py         # Phase 1 (Slack notification added Phase 2)
│       └── tools/
│           ├── __init__.py
│           ├── parsers.py        # csv_parser_tool, json_parser_tool, data_validator_tool (Phase 1)
│           ├── detection.py      # pattern_detector_tool, anomaly_detector_tool (Phase 1)
│           ├── classification.py # risk_assessor_tool, context_enricher_tool (Phase 1)
│           ├── threat_intel.py   # threat_lookup_tool — mock in Phase 1, real AbuseIPDB in Phase 2
│           ├── alerting.py       # Slack webhook post (Phase 2)
│           └── graphrag.py       # cve_graph_retrieval_tool (Phase 3)
├── scripts/
│   ├── generate_sample_logs.py   # synthetic security_logs.csv/.json generator (Phase 1)
│   └── load_cve_graph.py         # downloads NVD/CWE/ATT&CK subset, loads into Neo4j (Phase 3)
├── data/                         # gitignored — generated locally, not committed
├── reports/                      # gitignored — generated output reports
├── run_gradio_app.py             # Phase 1
├── requirements.txt
├── .env.example
├── .gitignore
├── LICENSE
├── README.md
├── PROJECT_DOCUMENTATION.md
└── PLANNING.md
```

---

## 2. Phase 1 — Core 6-Stage Pipeline on Claude

**Goal:** `python -m src.incident_agents.run` produces a real Markdown incident report from synthetic log data, running the full Ingest→Detect→Classify→Reflect→Respond→Report pipeline on Claude, with PII anonymization and configurable thresholds built in from the start.

### Tasks, in order

1. **Environment setup**
   - `python -m venv .venv`, activate it, `pip install -r requirements.txt`
   - Copy `.env.example` → `.env`, fill in `ANTHROPIC_API_KEY`
2. **Synthetic dataset** (`scripts/generate_sample_logs.py`)
   - Generate ~150-200 synthetic events (matching the reference tutorial's scale) across event types: `login` (success/fail), `sudo`, `data_download`, with realistic timestamps, usernames, source IPs (including a few deliberately anomalous ones: brute-force clusters, off-hours large downloads, foreign-IP logins, a `sudo` burst) — so the pipeline has real signal to detect.
   - Output both `data/security_logs.csv` and `data/security_logs.json` (same data, both formats) to exercise both Ingest parsers.
3. **`state.py`** — define `AgentState` (TypedDict): `log_path`, `events`, `anomalies`, `findings`, `reflection_retry_count`, `needs_reanalysis`, `autonomous_actions_taken`, `reasoning_trail`, `confidence_scores`.
4. **`config.py`** — `get_llm()` (returns a configured Claude client), `get_anthropic_key()`, `get_model_name()` (default `claude-opus-5` per `.env`), `get_temperature()`, and a `Thresholds` object (brute-force count, off-hours cutoff hour, off-hours byte threshold, high-confidence cutoff for auto-block) — all overridable via `.env`, sensible defaults otherwise.
5. **`anonymize.py`** — hash usernames/IPs at ingestion (e.g. salted SHA-256, truncated for readability), keep an in-memory reverse-lookup dict for the current run only (never persisted, never sent to the LLM) so the final report can still say "the same user across 3 findings" without ever sending the real username to Claude.
6. **Tools** (`tools/parsers.py`, `tools/detection.py`, `tools/classification.py`, `tools/threat_intel.py` mock version):
   - Port the reference tutorial's `pattern_detector_tool` and `anomaly_detector_tool` logic (brute force, privilege escalation, off-hours download, geographic anomaly — designing the geo-anomaly logic ourselves since it was never fully shown, per §5.11 of the documentation), with thresholds pulled from `config.py` instead of hardcoded.
   - `risk_assessor_tool`, `context_enricher_tool` — design fresh (never shown in source material, §5.11).
   - `threat_lookup_tool` — mock version for Phase 1 (real AbuseIPDB comes in Phase 2), matching the reference tutorial's interface so swapping it later is a one-file change.
7. **Nodes** (`nodes/ingest.py` → `nodes/report.py`) — implement each per the spec in `PROJECT_DOCUMENTATION.md` §5.1-§5.6, using Claude's tool-use API (see the `claude-api` reference this session used) instead of the reference tutorial's OpenAI-based `create_react_agent` calls.
8. **`respond.py`** — the bounded auto-block: on a High-severity, high-confidence, IP-bearing finding, append to `blocklist.json` (gitignored) with timestamp + reason.
9. **`graph.py`** — wire the `StateGraph` exactly as specified in §5.7 of the documentation, including the Reflect→Classify conditional loop (capped at `MAX_REFLECTION_RETRIES = 2`) and the `InMemorySaver` checkpointer (upgraded to a persistent store in Phase 4).
10. **`run.py`** — CLI with `--logs`, `--out`, `--show-reasoning`, matching the reference tutorial's interface.
11. **`run_gradio_app.py`** — the web UI, matching §5.8's spec (upload, config panel, results panel with the new "Actions Taken Automatically" section and Reflect's verdict shown in the reasoning trace).

### Definition of done
- Running the CLI against the synthetic dataset produces a Markdown report with real severity counts, real findings, and (for at least one deliberately-planted malicious IP in the synthetic data) an entry in `blocklist.json`.
- Running with a genuinely clean/benign log file produces "No suspicious activity detected." and never reaches Report (short-circuits correctly).
- The Gradio app runs locally and produces the same results as the CLI for the same input file.
- No raw username or IP ever appears in a Claude API request (verify by logging/inspecting one outbound request payload during testing).

---

## 3. Phase 2 — Real Integrations

**Goal:** Detect's threat lookups use real AbuseIPDB data; a Slack channel gets notified on High-severity findings.

### Tasks
1. Get an AbuseIPDB API key (free tier), add to `.env`.
2. Rewrite `tools/threat_intel.py`'s `threat_lookup_tool` to call the real AbuseIPDB `/check` endpoint, with basic rate-limit handling (free tier: 1,000 checks/day) and a graceful fallback (treat as "unknown reputation" rather than crashing) if the API errors or the daily limit is hit.
3. Create a Slack app + incoming webhook, add the URL to `.env`.
4. Add `tools/alerting.py` with a `send_slack_alert(report_summary)` function; call it from `report.py` after report generation, only when at least one High-severity finding exists.

### Definition of done
- A real known-bad IP (or a test IP AbuseIPDB flags) produces a real, non-mocked risk score in a run's output.
- A test run with a High-severity finding produces a real Slack message in the configured channel.

---

## 4. Phase 3 — GraphRAG Layer

**Goal:** Classify retrieves real CVE/CWE/ATT&CK context via Neo4j + Voyage AI hybrid retrieval, and that context measurably changes severity assignments (not just decoration).

### Tasks
1. Get a Voyage AI API key; add to `.env`.
2. Set up Neo4j — start with local Community Edition (Docker is the simplest path: `docker run` with the official `neo4j` image) unless you'd rather use Aura's free tier; add connection details to `.env`.
3. Pick and download a CVE/CWE/ATT&CK subset:
   - CVEs: a manageable slice of the NVD JSON feed (e.g. CVEs tagged with CWEs relevant to the attack patterns Aegis detects: privilege escalation, brute force/credential access, exfiltration) — a few hundred to a couple thousand entries, not the full feed.
   - CWEs: the MITRE CWE list (XML/CSV export) — filter to the categories actually referenced by the chosen CVEs.
   - ATT&CK: the MITRE ATT&CK STIX bundle, filtered to techniques mapped to the chosen CWEs.
4. `scripts/load_cve_graph.py` — parses the downloaded data, creates `CVE`, `CWE`, `ATT&CK Technique` nodes and `HAS_WEAKNESS`/`MAPS_TO`/`RELATED_TO` edges in Neo4j via Cypher.
5. Embed a searchable text representation of each CVE/CWE node via Voyage AI at load time (store the embedding as a node property or in a lightweight local index alongside the graph — a Neo4j vector index is the cleanest option if using Neo4j 5.11+).
6. `tools/graphrag.py`'s `cve_graph_retrieval_tool`: given a finding's description, embed it via Voyage AI, find the nearest CVE/CWE node(s), then run a Cypher traversal query to pull in directly connected nodes.
7. Wire `cve_graph_retrieval_tool` into `nodes/classify.py`'s tool list; update the classification prompt to actually use the retrieved context in the severity decision (not just append it to the output).

### Definition of done
- A `privilege_escalation` finding's report output visibly cites a real CVE ID and CWE category, not a generic label.
- Two structurally similar findings that map to different CWE severity profiles get measurably different severity assignments because of the retrieved graph context (proves it's actually influencing the decision, not just decorative).

---

## 5. Phase 4 — Persistent Cross-Run Memory

**Goal:** Aegis remembers past investigations across runs and references them ("this IP was flagged 3 runs ago too").

### Tasks
1. Replace `InMemorySaver` in `graph.py` with a persistent LangGraph checkpointer (SQLite-backed — check the current LangGraph checkpointer library for the SQLite option).
2. Design a lightweight "investigation history" schema (e.g. a `history` table: IP/user hash, first-seen, last-seen, times-flagged, past-severities).
3. Add a step (or extend Reflect) to check new findings against investigation history and note recurrence ("this IP has been flagged 3 times this month") in the report.

### Definition of done
- Running Aegis twice on the same recurring malicious IP shows the second report explicitly noting "previously flagged," with a real historical count.

---

## 6. Testing & Verification Strategy

- **Per-tool unit tests** (Phase 1): each detection/classification tool gets a small pytest covering its rule logic against hand-crafted event lists (e.g. exactly 5 failed logins → brute force fires; 4 → it doesn't).
- **End-to-end smoke test** (every phase): run the full CLI against the synthetic dataset and assert the report contains expected findings — this is the main regression check as phases get added.
- **No LLM-output golden-file testing** — Claude's exact wording will vary run to run; test for *structural* correctness (severity counts add up, sections present, blocklist entries match High-severity IP findings) rather than exact text.
- **Manual verification per phase** — the Definition of Done checklists above are pass/fail gates before moving to the next phase.

---

## 7. Answering "Are We Missing Anything Before Starting?"

**Yes, four small things — none of them require a decision, just action:**

1. **No Anthropic API key yet** — you said you need to get one. This is the only hard blocker; nothing in Phase 1 can run without it.
2. **No test data exists** — neither the original tutorial's dataset nor one of our own. Task 1.2 above (a synthetic log generator) resolves this, and I can build it without waiting on anything from you.
3. **No repo scaffolding existed until this session** — now resolved: `.gitignore`, `.env.example`, `requirements.txt`, `LICENSE` (Apache 2.0), and the `data/`/`reports/` directories have been added and pushed.
4. **No committed decision on secrets hygiene** — resolved by `.gitignore` explicitly excluding `.env*` (except `.env.example`) and `blocklist.json` — this matters more than usual since the repo is **public**.

**Nothing else blocks starting.** Once you have the Anthropic key, Phase 1 can begin immediately — I'll build the synthetic dataset generator and the pipeline code together so there's real data to test against from the first run.
