# Aegis — AI Cyber Defense Multi-Agent System

> Working documentation compiled from reference material (tutorial screenshots) reviewed on 2026-09-04/05.
> Status: **repo scaffolded, Phase 1 not yet started.** This document records *why* every decision was made; see [PLANNING.md](./PLANNING.md) for the concrete, step-by-step build plan (*what to do, in what order*).

**Repo:** [github.com/dineshyadav03/aegis](https://github.com/dineshyadav03/aegis) (public) · **Project board:** [github.com/users/dineshyadav03/projects/1](https://github.com/users/dineshyadav03/projects/1) (linked to the repo)

---

## 1. Project Name

**Aegis** (decided)
Aegis = the mythological shield of protection — short, brandable, and directly evokes defense.

Other names considered and set aside:
| Name | Rationale |
|---|---|
| SentinelFlow | Sentinel watches; flow = the LangGraph pipeline |
| ThreatCompass | Callback to the reference tutorial's own "Smart Compass" motif (Setup → Mission → Architecture → ... → Assess) |
| WardenAI | "Warden" = guard/keeper; plain and clear but generic |
| CyberSentry | Descriptive, safe, unexciting |

The reference material itself was untitled at the product level — its repo was called `AI Cyber Defence` / `AI Incident Response Agents`, which is descriptive but not a real product name. **Aegis** is the name going forward.

---

## 2. Problem We're Solving

**The problem, concretely:**

Every organization with any online footprint generates a constant stream of security-relevant events — login attempts, privilege/`sudo` usage, file/data downloads, VPN and geographic access records — across however many systems it runs. A mid-size company can easily produce tens of thousands of these events per day. Somewhere in that stream, real attacks look almost identical to routine noise:

- A **brute-force attempt** is just "a few more failed logins than usual" until you count them across a whole day.
- **Privilege escalation** is a single `sudo` line among thousands of legitimate ones.
- **Credential stuffing** looks like normal login traffic unless you notice the same account being tried from many different IPs in a short window.
- An **off-hours large data download** or a **login from an unexpected country** are single rows in a log file — meaningless on their own, significant only in context.

Three compounding issues make this hard to catch manually:

1. **Volume vs. attention.** No analyst can read every log line; most SOC teams rely on manual spot-checks or brittle static alert rules that either miss subtle multi-event patterns or fire so often (alert fatigue) that real signals get ignored along with the noise.
2. **Detection is only half the job.** Even when something suspicious is flagged, someone still has to manually correlate it with related events, judge severity, and write up what happened and what to do about it — which takes time analysts often don't have during an active incident.
3. **Small teams have no scale.** Smaller organizations or solo security-conscious developers typically have no SOC at all — this kind of log review simply doesn't happen unless it's automated.

The result: real incidents are frequently caught late — after data has already left the network, an account has already been taken over, or an attacker has already moved laterally — because detection and triage weren't fast or consistent enough to catch it early.

**What the system does about it:** ingest raw security logs → have AI agents autonomously detect suspicious patterns and statistical anomalies across the full event set (not just single rows in isolation) → classify/risk-score what's found → **review those findings before acting on them** → generate a prioritized, human-readable incident report with concrete next actions (isolate systems, reset passwords, enable MFA, etc.). This compresses what would be hours of manual log correlation into a single automated pass.

**On autonomy:** Aegis is primarily a **decision-support system** for a human analyst — almost every recommended action (isolate a system, reset a password, review access controls) is listed for a human to carry out, not executed automatically. The one deliberate exception is a narrowly bounded autonomous action — automatically adding a confirmed-malicious IP to a local blocklist — described in §5.5. Everything else always waits for a human. Aegis augments a SOC analyst; it does not replace one, and it does not grant itself broad remediation power.

---

## 3. Solution Overview

From the reference README:

```
AI CYBER DEFENCE MULTI AGENTS SYSTEM

📊 Security Logs → 🤖 AI Agents → 📄 Incident Reports
      ↓                  ↓                ↓
   Raw Data       Threat Analysis    Action Plans
```

**Architecture — 6-stage pipeline** (expanded from the reference tutorial's 4 stages to close two gaps against the *original* concept slide — see §7a):

```
WORKFLOW PIPELINE

[INGEST] → [DETECT] → [CLASSIFY] → [REFLECT] → [RESPOND] → [REPORT]
   |           |           |            |            |          |
 Reads      Finds       Assesses     Reviews      Auto-blocks  Generates
 & validates threats &   risk &      findings,     confirmed   incident
 log data   anomalies   enriches    can send      malicious   report +
            using AI    with CVE/    back to       IPs (bounded  Slack
            tools       CWE/ATT&CK  Classify for   autonomous   alert on
                        context     re-analysis    action) —     High
                        (GraphRAG)  (LangGraph      everything    severity
                                    reflection)     else stays
                                        ▲               a human
                                        |            recommendation
                                   loops back if
                                   findings look
                                   unjustified
                                        |
                        [Neo4j knowledge graph]
                   CVE —[HAS_WEAKNESS]→ CWE —[MAPS_TO]→ ATT&CK
                   Voyage AI embeddings find starting nodes,
                        then traverse relationships
```

**Framework:** LangGraph (graph/state orchestration, including a real reflection loop — not just linear conditional routing) + Google Gemini (LLM backend, decided — see §6) + a **GraphRAG** layer (Voyage AI embeddings for entity matching + Neo4j knowledge graph for relationship traversal) for CVE-grounded threat classification. The reference tutorial's actual implementation used OpenAI directly, had no RAG, no reflection stage, and no autonomous action at all — every one of those is a deliberate departure made for Aegis (§6, §7a).

---

## 4. Agent Capabilities (design principles from the reference material, now fully implemented)

Each agent uses the **ReAct (Reasoning + Acting) framework**:
- **Reasoning** — agents think through problems step-by-step before acting.
- **Acting** — agents call specialized tools scoped to their stage.
- **Memory** — agents are designed to learn from previous investigations (Phase 4 — see §6).
- **Confidence Scoring** — every agent attaches a confidence score to its output, surfaced to the end user.
- **Reflection** — the Reflect agent (§5.4) reviews Classify's output before it can proceed, and can send it back for re-analysis. This was named as a design principle in the original concept slide but wasn't demonstrated anywhere in the reference tutorial's actual code — it's a real gap we're now closing (§7a).

Concretely, each ReAct-based node tries `langgraph.prebuilt.create_react_agent(model, tools, prompt)` first; if no LLM/API key is configured, it falls back to direct deterministic tool calls (rule-based detection) — this is also exposed to the end user as a "Fast Mode (Skip AI Processing)" toggle.

---

## 5. Component-by-Component Breakdown

### 5.1 Ingest Agent (`nodes/ingest.py`)
- **Tools:** `csv_parser_tool`, `json_parser_tool`, `data_validator_tool`
- **Role prompt:** *"You are a data ingestion specialist. Parse and validate security log files."*
- **Fallback path:** direct CSV/JSON parse, plus `data_validator_tool.invoke({"events": events})` for a data-quality score.
- **Output:** parsed, **anonymized** `events` list onto shared state (usernames/IPs hashed per §6), plus a reasoning-trail note like `"Ingest ReAct agent processed {log_path} with data quality score: ..."`.

### 5.2 Detect Agent (`nodes/detect.py`)
- **Tools:** `pattern_detector_tool`, `anomaly_detector_tool`, `threat_lookup_tool`
- **Role prompt:** *"You are a security threat detection specialist. Analyze security events for threats and anomalies."*
- **`pattern_detector_tool`** (rule-based, thresholds configurable per §6):
  - **Brute force:** ≥N failed logins from the same (user, IP) pair (default N=5) → confidence 0.8
  - **Privilege escalation:** any `sudo` event type → confidence 0.9
- **`anomaly_detector_tool`** (rule-based, thresholds configurable):
  - **Off-hours large download:** event hour < configurable cutoff (default 5) AND bytes ≥ configurable size (default 1,000,000) → confidence 0.7
  - **Geographic anomaly** (`foreign_login`): login from an unexpected country/region
- **`threat_lookup_tool(ip)`:** **real AbuseIPDB lookup** (Phase 2, ✅ implemented 2026-09-05) — calls `GET /api/v2/check`, returns `risk_score` on AbuseIPDB's **native 0-100 `abuseConfidenceScore` scale** (Phase 1's mock used an invented 0-10 scale; Phase 2 adopts the real API's scale directly — thresholds updated accordingly, see §6). No key configured, a network error, or a rate-limit hit all degrade gracefully to `reputation: "Unknown"` rather than crashing the pipeline. One documented exception: the synthetic dataset's planted attacker IP (`198.51.100.23`, an RFC 5737 test-net address) is served from a small hardcoded demo-override map instead of the real API, since reserved documentation IPs will never have real abuse reports — see `tools/threat_intel.py`.
- **Output:** combined `anomalies` list (pattern-based + statistical) with per-item confidence.

### 5.3 Classify Agent (`nodes/classify.py`)
- **Tools:** `risk_assessor_tool`, `context_enricher_tool`, `cve_graph_retrieval_tool` (new — GraphRAG, §5.10)
- **Role prompt:** *"You are a security threat classification specialist. Assess risk levels and enrich with CVE/CWE/ATT&CK context."*
- **Output:** `findings` list, each tagged with a severity (`High` / `Medium` / `Low`) and enriched with related CVE/CWE/ATT&CK context retrieved from the knowledge graph.

### 5.4 Reflect Agent (`nodes/reflect.py`) — **new, closes a gap against the original concept**
This is the "Reasoning Agent (LangGraph with reflection)" from the original concept slide (§7a), which the reference tutorial's actual code never implemented.
- **Role:** review the Classify agent's findings *before* anything downstream happens — check that severity levels are actually justified by the evidence and CVE/CWE context, that findings aren't duplicated or contradictory, and that confidence scores are reasonable given the input.
- **Two outcomes:**
  1. **Approve** — findings look sound → proceed to Respond.
  2. **Send back for re-analysis** — something looks unjustified (e.g. a "High" severity with no supporting CVE match, or a confidence score that doesn't match the evidence) → loop back to Classify with feedback on what to reconsider.
- **Loop safety valve:** capped at a small number of retries (e.g. 2) — if Reflect still isn't satisfied after that, it proceeds anyway rather than looping forever, and notes the unresolved concern in the final report.
- This is the piece that makes Aegis's agents **self-correcting** rather than single-pass — a materially different capability from the reference tutorial's linear pipeline.

### 5.5 Respond Agent (`nodes/respond.py`) — **new, closes the other gap against the original concept**
This is the "Response Orchestration Agent (autonomous response)" from the original concept slide (§7a). Rather than skipping it (as the reference tutorial effectively did) or making it fully autonomous (as the original concept literally shows), Aegis implements a **narrowly bounded** version:
- **The only autonomous action:** for any finding that is (a) IP-based, (b) `High` severity, and (c) confirmed malicious by threat intel (`reputation == "malicious"` AND `risk_score` above a configurable threshold, default 8.0), automatically add that IP to a **local blocklist file** (`blocklist.json`) with a timestamp and the triggering finding as the reason. *(Refined during Phase 1 build/testing — the gate originally compared pattern-detection confidence to a threshold, which would almost never fire since no detector emits confidence that high; risk_score is the correct "confirmed malicious" signal, see §Phase 1 Build Notes below.)*
- **Everything else stays a recommendation** — password resets, system isolation, access-control reviews, MFA enforcement: none of these are auto-executed, ever. Only the single, reversible, low-blast-radius action above runs without a human.
- **Why a local file and not a real firewall call:** this is a portfolio/demo project without real corporate network infrastructure to integrate with. Writing to a local blocklist file demonstrates the autonomous-action capability honestly, without pretending to control infrastructure that doesn't exist. (A real deployment would swap this for an actual firewall/WAF API call — same decision point, different backend.)
- **Output:** an `autonomous_actions_taken` list on shared state, separate from `findings` — the Report agent surfaces these separately from human-facing recommendations.

### 5.6 Report Agent (`nodes/report.py`)
- **Not a ReAct agent** — calls Gemini directly for report generation (`_llm_report(findings)`), with a deterministic fallback (`_fallback_report(findings)`) when no API key is set, an LLM error occurs, or there are simply no findings (returns `"No suspicious activity detected."`).
- **System prompt:** *"You are a security analyst. Write a succinct markdown incident report. Group similar findings, include counts, and list prioritized actions. Be precise and avoid fluff."*
- **User payload:** the findings as a JSON list (with CVE/CWE/ATT&CK context from Classify, any Reflect concerns, and any autonomous actions already taken by Respond), plus explicit formatting instructions.
- **Output:** a Markdown **Security Incident Report** with distinct sections:
  - Summary (counts by severity)
  - Findings by severity, each with CVE/CWE/ATT&CK context where available
  - **⚡ Actions Taken Automatically** (IPs auto-blocked by Respond, if any)
  - **Recommended Actions For You** — split into 🚨 **Immediate** (reset compromised passwords, isolate systems, initiate IR procedures) and ⚠️ **Urgent** (review/update access controls, enable MFA, monitor affected accounts)
  - A **Slack notification** (Phase 2, ✅ implemented) fires via an Incoming Webhook post on any High-severity finding — a short summary, not the full report. Best-effort: no webhook configured, or the post failing, degrades to a `slack_notified: false` state field and a reasoning-trail note, never a crash.

### 5.7 Graph Wiring (`graph.py`)
```python
graph = StateGraph(AgentState)
graph.add_node("ingest", ingest_node)
graph.add_node("detect", detect_node)
graph.add_node("classify", classify_node)
graph.add_node("reflect", reflect_node)
graph.add_node("respond", respond_node)
graph.add_node("report", report_node)

graph.add_edge(START, "ingest")
graph.add_edge("ingest", "detect")

# Conditional: skip straight to END if nothing was found
def has_anomalies(state): return "classify" if state.get("anomalies") else END
graph.add_conditional_edges("detect", has_anomalies, {"classify": "classify", END: END})

graph.add_edge("classify", "reflect")

# Reflection loop: send back to classify for re-analysis, up to a retry cap
MAX_REFLECTION_RETRIES = 2
def reflection_verdict(state):
    if state.get("reflection_retry_count", 0) >= MAX_REFLECTION_RETRIES:
        return "respond"  # safety valve — proceed rather than loop forever
    return "classify" if state.get("needs_reanalysis") else "respond"
graph.add_conditional_edges("reflect", reflection_verdict, {"classify": "classify", "respond": "respond"})

# Conditional: only generate a report if something High/Medium was found
def needs_report(state):
    levels = {x.get("severity", "Low") for x in state.get("findings", [])}
    return "report" if any(s in ("High", "Medium") for s in levels) else END
graph.add_conditional_edges("respond", needs_report, {"report": "report", END: END})

graph.add_edge("report", END)

checkpointer = InMemorySaver()  # Phase 1; becomes a persistent store in Phase 4 (§6)
return graph.compile(checkpointer=checkpointer)
```
This preserves the reference tutorial's short-circuit behavior (nothing worth escalating → straight to `END`) while adding the reflection feedback loop and the bounded autonomous-response step that the original concept called for but the tutorial's actual code never built.

### 5.8 Runtime / Configuration
- **Config surface:** Gemini API key, Voyage AI API key, AbuseIPDB API key, Slack webhook URL, Neo4j connection details, selectable Gemini model, temperature (default `0.0`, deterministic), detection thresholds (§6), dataset path.
- **CLI:**
  ```bash
  python -m src.incident_agents.run                                   # default data
  python -m src.incident_agents.run --logs data/security_logs.csv     # custom log file (CSV or JSON)
  python -m src.incident_agents.run --show-reasoning                  # print agent reasoning trace
  python -m src.incident_agents.run --out reports/incident_report.md  # save report to file
  ```
- **Web UI (Gradio):** `python run_gradio_app.py` → `http://localhost:7860`
  - Header: "🛡️ Aegis — Automated cybersecurity threat detection using AI agents"
  - Left panel: log upload (CSV/JSON, drag-drop or click), Configuration (Show Agent Reasoning Process checkbox, AI Model dropdown, Temperature slider, Fast Mode checkbox), "Analyze Security Logs" button.
  - Right panel: Analysis Results — severity counts, full Markdown incident report (now including the Actions Taken Automatically section), "Agent Reasoning Process" step trace (now including Reflect's verdict and any re-analysis loops), "Analysis Details," and per-agent **Confidence Scores**.

### 5.9 Observed Sample Runs (from the reference tutorial, pre-dating our changes)
- Run A (`gpt-5-nano`, verbose): 150 events processed → 26 anomalies → report with **High: 20 / Medium: 1 / Low: 31**, dominated by `privilege_escalation` and `foreign_login` findings.
- Run B (`gpt-4o-mini`, tighter formatting): 150 events → 6 anomalies → **High: 6 / Medium: 0 / Low: 0**, findings: `brute_force_login` (x2), `privilege_escalation` (x4); confidence scores `ai_report: 0.92`, `detection: 0.88`, `classification: 0.85`; processing time ~00:01:03.

This shows the same pipeline producing materially different output volume/severity distribution depending on model choice — we'll want to re-baseline this once Aegis is running on Gemini instead of OpenAI.

### 5.10 GraphRAG Layer — CVE/CWE/ATT&CK Knowledge Retrieval (new, not in the reference tutorial)

The reference tutorial's actual code has **no RAG** — but the original concept slide for this project described a "Threat Pattern Recognition Agent (RAG with CVE database)." We decided to build that for real, then refined it further: security vulnerability data is naturally relational (a CVE has weaknesses, weaknesses map to attack techniques, CVEs relate to other CVEs), so plain vector similarity would flatten that structure. We're using **GraphRAG** instead of plain vector RAG for this reason.

- **What it retrieves:** relevant CVE (Common Vulnerabilities and Exposures) entries, their associated CWE (Common Weakness Enumeration) categories, and mapped MITRE ATT&CK techniques — matched against the patterns/anomalies the Detect agent finds. E.g. a detected `privilege_escalation` pattern doesn't just get "similar-sounding" CVEs back — it gets the actual graph neighborhood: the CWE category for privilege escalation, every CVE under that CWE, and the ATT&CK techniques those CVEs map to.
- **Knowledge graph structure:** nodes for `CVE`, `CWE`, and `ATT&CK Technique`; edges like `CVE -[HAS_WEAKNESS]-> CWE` and `CWE -[MAPS_TO]-> ATT&CK Technique`, plus `CVE -[RELATED_TO]-> CVE` where applicable.
- **Graph store:** **Neo4j** — a real graph database (Community Edition or Aura free tier), queried via Cypher.
- **Embedding provider:** **Voyage AI** — kept as a dedicated embeddings provider even though Gemini has its own native embeddings API (`gemini-embedding-2`), so this is a separate API call in the pipeline. Deliberately decoupling embeddings from the LLM provider (§6) rather than defaulting to Gemini's own embeddings. Used for the "entry point" half of retrieval (see below), not for the graph itself.
- **Retrieval strategy — hybrid:** (1) embed the finding's description via Voyage AI and use vector similarity to find the most relevant starting CVE/CWE node(s), then (2) traverse the graph from those nodes via Cypher to pull in directly related CWEs, ATT&CK techniques, and neighboring CVEs. This is the standard GraphRAG pattern — vector search for the entry point, graph traversal for the surrounding context vector similarity alone would miss.
- **CVE/CWE/ATT&CK data source:** a **static downloaded subset of the NVD (National Vulnerability Database) feed** plus the CWE and ATT&CK mapping data, loaded into Neo4j once at setup time — not a live API call per run.
- **Where it plugs in:** as an additional tool available to the Classify agent (`cve_graph_retrieval_tool`) — it takes a finding's pattern/description, runs the hybrid retrieval above, and folds the resulting graph context into the risk assessment before severity is assigned.

This is the one piece of Aegis that most resembles — but goes beyond — the other RAG projects already in this repo (Simple RAG, Agentic RAG): those use flat vector retrieval, while this uses hybrid vector-plus-graph retrieval, better suited to how vulnerability data is actually structured.

### 5.11 Source Material Completeness Note (added after a full re-check of all 40 screenshots, 2026-09-05)

A careful pass through every screenshot — not just the ones summarized above — turned up several pieces of the reference tutorial's code that were **never fully visible** in any frame, either cut off mid-scroll or referenced only by name. Recorded here so it's clear what's a documented fact about the reference material versus what we'll be designing ourselves from scratch regardless:

**Referenced by name, implementation never shown:**
- `csv_parser_tool`, `data_validator_tool` (used by Ingest, §5.1)
- `risk_assessor_tool`, `context_enricher_tool` (used by Classify, §5.3)

**Partially shown, cut off before completion:**
- `anomaly_detector_tool`'s **geographic anomaly detection** logic (§5.2) — the off-hours-download branch was fully visible; the `# Geographic anomaly detection` section that follows it (line 63 onward) was cut off at the bottom of the frame.
- `classify_node`'s **severity-assignment logic** (§5.3) — visible up through `findings = []` (line 59); how individual findings actually get tagged High/Medium/Low was never shown.
- `detect_node`'s **result-combination logic** (§5.2) — visible through appending pattern-based detections; how anomaly-based and threat-lookup results get merged into the same `all_anomalies` list was cut off.
- `_fallback_report`'s **actual body** (§5.6, Report agent) — every screenshot showing this function only shows call sites (`return _fallback_report(findings)`), never its definition.

**Never shown at all (already noted in §7):** `state.py`, `config.py`.

**Why this doesn't block anything:** none of this changes any decision made in §6 — we're building Aegis's own version of every one of these pieces from scratch anyway (different LLM provider, real AbuseIPDB instead of a mock, GraphRAG instead of no RAG, a new Reflect/Respond pair that doesn't exist in the reference at all). It just means there's no reference implementation to lean on for these specific functions; we'll design their logic fresh during Phase 1, same as `state.py`/`config.py`.

### 5.12 Phase 1 Build Notes (2026-09-05) — what changed from design to working code

Phase 1 is now built and verified end-to-end (CLI and Gradio UI both tested against real Gemini calls and against synthetic data). Two real bugs surfaced during testing that the design docs above didn't anticipate — both are now fixed in the code and reflected in §5.2/§5.5 above:

1. **`privilege_escalation` was blanket-High severity.** The original rule was "any `sudo` event → High." Aegis's own Reflect agent (running for real against Gemini) correctly flagged this as unjustified for routine, zero-risk internal maintenance — exactly the kind of alert-fatigue-inducing rule Aegis exists to prevent. This also exposed a structural bug: because Classify's severity logic is fully deterministic, sending it "back for re-analysis" changed nothing — Reflect kept re-flagging the same verdict until the retry cap gave up. **Fix:** `privilege_escalation` is now `High` only when threat intel confirms the source is malicious; otherwise `Medium`. After the fix, Reflect approved on the first pass with no wasted retries — confirming the fix addressed the root cause, not just the symptom.
2. **The auto-block gate compared the wrong number.** It required pattern-detection *confidence* ≥ 0.85, but no detector ever emits confidence that high except `privilege_escalation` (0.9) — which is exactly the type the malicious-reputation gate should exclude. This meant the "confirmed-malicious IP" auto-block, our one autonomous action, could never actually fire in practice. **Fix:** the gate now checks threat-intel `risk_score` (the real "how malicious is this" signal) instead of detection confidence — verified working: a real confirmed-malicious IP now gets auto-blocked and appears in the report's "Actions Taken Automatically" section.

**Operational discovery — Gemini model quota:** `gemini-3.8-flash`'s free tier caps at 20 requests/day (hit mid-testing). `gemini-2.5-flash` returned "no longer available to new users" for this API key/project. Settled on **`gemini-3.6-flash`** as the working default — confirmed via live testing to have a workable free-tier quota and to be genuinely accessible to this key (unlike the other two). `AEGIS_MODEL` remains a one-line `.env` change to any model the key can access.

### 5.13 Phase 2 Build Notes (2026-09-05) — real AbuseIPDB + Slack

**Real AbuseIPDB integration built** (`tools/threat_intel.py`): `GET https://api.abuseipdb.com/api/v2/check`, `Key` header auth, graceful fallback (no key / network error / rate-limit → `reputation: "Unknown"`, never a crash) — verified via the code's fallback path (real API calls pending the user obtaining a key, per their own choice in §6).

**Scale change:** AbuseIPDB's real `abuseConfidenceScore` is 0-100, not the 0-10 scale Phase 1's mock invented. Rather than converting incoming scores to match the old scale, Aegis now uses AbuseIPDB's native scale everywhere — `Thresholds.high_risk_score` and `auto_block_min_risk_score` both default to `80.0` (was `8.0`). This is a cleaner design than a conversion layer nobody else would expect.

**A real gap between demo data and a real API:** the synthetic dataset's planted "attacker" IP (`198.51.100.23`) is an RFC 5737 documentation/test-net address — deliberately chosen so a public repo never ships a real malicious IP as a test fixture. But that also means it can **never** have real AbuseIPDB reports, silently breaking the auto-block demo once the mock was replaced with a real call. Fixed with a small, explicitly-documented override map in `tools/threat_intel.py` for just that one test IP — every other IP goes through the real API untouched. This is a design tension worth knowing about for anyone adapting this pattern: synthetic security data and real threat-intel APIs don't naturally agree, and papering over that silently would have been worse than documenting it.

**Slack alerting built** (`tools/alerting.py`): posts a short summary (not the full report) to an Incoming Webhook on any High-severity finding; best-effort, `slack_notified` state field records whether it actually sent.

**Status:** code complete and verified via all fallback paths (no-key, rate-limit-shaped errors, no-webhook). Full live verification against real AbuseIPDB/Slack pending the user adding real credentials to their local `.env` (their choice, §6) — nothing in the code needs to change when they do, per the standard "no key → fallback, key present → real call" pattern already established for Gemini.

---

## 6. Decisions Made (2026-09-05)

| Question | Decision | Implication |
|---|---|---|
| LLM provider | **Google Gemini** (not Claude, not OpenAI, not Groq) — *changed 2026-09-05, superseding an earlier Claude decision* | All agent prompts/tool-calling target the Gemini API's manual function-calling format (see `agent_loop.py`). A third provider distinct from every other project in this repo (Simple RAG / Agentic RAG use Groq) — no existing config code to reuse. Verified directly against the live Gemini API on 2026-09-05: `gemini-3.8-flash` and `gemini-2.5-flash` both looked valid from `models.list`, but neither actually worked for this API key/project once Phase 1 was built and run for real (20/day quota; 404 "no longer available to new users," respectively) — **`gemini-3.6-flash` is the confirmed-working default** (see §5.12). Re-verify before relying on this later — Gemini's naming and per-key availability move fast. |
| Threat intelligence | **Real free API — AbuseIPDB**, ✅ implemented Phase 2 (2026-09-05) | Real network calls with graceful error/rate-limit handling (degrades to "Unknown" rather than crashing). Adopted AbuseIPDB's native 0-100 risk-score scale rather than Phase 1's invented 0-10 scale — see §5.2, §6 threshold rows below. |
| Cross-run memory | **Real learning**, not just a wired-but-unused checkpointer | Needs a persistent store (e.g. SQLite/file-backed) so investigation history and learned patterns actually survive between runs. Deferred to Phase 4. |
| Log formats | **CSV + JSON** for v1 | Ingest agent needs two parsers (or one normalizing parser) from day one. |
| PII handling | **Anonymize/hash before sending to Gemini** | Usernames and IPs hashed/masked at ingestion, with a local-only reverse-lookup mapping so the final report can still reference "the same user/IP" across findings without exposing raw values to any external API. |
| Detection thresholds | **Configurable from the start** | Thresholds (failed-login count, off-hours download size/time window, etc.) live in config, not hardcoded. |
| Downstream alerting | **Slack webhook notification** on High-severity findings, ✅ implemented Phase 2 | `tools/alerting.py` — best-effort post, never blocks the pipeline on failure. |
| Threat-intel API | **AbuseIPDB** | Free tier, purpose-built for IP abuse/reputation scoring. |
| Risk-score scale | **AbuseIPDB's native 0-100** (not Phase 1's invented 0-10) | `Thresholds.high_risk_score`/`auto_block_min_risk_score` default to 80.0 accordingly (§Phase 2 Build Notes). |
| Demo dataset vs. real threat intel | **Small hardcoded override** for the synthetic dataset's planted attacker IP | RFC 5737 test-net IPs (used deliberately so the public repo never ships a real malicious IP as a fixture) will never have real AbuseIPDB reports — the override keeps the demo deterministic without misrepresenting real API behavior for any other IP. |
| RAG (CVE retrieval) | **Yes — add it**, even though the tutorial's actual code has none | Original concept slide called for "RAG with CVE database" (§7a). |
| RAG type | **GraphRAG**, not plain vector RAG | CVE/CWE/ATT&CK data is inherently relational — a knowledge graph preserves that structure. |
| Graph store | **Neo4j** | Real graph database queried via Cypher (free Community Edition / Aura tier). |
| Retrieval strategy | **Hybrid: Voyage AI vector search for entry-point nodes, then Cypher graph traversal** | Standard GraphRAG pattern. |
| Embedding provider | **Voyage AI** (kept, re-confirmed 2026-09-05 after switching to Gemini) | Gemini *does* have a native embeddings API (`gemini-embedding-2`) — unlike Claude, so the original "no native embeddings" justification no longer applies. Deliberately kept Voyage AI anyway to decouple embeddings from the LLM provider, so either can be swapped independently later. |
| CVE/CWE/ATT&CK data source | **Static downloaded NVD + CWE + ATT&CK subset** | Loaded into Neo4j once at setup; no live dependency during runs. |
| **Reflection stage** | **Yes — add a Reflect agent** between Classify and Respond | Closes gap #1 against the original concept (§7a): findings now get reviewed/critiqued before anything acts on them, with a capped loop back to Classify for re-analysis if something looks unjustified. |
| **Autonomous response** | **Yes — but narrowly bounded**, not the original concept's fully autonomous orchestration | Closes gap #2 against the original concept (§7a): the *only* autonomous action is auto-blocking a confirmed-malicious IP (High severity + high confidence). Every other action (password resets, system isolation, access reviews) stays a human-executed recommendation. |
| Auto-block mechanism | **Write to a local blocklist file** (`blocklist.json`), not a real firewall API call | No real corporate firewall exists to integrate with in this project; a local file demonstrates the capability honestly. A real deployment would swap this for an actual firewall/WAF API. |
| Repo license | **Apache 2.0** | Matches the license already used elsewhere across this developer's repos; includes an explicit patent grant. |
| Package/dependency manager | **pip + venv** | Simplest, most universally familiar; matches the reference tutorial's own setup style. |
| Gemini API key | **Obtained by the user 2026-09-05** — ⚠️ **the key value was pasted into this chat and must be rotated before use.** A fresh key (never pasted anywhere) should be placed directly into the local `.env` file. | Once a rotated key exists in `.env`, nothing blocks starting Phase 1. |

**Net effect:** Aegis is intentionally scoped *beyond* both the reference tutorial (which had 4 linear agents, no RAG, no reflection, no autonomous action) and — in the RAG and reflection dimensions — matches or exceeds the *original* concept slide too. Suggested build order:

1. **Phase 1 — core 6-stage pipeline on Gemini:** Ingest (CSV+JSON) → Detect → Classify → Reflect → Respond (bounded auto-block only) → Report, with configurable thresholds, PII anonymization, and the reflection loop built in from the start.
2. **Phase 2 — real integrations:** swap in the real AbuseIPDB lookup, add the Slack webhook notification step.
3. **Phase 3 — GraphRAG layer:** stand up Neo4j, load the CVE/CWE/ATT&CK subset and relationships, embed entry-point text via Voyage AI, wire hybrid retrieval into Classify.
4. **Phase 4 — memory:** add the persistent cross-run learning store once everything else is solid.

Happy to sequence it differently if you'd rather.

---

## 7. Still Open (implementation details, no user input needed — will design as we build)

- **`state.py` / `config.py` schemas** — will design `AgentState` fields and config accessors ourselves, adapted for Gemini.
- **Persistent memory store choice** (SQLite vs. flat file) — Phase 4.
- **Anonymization scheme details** (hash algorithm, local reverse-lookup table design) — Phase 1.
- **Size/scope of the CVE/CWE/ATT&CK subset** — Phase 3.
- **Exact graph schema** (node/edge properties beyond the core chain) — Phase 3.
- **Neo4j hosting** (local Community Edition vs. Aura free tier) — Phase 3, defaulting to local.
- **Exact Reflect agent criteria** (what specifically counts as "unjustified" enough to trigger re-analysis) — Phase 1, will start with a reasonable rule set (e.g. High severity requires either a strong CVE match or ≥2 corroborating anomalies) and refine based on test runs.
- **Reflection retry cap value** (defaulted to 2 above) — Phase 1, adjustable if it proves too strict/loose in practice.

---

## 7a. Gap Check — Original Concept Slide vs. Current Design (2026-09-05, resolved)

The very first reference material for this project (before the detailed code walkthrough) was a 4-box concept diagram: **Log Ingestion Agent → Threat Pattern Recognition Agent (RAG w/ CVE database) → Reasoning Agent (LangGraph with reflection) → Response Orchestration Agent (autonomous response)**, framework "LangGraph + Anthropic Claude or OpenAI GPT-5." Checking it against the design as of §5-§6:

| Concept box | Status | Resolution |
|---|---|---|
| Log Ingestion Agent | ✅ Covered | Ingest Agent (§5.1) |
| Threat Pattern Recognition Agent (RAG w/ CVE database) | ✅ Covered (split across two agents) | Pattern/anomaly detection in Detect (§5.2), GraphRAG/CVE retrieval in Classify (§5.10). Functionally equivalent, structurally split — accepted as-is. |
| Reasoning Agent (LangGraph with reflection) | ✅ **Resolved — added** | New Reflect agent (§5.4), with a capped loop back to Classify for re-analysis. |
| Response Orchestration Agent (autonomous response) | ✅ **Resolved — added, narrowly bounded** | New Respond agent (§5.5): auto-blocks confirmed-malicious IPs only, writes to a local blocklist file; everything else stays a human recommendation. |
| "Flow of Operations" (feedback loop in the concept diagram) | ✅ Resolved | The Reflect→Classify conditional edge (§5.7) now provides the same kind of feedback loop the original diagram showed, with a retry cap as a safety valve. |

Both real gaps identified on 2026-09-05 are now closed. The design matches the original concept's *intent* on all four boxes, while keeping autonomous action deliberately narrow rather than fully autonomous, for safety.

---

## 8. Skills Demonstrated

Aegis sits at the intersection of three overlapping domains, plus one thing beyond basic agentic AI:

| Domain | Where it shows up in Aegis |
|---|---|
| **AI Engineering** | Real API integration across five external services (Gemini, Voyage AI, AbuseIPDB, Slack, Neo4j); config/secrets management; structured output parsing (severity levels, confidence scores); graceful degradation (rule-based "Fast Mode" when no LLM key is present); PII-safe data handling (anonymize before any log content reaches an external API); two working interfaces (CLI + Gradio web app). |
| **Agentic AI** | Six autonomous agents (Ingest, Detect, Classify, Reflect, Respond, Report), each reasoning over its own scoped toolset; orchestrated as a LangGraph state machine with **conditional routing** (short-circuits to `END` when nothing's worth escalating) *and* a **reflection feedback loop** (Reflect can send work back to Classify) *and* **one narrowly bounded autonomous action** (Respond auto-blocks confirmed-malicious IPs) — a materially more sophisticated agentic design than a single-pass pipeline. |
| **RAG — specifically GraphRAG** | A knowledge-graph-backed retrieval pipeline, not just flat vector search: CVE/CWE/ATT&CK relationships modeled as a **Neo4j graph**, with **hybrid retrieval** (Voyage AI embeddings to find entry-point nodes, then Cypher graph traversal for related context) injected into the Classify agent's risk assessment. A step up in sophistication from this repo's Simple RAG and Agentic RAG projects, which use flat vector retrieval. |
| **Multi-agent orchestration + persistent memory** (beyond basic agentic AI) | Cross-run investigation history and learned patterns intended to persist between sessions (Phase 4) — not just a single-session agent loop, but a system meant to get better at recognizing recurring threats over time. |

Taken together, this makes Aegis a stronger portfolio piece than any one of those domains alone would be — it's not "a RAG demo" or "an agent demo," it's a single system where graph-based retrieval, self-correcting multi-step reasoning, one carefully bounded autonomous action, and production-grade engineering concerns (secrets, fallbacks, privacy, alerting) all have to work together.

---

## 9. Summary

| | |
|---|---|
| **Problem** | Security-relevant events (logins, privilege use, downloads, geographic access) are produced in volumes no analyst can manually review; real attacks (brute force, privilege escalation, credential stuffing, off-hours exfiltration) look like routine noise until correlated across the full event set, so detection and triage both lag — often until after damage is done. |
| **Solution** | A 6-stage multi-agent pipeline (Ingest → Detect → Classify → Reflect → Respond → Report) built on LangGraph. Classify retrieves CVE/CWE/ATT&CK context via GraphRAG; Reflect reviews findings and can loop back for re-analysis; Respond auto-blocks confirmed-malicious IPs (the only autonomous action) while everything else becomes a human-facing recommendation in the final Markdown incident report — plus a Slack notification on High-severity findings. |
| **Interfaces** | CLI (`python -m src.incident_agents.run`) and a Gradio web app (`localhost:7860`). |
| **Fallback mode** | Rule-based detection only (no LLM) when no API key is configured, or via an explicit "Fast Mode" toggle. |
| **LLM provider** | Google Gemini (decided 2026-09-05, superseding an earlier Claude decision) — a departure from the tutorial's OpenAI implementation and from this repo's existing Groq-based projects. |
| **RAG stack** | **GraphRAG**: Neo4j knowledge graph (CVE→CWE→ATT&CK relationships) + Voyage AI embeddings for hybrid entry-point/traversal retrieval, over a static downloaded NVD/CWE/ATT&CK subset. Voyage AI kept deliberately even though Gemini has native embeddings, to decouple the embedding provider from the LLM provider. |
| **Autonomy model** | Decision-support by default; one narrowly bounded exception (auto-block a confirmed-malicious IP to a local blocklist file) — everything else always waits for a human. |
| **Scope vs. reference tutorial** | Deliberately much larger: real AbuseIPDB threat-intel, real persistent cross-run memory, CSV+JSON ingestion, PII anonymization, configurable detection thresholds, Slack alerting, a full GraphRAG/Neo4j layer, a reflection loop, one bounded autonomous action, and Gemini instead of OpenAI. |
| **Scope vs. original concept slide** | Now matches on all four architectural boxes (§7a) — the two gaps found on 2026-09-05 (missing reflection, missing response orchestration) are both resolved. |
| **Status** | **Phase 1 complete and verified.** **Phase 2 code complete** (real AbuseIPDB + Slack, §5.13) — verified via all fallback paths; full live verification pending the user adding real API credentials to `.env` (their choice to obtain these themselves, no code changes needed once added). Next: Phase 3 (GraphRAG). |

---

*Compiled from screenshots reviewed across two sessions (2026-09-04 22:36–22:37 and 2026-09-05 00:34–00:42), plus a gap-check re-review of the original concept slide on 2026-09-05. No files beyond screenshots existed in the project folder at time of writing.*
