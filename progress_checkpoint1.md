# 📋 Prompt Guardian — Project Progress Tracker

> **Last Updated:** 28 April 2026 &nbsp;|&nbsp; **Repo:** [Sagar44-Github/prompt-guardian](https://github.com/Sagar44-Github/prompt-guardian)

---

## 📌 Project Overview

**Prompt Guardian** is a browser-native prompt injection firewall that intercepts user prompts sent to AI chatbots (like ChatGPT), analyses them in real-time for injection attacks, and blocks or warns the user before the prompt is submitted.

The system is a two-part architecture:
1. **Backend (Python/Flask)** — A multi-layer detection engine combining regex pattern matching, Groq-powered AI semantic analysis, risk scoring, and prompt sanitization.
2. **Frontend (Chrome Extension)** — A browser extension that hooks into ChatGPT's UI, intercepts outgoing prompts, queries the backend, and displays block/warn overlays to the user.

---

## 👥 Team & Responsibilities

| Member | Role | Branch | Files Owned |
|--------|------|--------|-------------|
| **Sagar R** | Tech Lead / Backend Core | `backend-sagar` | `app.py`, `patterns.py`, `scorer.py`, `.gitignore`, `requirements.txt` |
| **Poojitha** | Backend AI & Sanitizer | `backend-poojitha` | `firewall/groq_checker.py`, `firewall/sanitizer.py`, `firewall/analyzer.py` |
| **Sai Tej** | Extension Core Logic | `extension-saitej` | `extension/manifest.json`, `extension/content.js` |
| **Prithvi** | Extension Popup UI | `extension-prithvi` | `extension/popup.html`, `extension/popup.js` |

---

## 🌿 Branch Structure

```
main                    ← Stable / merged code (base setup only so far)
├── backend-sagar       ← Sagar's backend work (ACTIVE — 3 commits ahead of main)
├── backend-poojitha    ← Poojitha's backend work (at initial setup)
├── extension-saitej    ← Sai Tej's extension work (at initial setup)
└── extension-prithvi   ← Prithvi's extension work (at initial setup)
```

---

## 📜 Commit History

| # | Hash | Author | Date | Message | Branch |
|---|------|--------|------|---------|--------|
| 1 | `2b037f3` | Sagar R | 28 Apr 2026 | Initial SetUp | `main` (base for all feature branches) |
| 2 | `ca9b627` | Sagar R | 28 Apr 2026 | Documentation Added | `main` |
| 3 | `5a379d1` | Sagar R | 28 Apr 2026 | Git Ignore Updated | `main` |
| 4 | `00e9ba5` | Sagar R | 28 Apr 2026 | Initial SetUP | `main` |
| 5 | `250f483` | Sagar R | 28 Apr 2026 | Main Initial Setup | `main` (HEAD) |
| 6 | `e737e70` | Sagar R | 28 Apr 2026 | feat(backend): add patterns.py and scorer.py | `backend-sagar` |
| 7 | `659a422` | Sagar R | 28 Apr 2026 | App.py updated | `backend-sagar` |
| 8 | `3c491c1` | Sagar R | 28 Apr 2026 | Final Commit Sagar | `backend-sagar` (HEAD) |

**Total Commits:** 8

---

## ✅ What Has Been Completed

### Phase 1 — Project Setup (Sagar)
- [x] Created GitHub repository and initial project structure
- [x] Set up directory layout: `firewall/`, `extension/`, `Documentations/`
- [x] Created all placeholder files for team members
- [x] Configured `.gitignore` (venv, .env, __pycache__, IDE files)
- [x] Created 4 feature branches (`backend-sagar`, `backend-poojitha`, `extension-saitej`, `extension-prithvi`)
- [x] Pushed all branches to remote
- [x] Added documentation: `Buid.md`, `CollaborationGuide.md`, `Pure Follow Guide`, `Hackathon AtoZ.pdf`

### Phase 2 — Backend Core (Sagar) ✅ COMPLETE
All backend modules authored by Sagar have been built, tested, and pushed to `backend-sagar`.

#### `patterns.py` — Regex Pattern Engine
- [x] **114 injection patterns** across **10 attack categories**
- [x] Categories: instruction_override, jailbreak, prompt_extraction, data_extraction, role_override, encoded_injection, indirect_injection, social_engineering, privilege_escalation, harmful_content
- [x] Risk weight range: 0.68 – 0.97 per pattern
- [x] `pattern_check(prompt)` returns: score, cumulative_score, attack_type, attack_types, severity, is_injection, matches
- [x] Severity classification: none / low / medium / high / critical
- [x] Validated with 97/97 test checks passing

#### `scorer.py` — Risk Scoring Engine
- [x] 4-stage scoring pipeline:
  1. Weighted blend: `(pattern × 0.50) + (groq × 0.50)`
  2. Multi-match bonus: +3% per extra pattern (capped at +15%)
  3. Category danger multiplier (e.g., data_extraction × 1.15)
  4. Dual-signal boost: ×1.20 when both layers agree
- [x] Action thresholds: `≥ 70% → BLOCK`, `≥ 40% → WARN`, `else → ALLOW`
- [x] 21-field return schema including UI metadata (colors, icons, labels)
- [x] Human-readable explanations and recommendations
- [x] Confidence rating based on layer agreement (high/medium/low)

#### `app.py` — Flask REST API
- [x] **4 endpoints:**
  | Route | Method | Purpose |
  |-------|--------|---------|
  | `/health` | GET | Health check + uptime + version |
  | `/analyze` | POST | Single prompt analysis |
  | `/analyze/batch` | POST | Batch analysis (up to 10 prompts) |
  | `/stats` | GET | Live request statistics |
- [x] Per-IP sliding-window rate limiter (60 req/min, no dependencies)
- [x] Request middleware: auto request-ID, response time, version headers
- [x] Thread-safe in-memory stats tracker (blocked/warned/allowed/errors)
- [x] Structured logging for every request
- [x] Error handlers: 400, 404, 405, 415, 429, 500 (all return JSON)
- [x] Input validation: type check, empty check, max 8000 chars
- [x] Env-based configuration (host, port, debug, rate limit, batch size)

#### `firewall/analyzer.py` — Analysis Pipeline Orchestrator
- [x] 5-stage pipeline: Pre-process → Pattern Match → Groq AI → Risk Score → Sanitize
- [x] Pre-processing: SHA-256 hash, char/word/line stats, suspicious encoding detection
- [x] Fast-path: pattern score ≥ 0.90 skips Groq API (saves cost/latency)
- [x] Graceful degradation: Groq/sanitizer failures don't crash the pipeline
- [x] Full metadata in response: layers used, timing, groq_skipped flag
- [x] 48/48 test checks passing

#### `firewall/groq_checker.py` — Groq AI Semantic Analysis
- [x] LLM-based prompt injection detection using Groq API (llama-3.1-8b-instant)
- [x] Comprehensive system prompt covering 10 attack types with scoring guidelines
- [x] Robust JSON parsing (handles markdown fences, partial JSON)
- [x] Graceful fallback when API key missing or call fails

#### `firewall/sanitizer.py` — Prompt Sanitization
- [x] `sanitize_prompt()` — replaces matched injections with `[REDACTED]`
- [x] `get_safe_version()` — generates clean prompt for downstream use
- [x] Handles edge cases: full redaction, multiple consecutive markers, whitespace cleanup

#### `firewall/__init__.py` — Package Initialization
- [x] Exposes `analyze_prompt` at the package level
- [x] Documents all sub-modules

#### Bridge Re-export Modules
- [x] `firewall/patterns.py` — re-exports from root `patterns.py`
- [x] `firewall/scorer.py` — re-exports from root `scorer.py`

---

## ⏳ What Is In Progress / Pending

### Phase 2 — Backend (Other Members)

| Task | Assignee | Status | Notes |
|------|----------|--------|-------|
| Groq checker — standalone testing with real API key | Poojitha | 🔲 Not started | `backend-poojitha` branch at initial setup |
| Sanitizer — standalone testing | Poojitha | 🔲 Not started | Code written by Sagar on his branch |
| Analyzer — review & validate | Poojitha | 🔲 Not started | Poojitha's assigned file, Sagar wrote it on his branch |

### Phase 2 — Chrome Extension

| Task | Assignee | Status | Notes |
|------|----------|--------|-------|
| `manifest.json` — Manifest V3 configuration | Sai Tej | 🔲 Not started | File is empty |
| `content.js` — Prompt interception & block overlay | Sai Tej | 🔲 Not started | File is empty |
| `popup.html` — Extension popup UI (dark theme) | Prithvi | 🔲 Not started | File is empty |
| `popup.js` — Popup logic with scan history display | Prithvi | 🔲 Not started | File is empty |

### Phase 3 — Integration & Merge

| Task | Assignee | Status |
|------|----------|--------|
| Merge `backend-sagar` → `main` | Sagar | 🔲 Pending |
| Merge `backend-poojitha` → `main` | Sagar | 🔲 Pending |
| Merge `extension-saitej` → `main` | Sagar | 🔲 Pending |
| Merge `extension-prithvi` → `main` | Sagar | 🔲 Pending |
| Remove mock/dummy data from extension files | Sai Tej + Prithvi | 🔲 Pending |
| Connect extension `content.js` to real backend API | Sai Tej | 🔲 Pending |
| Connect `popup.js` to `chrome.storage.local` | Prithvi | 🔲 Pending |

### Phase 4 — Testing & Polish

| Task | Status |
|------|--------|
| End-to-end test: Extension → Backend → Response → Overlay | 🔲 Pending |
| Test with real Groq API key on live ChatGPT | 🔲 Pending |
| Cross-browser testing | 🔲 Pending |
| `requirements.txt` — populate with all dependencies | 🔲 Pending |
| Performance benchmarking (response time under load) | 🔲 Pending |

---

## 📁 Current Project Structure

```
prompt-guardian/
├── app.py                      # Flask REST API (417 lines) ✅
├── patterns.py                 # 114 regex injection patterns (340 lines) ✅
├── scorer.py                   # Multi-layer risk scoring engine (299 lines) ✅
├── .env                        # Groq API key (gitignored)
├── .gitignore                  # Environment, OS, IDE exclusions ✅
├── requirements.txt            # (empty — needs populating)
├── Buid.md                     # Build guide with 4-phase workflow
│
├── firewall/
│   ├── __init__.py             # Package init — exposes analyze_prompt ✅
│   ├── analyzer.py             # 5-stage analysis pipeline (184 lines) ✅
│   ├── groq_checker.py         # Groq LLM integration (161 lines) ✅
│   ├── sanitizer.py            # Prompt redaction & safe version (81 lines) ✅
│   ├── patterns.py             # Re-export bridge → root patterns.py ✅
│   └── scorer.py               # Re-export bridge → root scorer.py ✅
│
├── extension/
│   ├── manifest.json           # (empty — Sai Tej's task)
│   ├── content.js              # (empty — Sai Tej's task)
│   ├── popup.html              # (empty — Prithvi's task)
│   └── popup.js                # (empty — Prithvi's task)
│
└── Documentations/
    ├── CollaborationGuide.md   # Complete Git/GitHub team guide
    ├── Build Guide - Secondary.js
    ├── Pure Follow Guide - MD format.md
    ├── CollaborationGuide.docx
    ├── Blind Follow Guide.docx
    ├── Main Report.docx
    └── Hackathon AtoZ.pdf
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        CHROME EXTENSION                                 │
│                                                                         │
│  ┌──────────────┐     ┌──────────────────┐     ┌──────────────────┐   │
│  │  content.js   │────>│   Flask Backend   │────>│   Block/Warn     │   │
│  │  (intercept)  │<────│   POST /analyze   │<────│   Overlay UI     │   │
│  └──────────────┘     └──────────────────┘     └──────────────────┘   │
│                                                                         │
│  ┌──────────────┐                                                       │
│  │  popup.html   │  <── chrome.storage.local ── scan history           │
│  │  popup.js     │                                                      │
│  └──────────────┘                                                       │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                         FLASK BACKEND (app.py)                          │
│                                                                         │
│   POST /analyze                                                         │
│        │                                                                │
│        v                                                                │
│   ┌──────────────────────────────────────────────────────────────┐     │
│   │                    analyzer.py (Pipeline)                     │     │
│   │                                                              │     │
│   │  Step 1: Pre-process (hash, stats, encoding check)           │     │
│   │      │                                                       │     │
│   │  Step 2: pattern_check() — 114 regex patterns                │     │
│   │      │                                                       │     │
│   │  Step 3: groq_check() — Groq LLM semantic analysis           │     │
│   │      │         (skipped if pattern score >= 0.90)            │     │
│   │  Step 4: calculate_risk_score() — weighted blend + boosts    │     │
│   │      │                                                       │     │
│   │  Step 5: sanitize_prompt() — generate safe version           │     │
│   └──────────────────────────────────────────────────────────────┘     │
│        │                                                                │
│        v                                                                │
│   JSON Response: action, risk_score, attack_type, sanitized, etc.      │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend Framework** | Python 3 + Flask |
| **AI/LLM** | Groq API (llama-3.1-8b-instant) |
| **Pattern Engine** | Python `re` module (114 regex patterns) |
| **Extension** | Chrome Manifest V3 (JavaScript) |
| **CORS** | flask-cors |
| **Environment** | python-dotenv |
| **Version Control** | Git + GitHub |

---

## 🔑 Key Design Decisions

1. **Dual-layer detection** — Regex patterns catch known attacks instantly; Groq AI catches novel/semantic attacks that evade regex.
2. **Fast-path optimization** — If pattern score >= 0.90, skip the Groq API call entirely to save latency and cost.
3. **Graceful degradation** — If Groq API fails or key is missing, the system still works with pattern-only detection.
4. **Zero-deadlock collaboration** — Each team member works on completely separate files, eliminating merge conflicts.
5. **Mock-first frontend** — Extension team uses mock/dummy data to build UI independently of backend completion.

---

## 🚀 What's Next (Roadmap)

### Immediate (This Sprint)
1. **Poojitha** — Review and test `groq_checker.py` and `sanitizer.py` with real API key
2. **Sai Tej** — Build `manifest.json` and `content.js` with mock backend, then swap to real API
3. **Prithvi** — Build `popup.html` and `popup.js` with dummy history data
4. **Sagar** — Merge all branches to `main` once team members push their work
5. Populate `requirements.txt` with: `flask`, `flask-cors`, `python-dotenv`, `groq`

### Post-Integration
6. End-to-end testing on live ChatGPT
7. Performance tuning and rate limit adjustments
8. UI/UX polish on the extension overlay and popup

### Future Enhancements
- Dashboard with analytics (attack trends, top patterns, response times)
- Fine-tuned model for even better semantic detection
- Multi-platform support (Claude, Gemini, Copilot, etc.)
- Persistent storage (database) for scan history across sessions
- User authentication and per-user settings
- Chrome Web Store publication
- Real-time pattern updates (download new patterns from a remote config)
- Adversarial testing against known prompt injection benchmarks

---

## 📊 Current Metrics

| Metric | Value |
|--------|-------|
| Total lines of backend code | ~1,300+ |
| Injection patterns | 114 |
| Attack categories | 10 |
| API endpoints | 4 |
| Test checks passed | 145/145 (patterns: 97, scorer: 97, analyzer: 48) |
| Branches | 5 (main + 4 feature) |
| Total commits | 8 |
| Dependencies | 4 (flask, flask-cors, python-dotenv, groq) |

---

*This document is a living tracker. Update it as work progresses.*
