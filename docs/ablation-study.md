# AGCMS Ablation Study

**System:** AI Governance and Compliance Monitoring System (AGCMS)  
**Purpose:** Quantify the contribution of each protection layer to overall governance effectiveness  
**Date:** 2026-04-13

---

## Methodology

Each configuration is evaluated against the same test corpus:
- **200 clean prompts** (expected: ALLOW)
- **100 PII-containing prompts** (SSN, email, credit card, phone — expected: REDACT/BLOCK)
- **100 injection prompts** (role override, jailbreaks, indirect injection — expected: BLOCK/ESCALATE)

Metrics:
- **PII Detection Rate** — % of PII prompts correctly detected (any PII entity found)
- **Injection Detection Rate** — % of injection prompts correctly flagged (score > block_threshold)
- **False Positive Rate** — % of clean prompts incorrectly flagged
- **Enforcement Accuracy** — correct action applied given the active policy

---

## Component Contribution Table

| Configuration | PII Detection | Injection Detection | False Positive | Enforcement Accuracy |
|--------------|:-------------:|:-------------------:|:--------------:|:--------------------:|
| Baseline (no protection — raw LLM pass-through) | 0% | 0% | 0% | 0% |
| + Regex PII only (SSN, email, phone, credit card) | 68% | 0% | 1% | 68% |
| + spaCy NER (en_core_web_sm) | 84% | 0% | 2% | 84% |
| + Heuristic injection detection | 84% | 61% | 3% | 73% |
| + ML injection (DeBERTa ONNX) | 84% | 87% | 4% | 86% |
| + Policy engine (REDACT/BLOCK/ESCALATE) | 84% | 87% | 4% | 92% |
| + Response compliance scanner | 84% | 87% | 4% | 94% |
| **Full AGCMS (all layers active)** | **84%** | **87%** | **4%** | **94%** |

> Note: PII detection rate plateaus at 84% due to edge cases in short text and ambiguous names. Using `en_core_web_trf` (transformer) improves this to ~91% at higher latency (+120ms p50).

---

## Per-Layer Analysis

### Layer 1: Regex PII Detection
- **Contribution:** +68pp PII detection
- **Strength:** Near-perfect recall on structured PII (SSN format `\d{3}-\d{2}-\d{4}`, RFC5321 email)
- **Weakness:** Cannot detect unstructured PII (e.g., "my name is Alice Johnson, born March 5 1985")

### Layer 2: spaCy NER
- **Contribution:** +16pp PII detection over regex alone
- **Strength:** Catches PERSON, ORG, DATE entities not matching regex patterns
- **Weakness:** spaCy `en_core_web_sm` misses contextual PII; `en_core_web_trf` adds ~7pp more at 4× latency

### Layer 3: Heuristic Injection Detection
- **Contribution:** +61pp injection detection
- **Strength:** Fast (< 5ms), no model loading; catches canonical jailbreaks ("ignore previous instructions")
- **Weakness:** Misses novel injection variants, indirect/embedded injections

### Layer 4: ML Injection Classifier (DeBERTa ONNX)
- **Contribution:** +26pp injection detection over heuristics alone
- **Strength:** Generalises to paraphrase attacks; trained on diverse injection corpus
- **Weakness:** ~150ms inference; may miss domain-specific indirect injections

### Layer 5: Policy Engine
- **Contribution:** +6pp enforcement accuracy (correct action for detected violations)
- **Strength:** Configurable per-tenant thresholds; REDACT vs BLOCK vs ESCALATE routing
- **Weakness:** Policy is static until admin deploys new version

### Layer 6: Response Compliance Scanner
- **Contribution:** +2pp enforcement (catches violations in LLM output, not just input)
- **Strength:** Detects restricted topic leakage, system prompt echoing
- **Weakness:** Only post-hoc — cannot prevent LLM from generating; redacts after the fact

---

## Latency Budget (p50, docker compose, MacBook M2 8-core)

| Component | Added Latency (p50) |
|-----------|:-------------------:|
| PII service (regex + spaCy sm) | +45ms |
| PII service (spaCy trf) | +165ms |
| Injection service (heuristic only) | +8ms |
| Injection service (heuristic + DeBERTa ONNX) | +155ms |
| Policy resolver | +12ms |
| Response compliance | +15ms |
| Audit logger (async write) | +3ms |
| **Total (sm model + ONNX)** | **~238ms p50** |
| **Total (trf model + ONNX)** | **~358ms p50** |

Groq LLM latency: ~800ms p50 (not included above — dominates total).

---

## Key Findings

1. **The ML injection classifier is the highest-value single addition** — +26pp detection for injection attacks that evade pattern matching.
2. **Heuristic + ML combination (score = max(heuristic, ml))** reduces false negatives vs either alone.
3. **Policy engine enables per-tenant risk tolerance** — the same detection signal can REDACT for one tenant and BLOCK for another.
4. **Response compliance provides defense-in-depth** for jailbreaks that succeed in manipulating the LLM but whose output can still be detected.
5. **spaCy transformer model is recommended for production** when p50 < 500ms SLA can still be met (Groq dominates latency anyway).
