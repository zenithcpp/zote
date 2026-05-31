#!/usr/bin/env python3
# zote_readme.py
# Run from ~/Desktop/ZOTE/
# Writes README.md

import pathlib

readme = '''# ZOTE — zenithcpp Open Source Threat Engine

> A deterministic, evidence-based threat detection and correlation engine.  
> ISO C++23 · Zero external dependencies · Apache 2.0

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![C++](https://img.shields.io/badge/C%2B%2B-23-blue.svg)](https://en.cppreference.com/w/cpp/23)
[![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Tests](https://img.shields.io/badge/tests-126%20passing-brightgreen.svg)]()

---

## What is ZOTE?

ZOTE is a C++23 threat detection and correlation library designed for security engineers building SOC platforms, XDR engines, and SIEM backends.

It provides a complete, production-oriented pipeline:

```
Signal
  → DetectionEngine     rule-based detection with evidence + confidence
  → KillChainMapper     ATT&CK-aware kill chain inference
  → CorrelationEngine   campaign grouping, UEBA, actor attribution
  → ThreatAssessment    unified output for analyst consumption
```

Every decision is explainable. Every result carries evidence. Every confidence score is deterministic and reproducible.

---

## Features

**Detection Runtime Kernel**
- Signature, threshold, behavioral, Sigma, Suricata, and YARA-like rules
- Structured condition system (`RuleCondition` with field, type, weight)
- Evidence vector on every match — analysts know exactly why a rule fired
- Deterministic confidence scoring (0.0–1.0)
- False positive tuning per rule
- TTL-based IP and rule suppression
- Permanent IP/CIDR whitelist

**Kill Chain Inference Engine**
- Lockheed Martin 7-stage kill chain mapping
- Evidence-based `KillChainAssessment` with confidence and reasons
- Multi-stage candidate output — one signal can span multiple stages
- MITRE technique ID → stage mapping (90–95% confidence)
- Keyword inference fallback (75–80% confidence)
- `stages_for_technique()` — all kill chain stages for a given technique

**MITRE ATT&CK Knowledge Base**
- Enterprise v14: 89+ techniques and sub-techniques
- ICS matrix: 87 techniques (T08xx range)
- 12 threat actors: APT28, APT29, APT41, Lazarus, LockBit, FIN7, Cobalt, Sandworm, and more
- 12 software tools: Mimikatz, CobaltStrike, Metasploit, Impacket, BloodHound, Sliver, and more
- 15 service mappings: SSH, RDP, SMB, HTTP/S, DNS, LDAP, and more
- D3FEND countermeasure mappings
- ATT&CK Navigator 4.9 JSON export
- Composable `MitreQuery` — filter by actor, software, service, tactic, severity, platform

**Correlation Engine**
- Campaign grouping by source IP with O(1) index
- Full attack timeline with kill chain stage per event
- UEBA profiling — 24h alert counters, unique destination tracking, anomaly scoring
- Threat actor attribution from MITRE technique signatures
- `Attribution` carries actor, confidence, and matched techniques
- Campaign lifecycle: Active → Dormant → Closed

**Confidence Normalization**
- `ConfidenceNormalizer` — combines detection, UEBA, and kill chain scores
- `ConfidenceModel` — versioned weights for reproducible scoring
- Default weights: detection 50%, UEBA 30%, kill chain 20%

**ZoteEngine — Unified Product Interface**
- Single entry point wiring all engines together
- `process(Signal)` → `ThreatAssessment`
- Streaming callback API for high-throughput pipelines
- Batch processing with `process_batch(span<Signal>)`

---

## Quick Start

### Requirements

- C++23 compiler (GCC 13+, Clang 16+)
- CMake 3.20+
- No other dependencies

### Build

```bash
git clone https://github.com/zenithcpp/zote
cd zote
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

### Run tests

```bash
ctest --test-dir build --verbose
```

---

## Usage

### ZoteEngine — simplest API

```cpp
#include <zote/zote_engine.hpp>

// Create engine
zote::ZoteEngine engine;

// Add detection rules
zote::DetectionRule rule;
rule.id       = zote::RuleId{1};
rule.type     = zote::RuleType::Signature;
rule.name     = "RansomwareDetection";
rule.pattern  = "ransomware";
rule.severity = zote::Severity::Critical;
rule.tags     = {"ransomware", "impact", "windows"};
engine.add_rule(rule);

// Process a signal
zote::Signal sig;
sig.net.src      = zote::IpAddress{"1.2.3.4"};
sig.description  = "ransomware encrypting files on host";
sig.mitre_id     = zote::TechniqueId{"T1486"};

auto assessment = engine.process(sig);

// Results
std::cout << "Risk score:  " << assessment.risk.score      << "\\n";
std::cout << "Confidence:  " << assessment.risk.confidence << "\\n";
std::cout << "Kill chain:  " << zote::KillChainMapper::stage_name(
    assessment.kill_chain.furthest_stage) << "\\n";
std::cout << "Actor:       " << assessment.attribution.actor.value << "\\n";

// Countermeasures
auto cms = zote::ZoteEngine::countermeasures_for(
    zote::TechniqueId{"T1486"});
for (const auto& cm : cms)
    std::cout << "  → " << cm << "\\n";
```

### Streaming callback API

```cpp
engine.process(sig, [](const zote::DetectionResult& r) {
    std::cout << "[ALERT] " << r.rule_name
              << " confidence=" << r.confidence << "\\n";
    for (const auto& e : r.evidence)
        std::cout << "  evidence: " << e.field << "=" << e.value << "\\n";
});
```

### Condition-based rules

```cpp
zote::DetectionRule rule;
rule.id      = zote::RuleId{2};
rule.name    = "NetcatReverse";
rule.type    = zote::RuleType::Signature;
rule.enabled = true;

// Structured conditions — AND semantics
rule.conditions.push_back({
    "proc.name", zote::ConditionType::Contains, "nc", 0.8f});
rule.conditions.push_back({
    "proc.cmdline", zote::ConditionType::Contains, "-e", 1.0f});
```

### MITRE ATT&CK queries

```cpp
// Lookup technique
auto* t = zote::MitreDb::lookup("T1566");
std::cout << t->name << " — " << t->tactic_name << "\\n";

// All techniques used by APT28
auto techs = zote::MitreDb::by_actor("APT28");

// Composable query — Windows techniques in Initial Access with High severity
zote::MitreQuery q;
q.tactic       = "TA0001";
q.platform     = "Windows";
q.min_severity = zote::Severity::High;
auto results   = zote::MitreDb::query(q);

// Navigator export
auto layer = zote::MitreDb::build_layer(
    {"T1566", "T1059", "T1486"}, "My Campaign");
std::string json = layer.to_json();
```

### Kill chain inference

```cpp
zote::Signal sig;
sig.description = "cobaltstrike beacon outbound";

auto assessment = zote::KillChainMapper::assess(sig);
std::cout << zote::KillChainMapper::stage_name(assessment.stage)
          << " (" << assessment.confidence << ")\\n";

// All matching stages
for (const auto& sc : assessment.candidates)
    std::cout << "  candidate: "
              << zote::KillChainMapper::stage_name(sc.stage)
              << " " << sc.confidence << "\\n";
```

---

## Architecture

```
include/zote/
  types.hpp          Canonical data model (19 sections)
  engine.hpp         Detection Runtime Kernel (DRK)
  killchain.hpp      Kill Chain Inference Engine (KCIE)
  mitre.hpp          ATT&CK knowledge base
  correlation.hpp    Campaign + UEBA + attribution
  zote_engine.hpp    Unified product interface

src/
  engine.cpp         Rule evaluation pipeline
  killchain.cpp      Evidence-based stage inference
  mitre_map.cpp      ATT&CK database (176+ techniques)
  correlation.cpp    Campaign lifecycle + UEBA
  zote_engine.cpp    Pipeline orchestration
```

### Evaluation pipeline (DetectionEngine)

```
1. Whitelist check        suppress if IP in whitelist
2. IP suppression         suppress if IP TTL active
3. Rule loop:
   a. enabled check
   b. FP score filter      suppress if fp_score >= threshold
   c. rule suppression     suppress if rule TTL active
   d. condition eval       structured conditions (AND) or pattern
   e. threshold check      skip if count < N in window
   f. evidence collection  populate result.evidence
   g. confidence scoring   weighted sum of conditions
   h. severity score       severity_score(severity) → 0–10
   i. timestamp            now_us()
   j. kill chain           KillChainMapper::map(signal)
4. Return matched results
```

---

## Thread Safety

All public APIs are thread-safe under a mutex-per-engine model.

| Operation | Thread safe |
|-----------|-------------|
| `evaluate()`, `process()` | Multiple threads concurrent |
| `stats()`, `rule_count()` | Read-only, always safe |
| `add_rule()`, `suppress_*()` | Serialized writes |
| `reset()`, `clear()` | Serialized writes |

v0.2 target: lock-free reads + locked writes.

---

## Roadmap

### v0.2
- `CompiledRule` — pre-compiled rule execution graph
- `RuleIndex` — field-indexed O(1) dispatch
- `SigmaParser` and `SuricataParser` as separate classes
- CIDR suppression expansion
- Sliding window detection engine
- Full MITRE mobile ATT&CK matrix
- Campaign merge support
- JSON import/export

### v1.0
- String interning (`FieldId`, `TechniqueIndex`)
- Lock-free ingestion pipeline
- Graph-based threat modeling
- Plugin SDK (custom scoring, exporters)
- Threat hunting API
- Full UEBA v2 (baselines, beaconing, temporal anomalies)

---

## Design Principles

**Explainability first.** Every `DetectionResult` carries an evidence vector. Every `KillChainAssessment` carries reasons. Analysts must understand why the engine fired.

**Deterministic.** Same signal + same rules = same output. No randomness in the hot path.

**Zero dependencies.** ZOTE compiles with a C++23 compiler and nothing else. Runs fully air-gapped.

**ISO C++23.** No platform-specific extensions. No UB. No hidden allocations on the hot path.

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

Issues, PRs, and rule contributions welcome at [github.com/zenithcpp/zote](https://github.com/zenithcpp/zote).
'''

pathlib.Path("README.md").write_text(readme, encoding="utf-8")
lines = len(readme.splitlines())
print(f"OK -- README.md written ({lines} lines)")
