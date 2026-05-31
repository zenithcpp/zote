# ZOTE

**zenithcpp Open Source Threat Engine**

[![License](https://img.shields.io/badge/License-Apache%202.0-brightgreen.svg)](../LICENSE)
[![C++ ISO](https://img.shields.io/badge/C%2B%2B-ISO%2023-blue.svg)](https://en.cppreference.com/w/cpp/23)
[![Header Standard](https://img.shields.io/badge/Standard-C%2B%2B23-blue.svg)]()
[![Tests](https://img.shields.io/badge/Tests-126%20passing-brightgreen.svg)]()
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14%20%7C%20176%20techniques-red.svg)](https://attack.mitre.org)
[![ICS](https://img.shields.io/badge/ICS%20ATT%26CK-87%20techniques-orange.svg)](https://attack.mitre.org/matrices/ics/)
[![Cppcheck](https://img.shields.io/badge/Cppcheck-clean-brightgreen.svg)]()
[![Dependencies](https://img.shields.io/badge/Dependencies-none-brightgreen.svg)]()
[![Timestamped](https://img.shields.io/badge/Timestamped-Bitcoin%20blockchain-yellow.svg)](ZOTE_v0.1.0.sha256.ots)

---

## Overview

ZOTE is a C++23 library implementing a deterministic threat detection and correlation pipeline. It is intended for use in security platform backends, SOC tooling, XDR engines, and SIEM correlation layers.

The library provides five components that operate as a sequential pipeline:

```
Signal
  ↓ DetectionEngine      rule evaluation with evidence and confidence scoring
  ↓ KillChainMapper      probabilistic kill chain stage inference
  ↓ CorrelationEngine    campaign grouping, UEBA profiling, actor attribution
  ↓ ConfidenceNormalizer cross-engine score combination
  ↓ ThreatAssessment     structured output containing all engine results
```

All confidence scores are deterministic: identical inputs produce identical outputs across runs.

---

## Requirements

- GCC 13+ or Clang 16+ with C++23 support
- CMake 3.20+
- No external libraries required

---

## Build

```bash
git clone https://github.com/zenithcpp/zote
cd zote
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
ctest --test-dir build
```

---

## Components

### DetectionEngine

Evaluates `Signal` objects against a loaded rule set. Each match produces a `DetectionResult` containing the matched rule, confidence score (0.0–1.0), severity score (0.0–10.0), timestamp, kill chain stage, and an evidence vector identifying which signal fields triggered the match.

Supported rule types: `Signature`, `Threshold`, `Behavioral`, `Sigma`, `Suricata`, `Yara`.

Rule conditions use AND semantics across multiple `RuleCondition` entries, each carrying a field name, match type (`Contains`, `Equals`, `StartsWith`, `EndsWith`), value, and weight. The confidence score is computed as the weighted sum of matched conditions divided by the total weight. Legacy single-pattern rules receive a fixed confidence of 0.80.

Suppression is TTL-based, applied at the IP and rule levels. Whitelisted IPs take precedence over all suppression. False positive scores are configurable per rule; rules exceeding the configured threshold are excluded from evaluation.

**Evaluation order:**
1. Whitelist check
2. IP suppression
3. Per rule: enabled flag → FP score → rule suppression → condition evaluation → threshold check → evidence collection → confidence scoring → severity score → timestamp → kill chain mapping

### KillChainMapper

Maps a `Signal` to one or more Lockheed Martin kill chain stages using evidence-based inference. Returns a `KillChainAssessment` containing the primary stage, confidence, a reasons vector, and a candidates vector for signals that span multiple stages.

Mapping priority:
1. MITRE technique ID — confidence 0.90–0.95
2. Description keyword match — confidence 0.75
3. Category string match — confidence 0.70
4. Unknown — confidence 0.0

The `stages_for_technique()` method returns all kill chain stages associated with a given MITRE technique ID, reflecting that some techniques appear across multiple stages.

### MITRE ATT&CK Knowledge Base

Static, compiled-in database. No file loading required at runtime.

Coverage:
- Enterprise v14: 89 techniques and sub-techniques
- ICS matrix: 87 techniques (T08xx)
- 12 threat actors with technique mappings
- 12 software tools with technique mappings
- 15 service-to-technique mappings
- D3FEND countermeasure mappings for 12 techniques
- ATT&CK Navigator 4.9 JSON export via `NavigatorLayer::to_json()`

Queries are composable via `MitreQuery`, supporting optional filters on actor, software, service, tactic, minimum severity, and platform. Filters are applied with AND semantics.

### CorrelationEngine

Groups `CorrelatedAlert` objects into campaigns by source IP using an O(1) hash index. Each campaign maintains a full `TimelineEvent` sequence, a kill chain stage set, a risk score, and a lifecycle state (`Active`, `Dormant`, `Closed`).

UEBA profiling tracks per-IP alert counts over a 24-hour window, unique destination counts, and an anomaly score. The anomaly threshold is configurable via `CorrelationConfig`.

Actor attribution scores known threat actors against the campaign's MITRE technique set and returns an `Attribution` containing the attributed actor, confidence, and matched techniques.

The `submit()` method accepts a `KillChainAssessment` directly, providing an integration hook from the kill chain engine to the correlation engine without constructing a full `CorrelatedAlert`.

### ConfidenceNormalizer

Combines confidence scores from the detection engine, UEBA subsystem, and kill chain mapper into a single normalized score using configurable weights. The `ConfidenceModel` struct carries versioned weights to ensure reproducibility across deployments.

Default weights: detection 0.50, UEBA 0.30, kill chain 0.20.

### ZoteEngine

Orchestrates the full pipeline. Accepts a `Signal`, runs detection, kill chain inference, confidence normalization, correlation ingestion, and actor attribution, and returns a `ThreatAssessment`.

Also provides a streaming callback overload (`process(Signal, AlertCallback)`) for low-latency alerting and a batch overload (`process_batch(span<Signal>)`) for bulk processing.

---

## Usage

### Minimal example

```cpp
#include <zote/zote_engine.hpp>

zote::ZoteEngine engine;

zote::DetectionRule rule;
rule.id       = zote::RuleId{1};
rule.type     = zote::RuleType::Signature;
rule.name     = "RansomwareDetection";
rule.pattern  = "ransomware";
rule.severity = zote::Severity::Critical;
rule.mitre_id = zote::TechniqueId{"T1486"};
engine.add_rule(rule);

zote::Signal sig;
sig.net.src     = zote::IpAddress{std::string{"185.220.101.47"}};
sig.description = "ransomware process encrypting file shares";
sig.mitre_id    = zote::TechniqueId{"T1486"};

auto a = engine.process(sig);
// a.risk.score           — accumulated risk 0.0–10.0
// a.risk.confidence      — normalized confidence 0.0–1.0
// a.kill_chain.stage     — primary kill chain stage
// a.attribution.actor    — attributed threat actor
// a.recommendations      — suggested response actions
```

### Structured conditions

```cpp
zote::DetectionRule rule;
rule.id      = zote::RuleId{2};
rule.name    = "NetcatReverseShell";
rule.type    = zote::RuleType::Signature;
rule.enabled = true;

// All conditions must match (AND semantics).
// Weight contributes to confidence calculation.
rule.conditions.push_back({
    "proc.name",    zote::ConditionType::Contains, "nc",  0.8f});
rule.conditions.push_back({
    "proc.cmdline", zote::ConditionType::Contains, "-e",  1.0f});
rule.conditions.push_back({
    "proc.cmdline", zote::ConditionType::Contains, "/bin/sh", 1.0f});
```

### MITRE ATT&CK queries

```cpp
// Direct lookup
const auto* t = zote::MitreDb::lookup("T1566");

// Composable query
zote::MitreQuery q;
q.actor       = zote::ActorId{"APT29"};
q.platform    = "Windows";
q.min_severity = zote::Severity::High;
auto refs = zote::MitreDb::query(q); // vector<TechniqueRef>

// D3FEND countermeasures
auto cms = zote::MitreDb::d3fend_for("T1486");

// Navigator export
auto layer = zote::MitreDb::build_layer(
    {"T1566", "T1059", "T1486"}, "APT29 Investigation");
std::string json = layer.to_json();
```

### Kill chain assessment

```cpp
zote::Signal sig;
sig.description = "cobaltstrike beacon to external host";
sig.mitre_id    = zote::TechniqueId{"T1071"};

auto a = zote::KillChainMapper::assess(sig);
// a.stage       — primary stage (CommandControl)
// a.confidence  — 0.95 (MITRE ID match)
// a.reasons     — field, match, weight, contribution per reason
// a.candidates  — all matching stages with individual confidence
```

---

## Thread Safety

Thread safety model: `std::mutex` per engine instance (v0.1).

| Operation | Behaviour |
|-----------|-----------|
| `evaluate()`, `process()` | Safe for concurrent calls from multiple threads |
| `stats()`, `rule_count()` | Read-only; always safe |
| `add_rule()`, `remove_rule()`, `suppress_*()` | Serialized; one writer at a time |
| `reset()`, `clear()` | Serialized; one writer at a time |

v0.2 planned: reader–writer lock separating evaluation reads from rule-write operations.

---

## Repository Layout

```
include/zote/
  types.hpp          Canonical type definitions (19 sections)
  engine.hpp         DetectionEngine — Detection Runtime Kernel
  killchain.hpp      KillChainMapper — Kill Chain Inference Engine
  mitre.hpp          MitreDb — ATT&CK knowledge base
  correlation.hpp    CorrelationEngine — campaign and UEBA engine
  zote_engine.hpp    ZoteEngine — pipeline orchestrator

src/
  engine.cpp
  killchain.cpp
  mitre_map.cpp      ATT&CK compiled-in database (176 techniques)
  correlation.cpp
  zote_engine.cpp

tests/unit/          126 test cases (Catch2)
examples/            4 annotated usage examples
docs/                Documentation, roadmap, contribution guidelines
.github/workflows/   CI configuration (GCC 13/14, Clang 17, ASan, cppcheck)
```

---

## Known Limitations (v0.1)

- Rule evaluation is O(n) per signal. No field index. Performance degrades linearly with rule count above ~10,000.
- Rules are interpreted at evaluation time. No pre-compilation.
- MITRE technique-to-tactic mapping is one-to-one. Multi-tactic techniques use the primary tactic only.
- IP suppression uses exact string matching. CIDR notation is accepted in the whitelist field but not expanded for suppression.
- Mobile ATT&CK matrix returns an empty set.

These limitations are documented in the v0.2 roadmap (`docs/ROADMAP.md`).

---

## License

Apache License 2.0. See `LICENSE`.
