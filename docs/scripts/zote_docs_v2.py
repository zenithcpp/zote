#!/usr/bin/env python3
# zote_docs_v2.py
# Run from ~/Desktop/ZOTE/
# Rewrites README.md, CONTRIBUTING.md, SECURITY.md
# Professional security engineering language — no hype

import pathlib

# ── README.md ─────────────────────────────────────────────────────────────
readme = '''\
# ZOTE

**zenithcpp Open Source Threat Engine**  
ISO C++23 · Zero external dependencies · Apache 2.0

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![C++23](https://img.shields.io/badge/C%2B%2B-23-blue.svg)](https://en.cppreference.com/w/cpp/23)

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
'''

pathlib.Path("docs/README.md").write_text(readme, encoding="utf-8")
print(f"OK -- docs/README.md rewritten ({len(readme.splitlines())} lines)")

# ── Root README.md ────────────────────────────────────────────────────────
# Root README is a brief pointer — actual content lives in docs/
root_readme = '''\
# ZOTE

**zenithcpp Open Source Threat Engine**  
ISO C++23 · Zero external dependencies · Apache 2.0

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![C++23](https://img.shields.io/badge/C%2B%2B-23-blue.svg)](https://en.cppreference.com/w/cpp/23)

A C++23 library implementing a deterministic threat detection and correlation pipeline for SOC, XDR, and SIEM backends.

**Documentation:** [docs/README.md](docs/README.md)  
**Roadmap:** [docs/ROADMAP.md](docs/ROADMAP.md)  
**Contributing:** [docs/contribution/CONTRIBUTING.md](docs/contribution/CONTRIBUTING.md)  
**Security:** [docs/security/SECURITY.md](docs/security/SECURITY.md)

## Quick Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
ctest --test-dir build
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
'''

pathlib.Path("README.md").write_text(root_readme, encoding="utf-8")
print(f"OK -- README.md (root) rewritten ({len(root_readme.splitlines())} lines)")

# ── CONTRIBUTING.md ───────────────────────────────────────────────────────
contributing = '''\
# Contributing to ZOTE

## Scope

Contributions are accepted in the following areas:

- Detection rule additions or corrections
- MITRE ATT&CK coverage expansions (techniques, actors, software, services)
- Bug fixes with accompanying test cases
- Performance improvements with benchmark evidence
- Documentation corrections
- New unit tests for uncovered code paths

Contributions that introduce external dependencies will not be accepted. ZOTE
is a zero-dependency library; this is a design constraint, not a preference.

## Development Requirements

- GCC 13+ or Clang 16+ with C++23 support
- CMake 3.20+
- Catch2 v3 (for tests)

## Standards

All code must conform to the following:

- ISO C++23. No compiler extensions. No platform-specific headers outside
  the standard library.
- Zero warnings under `-Wall -Wextra` with GCC 13+ and Clang 16+.
- No undefined behaviour. AddressSanitizer and UBSanitizer must pass
  cleanly on the CI sanitizer job.
- Every new public API function must have at least one test case.
- Every bug fix must include a regression test.
- `noexcept` is applied only where genuinely guaranteed — functions that
  allocate or perform I/O are not marked `noexcept`.

## Submitting Changes

1. Fork the repository and create a branch from `main`.
2. Make changes. Run the full test suite locally before submitting.
3. Open a pull request against `main`. Describe the change, its rationale,
   and any limitations.
4. CI must pass. All existing tests must continue to pass.

## Rule Contributions

Detection rules submitted as pull requests must include:

- Rule type, name, and pattern or conditions
- MITRE technique ID where applicable
- Severity classification with justification
- At least one test signal that triggers the rule
- At least one test signal that does not trigger the rule (false positive test)

## Reporting Issues

Security vulnerabilities: see `docs/security/SECURITY.md`.  
All other issues: open a GitHub issue with a minimal reproduction case.
'''

pathlib.Path("docs/contribution/CONTRIBUTING.md").write_text(
    contributing, encoding="utf-8")
print(f"OK -- docs/contribution/CONTRIBUTING.md rewritten "
      f"({len(contributing.splitlines())} lines)")

# ── SECURITY.md ───────────────────────────────────────────────────────────
security = '''\
# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

Only the current release branch receives security fixes.

## Reporting a Vulnerability

Do not open a public GitHub issue for security vulnerabilities.

Report vulnerabilities by email to the maintainers via the contact information
on the repository profile, or open a private security advisory through the
GitHub Security Advisories interface.

Include in your report:

- A description of the vulnerability and its potential impact
- Steps to reproduce, including a minimal test case where possible
- The affected version(s)
- Any suggested remediation

You will receive an acknowledgement within 72 hours. We aim to issue a fix
within 14 days for confirmed vulnerabilities.

## Scope

This policy covers the ZOTE library source code. It does not cover:

- Third-party rule sets loaded by users of the library
- Applications built on top of ZOTE
- The build toolchain or dependencies of the CI environment

## Out of Scope

The following are not considered security vulnerabilities for the purposes
of this policy:

- Performance degradation without impact on correctness or confidentiality
- Issues requiring physical access to a system running ZOTE
- Issues in unreleased development branches

## Disclosure

Confirmed vulnerabilities will be disclosed publicly after a fix has been
released or after 90 days from the initial report, whichever comes first.
'''

pathlib.Path("docs/security/SECURITY.md").write_text(
    security, encoding="utf-8")
print(f"OK -- docs/security/SECURITY.md rewritten "
      f"({len(security.splitlines())} lines)")

print("")
print("ALL DOCS REWRITTEN:")
print("  docs/README.md          — full technical reference")
print("  README.md               — brief root pointer")
print("  docs/contribution/CONTRIBUTING.md")
print("  docs/security/SECURITY.md")
