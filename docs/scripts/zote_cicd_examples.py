#!/usr/bin/env python3
# zote_cicd_examples.py
# Run from ~/Desktop/ZOTE/
# Writes GitHub Actions CI/CD + 3 examples + ROADMAP.md

import pathlib

# ── GitHub Actions ────────────────────────────────────────────────────────
pathlib.Path(".github/workflows").mkdir(parents=True, exist_ok=True)

ci = '''name: ZOTE CI

on:
  push:
    branches: [ main, dev ]
  pull_request:
    branches: [ main ]

jobs:
  build-and-test:
    name: Build and Test (${{ matrix.os }}, ${{ matrix.compiler }})
    runs-on: ${{ matrix.os }}

    strategy:
      fail-fast: false
      matrix:
        include:
          - os: ubuntu-24.04
            compiler: gcc-13
            cc: gcc-13
            cxx: g++-13
          - os: ubuntu-24.04
            compiler: gcc-14
            cc: gcc-14
            cxx: g++-14
          - os: ubuntu-24.04
            compiler: clang-17
            cc: clang-17
            cxx: clang++-17

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Install compiler (${{ matrix.compiler }})
        run: |
          sudo apt-get update -qq
          sudo apt-get install -y ${{ matrix.cc }} ${{ matrix.cxx }} cmake ninja-build

      - name: Install Catch2
        run: |
          sudo apt-get install -y catch2 || true
          # Fallback: build from source if package not available
          if ! dpkg -l | grep -q catch2; then
            git clone --depth 1 --branch v3.7.1 \\
              https://github.com/catchorg/Catch2.git /tmp/catch2
            cmake -S /tmp/catch2 -B /tmp/catch2/build \\
              -DCMAKE_BUILD_TYPE=Release \\
              -DBUILD_TESTING=OFF
            sudo cmake --build /tmp/catch2/build --target install -j$(nproc)
          fi

      - name: Configure
        env:
          CC: ${{ matrix.cc }}
          CXX: ${{ matrix.cxx }}
        run: |
          cmake -S . -B build \\
            -DCMAKE_BUILD_TYPE=Release \\
            -DCMAKE_CXX_STANDARD=23 \\
            -G Ninja

      - name: Build
        run: cmake --build build -j$(nproc)

      - name: Test
        run: ctest --test-dir build --output-on-failure

      - name: Test report
        if: always()
        run: |
          ./build/test_zote --reporter junit > test_results.xml || true

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: test-results-${{ matrix.os }}-${{ matrix.compiler }}
          path: test_results.xml

  static-analysis:
    name: Static Analysis
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4

      - name: Install tools
        run: |
          sudo apt-get update -qq
          sudo apt-get install -y cppcheck cmake

      - name: Run cppcheck
        run: |
          cppcheck --std=c++23 \\
            --enable=all \\
            --suppress=missingIncludeSystem \\
            --suppress=unmatchedSuppression \\
            --error-exitcode=1 \\
            -I include \\
            src/

  sanitizers:
    name: Sanitizers (ASan + UBSan)
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4

      - name: Install
        run: |
          sudo apt-get update -qq
          sudo apt-get install -y g++-13 cmake ninja-build catch2 || true

      - name: Configure with sanitizers
        env:
          CC: gcc-13
          CXX: g++-13
        run: |
          cmake -S . -B build-san \\
            -DCMAKE_BUILD_TYPE=Debug \\
            -DCMAKE_CXX_STANDARD=23 \\
            -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \\
            -G Ninja

      - name: Build
        run: cmake --build build-san -j$(nproc)

      - name: Test under sanitizers
        env:
          ASAN_OPTIONS: detect_leaks=1
          UBSAN_OPTIONS: print_stacktrace=1
        run: ctest --test-dir build-san --output-on-failure
'''

pathlib.Path(".github/workflows/ci.yml").write_text(ci, encoding="utf-8")
print("OK -- .github/workflows/ci.yml written")

# ── Example 1: threat_hunting.cpp ────────────────────────────────────────
ex1 = '''// examples/threat_hunting.cpp
// ZOTE — zenithcpp Open Source Threat Engine
//
// Example: Threat hunting with MITRE ATT&CK
// Demonstrates:
//   - Querying techniques by actor, tactic, platform
//   - D3FEND countermeasure lookup
//   - Navigator layer export

#include <zote/mitre.hpp>
#include <zote/killchain.hpp>
#include <iostream>
#include <vector>

int main() {
    std::cout << "ZOTE Threat Hunting Example\\n";
    std::cout << "MITRE ATT&CK v" << zote::MitreDb::attack_version()
              << " | " << zote::MitreDb::total_size()
              << " techniques\\n\\n";

    // ── Hunt: APT29 techniques on Windows ────────────────────────────────
    std::cout << "=== APT29 techniques (Windows) ===\\n";
    zote::MitreQuery q;
    q.actor    = zote::ActorId{"APT29"};
    q.platform = "Windows";
    auto results = zote::MitreDb::query(q);
    for (const auto& ref : results) {
        const auto& t = ref.get();
        std::cout << "  " << t.id
                  << " [" << t.tactic << "] "
                  << t.name << "\\n";
    }

    // ── Kill chain for key techniques ────────────────────────────────────
    std::cout << "\\n=== Kill chain mapping ===\\n";
    std::vector<std::string> hunt_ids = {
        "T1566", "T1059", "T1003", "T1071", "T1486"
    };
    for (const auto& tid : hunt_ids) {
        auto stage = zote::KillChainMapper::from_mitre_id(tid);
        auto* t    = zote::MitreDb::lookup(tid);
        if (t) {
            std::cout << "  " << tid << " " << t->name
                      << " → "
                      << zote::KillChainMapper::stage_name(stage)
                      << "\\n";
        }
    }

    // ── D3FEND countermeasures ────────────────────────────────────────────
    std::cout << "\\n=== D3FEND countermeasures for T1486 (Ransomware) ===\\n";
    auto cms = zote::MitreDb::d3fend_for("T1486");
    for (const auto& cm : cms)
        std::cout << "  → " << cm << "\\n";

    // ── Navigator export ──────────────────────────────────────────────────
    std::cout << "\\n=== ATT&CK Navigator export ===\\n";
    auto layer = zote::MitreDb::build_layer(
        hunt_ids, "APT29 Hunt");
    std::string json = layer.to_json();
    std::cout << "  Layer JSON (" << json.size()
              << " bytes) ready for navigator.attack.mitre.org\\n";
    std::cout << "  " << json.substr(0, 80) << "...\\n";

    return 0;
}
'''
pathlib.Path("examples/threat_hunting.cpp").write_text(ex1, encoding="utf-8")
print("OK -- examples/threat_hunting.cpp written")

# ── Example 2: campaign_analysis.cpp ─────────────────────────────────────
ex2 = '''// examples/campaign_analysis.cpp
// ZOTE — zenithcpp Open Source Threat Engine
//
// Example: Multi-stage attack campaign analysis
// Demonstrates:
//   - ZoteEngine full pipeline
//   - Campaign grouping across multiple signals
//   - Kill chain progression tracking
//   - Actor attribution

#include <zote/zote_engine.hpp>
#include <iostream>

static zote::DetectionRule make_rule(
    std::uint64_t id,
    const std::string& name,
    const std::string& pattern,
    zote::Severity sev,
    const std::string& mitre = "") {
    zote::DetectionRule r;
    r.id       = zote::RuleId{id};
    r.type     = zote::RuleType::Signature;
    r.name     = name;
    r.pattern  = pattern;
    r.severity = sev;
    r.enabled  = true;
    if (!mitre.empty())
        r.mitre_id = zote::TechniqueId{mitre};
    return r;
}

int main() {
    std::cout << "ZOTE Campaign Analysis Example\\n\\n";

    zote::ZoteEngine engine;

    // Load detection rules representing attack stages
    engine.add_rule(make_rule(1, "PortScan",
        "port scan", zote::Severity::Low,    "T1595"));
    engine.add_rule(make_rule(2, "Phishing",
        "phishing",  zote::Severity::High,   "T1566"));
    engine.add_rule(make_rule(3, "Exploit",
        "exploit",   zote::Severity::High,   "T1190"));
    engine.add_rule(make_rule(4, "C2Beacon",
        "beacon",    zote::Severity::Critical,"T1071"));
    engine.add_rule(make_rule(5, "Ransomware",
        "ransomware",zote::Severity::Critical,"T1486"));

    // Simulate a multi-stage attack from one source
    const std::string attacker = "185.220.101.47";

    struct AttackEvent {
        std::string description;
        std::string mitre_id;
    };

    std::vector<AttackEvent> events = {
        {"port scan detected on perimeter",          "T1595"},
        {"phishing email with malicious attachment", "T1566"},
        {"exploit attempt against web application",  "T1190"},
        {"c2 beacon outbound to suspicious host",    "T1071"},
        {"ransomware encrypting file shares",        "T1486"},
    };

    std::cout << "=== Processing attack sequence from "
              << attacker << " ===\\n\\n";

    for (const auto& ev : events) {
        zote::Signal sig;
        sig.net.src     = zote::IpAddress{std::string(attacker)};
        sig.description = ev.description;
        sig.mitre_id    = zote::TechniqueId{ev.mitre_id};

        auto assessment = engine.process(sig);

        std::cout << "  Signal: " << ev.description << "\\n";
        if (assessment.risk.score > 0.0f) {
            std::cout << "    Risk:       " << assessment.risk.score
                      << "/10\\n";
            std::cout << "    Confidence: " << assessment.risk.confidence
                      << "\\n";
            std::cout << "    Stage:      "
                      << zote::KillChainMapper::stage_name(
                             assessment.kill_chain.furthest_stage)
                      << "\\n";
            if (!assessment.attribution.actor.empty())
                std::cout << "    Actor:      "
                          << assessment.attribution.actor.value
                          << " (conf="
                          << assessment.attribution.confidence
                          << ")\\n";
            for (const auto& rec : assessment.recommendations)
                std::cout << "    → " << rec << "\\n";
        } else {
            std::cout << "    (no detection)\\n";
        }
        std::cout << "\\n";
    }

    // Campaign summary
    auto camps = engine.campaigns_snapshot();
    if (!camps.empty()) {
        const auto& camp = camps[0];
        std::cout << "=== Campaign Summary ===\\n";
        std::cout << "  Name:        " << camp.name << "\\n";
        std::cout << "  Risk score:  " << camp.risk_score << "/10\\n";
        std::cout << "  Alerts:      " << camp.alert_count << "\\n";
        std::cout << "  Stages seen: " << camp.stages.size() << "\\n";
        std::cout << "  Timeline:    " << camp.timeline.size()
                  << " events\\n";

        auto attr = engine.attribute_actor(camp.id);
        if (!attr.actor.empty()) {
            std::cout << "  Attribution: " << attr.actor.value
                      << " (confidence=" << attr.confidence << ")\\n";
            std::cout << "  Techniques matched: "
                      << attr.matched_techniques.size() << "\\n";
        }
    }

    return 0;
}
'''
pathlib.Path("examples/campaign_analysis.cpp").write_text(ex2, encoding="utf-8")
print("OK -- examples/campaign_analysis.cpp written")

# ── Example 3: confidence_scoring.cpp ────────────────────────────────────
ex3 = '''// examples/confidence_scoring.cpp
// ZOTE — zenithcpp Open Source Threat Engine
//
// Example: Confidence normalization across engines
// Demonstrates:
//   - DetectionEngine confidence
//   - KillChainMapper confidence
//   - ConfidenceNormalizer combining scores
//   - ConfidenceModel versioning

#include <zote/engine.hpp>
#include <zote/killchain.hpp>
#include <zote/types.hpp>
#include <iostream>
#include <iomanip>

int main() {
    std::cout << "ZOTE Confidence Scoring Example\\n";
    std::cout << "ZOTE v" << zote::version().to_string() << "\\n\\n";

    // ── Detection engine setup ────────────────────────────────────────────
    zote::DetectionEngine eng;

    // Rule with structured conditions for precise confidence
    zote::DetectionRule rule;
    rule.id      = zote::RuleId{1};
    rule.name    = "C2BeaconDetection";
    rule.type    = zote::RuleType::Signature;
    rule.enabled = true;
    rule.severity = zote::Severity::High;
    rule.mitre_id = zote::TechniqueId{"T1071"};

    // Multiple weighted conditions
    rule.conditions.push_back({
        "description", zote::ConditionType::Contains,
        "beacon", 0.8f});
    rule.conditions.push_back({
        "description", zote::ConditionType::Contains,
        "outbound", 0.6f});
    rule.conditions.push_back({
        "proc.name", zote::ConditionType::Contains,
        "powershell", 1.0f});
    eng.add_rule(rule);

    // ── Test signals with varying confidence ─────────────────────────────
    struct TestCase {
        std::string description;
        std::string proc_name;
        std::string label;
    };

    std::vector<TestCase> cases = {
        {"outbound beacon detected",   "powershell.exe", "Full match"},
        {"beacon detected",            "",               "Partial match"},
        {"suspicious outbound traffic","",               "Weak match"},
        {"normal web traffic",         "",               "No match"},
    };

    std::cout << std::fixed << std::setprecision(2);
    std::cout << "=== Detection confidence ===\\n";

    for (const auto& tc : cases) {
        zote::Signal sig;
        sig.description     = tc.description;
        sig.proc.process_name = tc.proc_name;
        sig.net.src = zote::IpAddress{std::string("1.2.3.4")};

        auto results = eng.evaluate(sig);
        auto kc      = zote::KillChainMapper::assess(sig);

        float det_conf = results.empty() ? 0.0f : results[0].confidence;
        float kc_conf  = kc.confidence;

        // Simulate UEBA score (would come from CorrelationEngine)
        float ueba_conf = det_conf > 0.5f ? 0.7f : 0.1f;

        float combined = zote::ConfidenceNormalizer::combine(
            det_conf, ueba_conf, kc_conf);

        std::cout << "  " << tc.label << ":\\n";
        std::cout << "    Detection:   " << det_conf << "\\n";
        std::cout << "    Kill chain:  " << kc_conf
                  << " (" << zote::KillChainMapper::stage_name(kc.stage)
                  << ")\\n";
        std::cout << "    UEBA:        " << ueba_conf << "\\n";
        std::cout << "    Combined:    " << combined << "\\n";
        if (!results.empty()) {
            std::cout << "    Severity:    "
                      << results[0].severity_score << "/10\\n";
            std::cout << "    Evidence:    "
                      << results[0].evidence.size() << " items\\n";
        }
        std::cout << "\\n";
    }

    // ── Custom confidence model ───────────────────────────────────────────
    std::cout << "=== Custom confidence model (EDR-heavy) ===\\n";
    zote::ConfidenceModel edr_model;
    edr_model.w_detection  = 0.70f; // trust EDR more
    edr_model.w_ueba       = 0.20f;
    edr_model.w_kill_chain = 0.10f;
    edr_model.version      = 2;

    float custom = edr_model.apply(0.9f, 0.6f, 0.8f);
    float default_score = zote::DEFAULT_CONFIDENCE_MODEL.apply(
        0.9f, 0.6f, 0.8f);

    std::cout << "  Default model (v"
              << zote::DEFAULT_CONFIDENCE_MODEL.version
              << "): " << default_score << "\\n";
    std::cout << "  EDR model     (v"
              << edr_model.version << "): " << custom << "\\n";

    return 0;
}
'''
pathlib.Path("examples/confidence_scoring.cpp").write_text(ex3, encoding="utf-8")
print("OK -- examples/confidence_scoring.cpp written")

# ── ROADMAP.md ─────────────────────────────────────────────────────────────
roadmap = '''# ZOTE Roadmap

## v0.1 — Foundation (current)

**Status:** Complete

### What is included
- Detection Runtime Kernel (DRK) — rule-based detection with evidence and confidence
- Kill Chain Inference Engine (KCIE) — evidence-based ATT&CK kill chain mapping
- MITRE ATT&CK knowledge base — Enterprise v14 + ICS, 176+ techniques
- Correlation Engine — campaign grouping, UEBA, actor attribution
- ZoteEngine — unified product interface
- 126 tests, 0 warnings, 0 errors

### Known limitations
- Rule evaluation is O(n) per signal (no index)
- Rules are interpreted at runtime (no compilation)
- MITRE techniques map to single primary tactic (not many-to-many)
- IP suppression is exact-match only (no CIDR)
- Mobile ATT&CK matrix is empty

---

## v0.2 — Production Core

**Target:** Q3 2026

### REQ-ZOTE-001: Rule compilation layer
- `CompiledRule` — pre-compiled execution graph
- Lowercase normalization at compile time
- Pre-tokenized patterns
- Threshold metadata baked in

### REQ-ZOTE-002: Field indexing
- `RuleIndex` — field → rule mapping
- O(1) dispatch for common fields
- Eliminates O(n) scan per signal

### REQ-ZOTE-003: Separate parser classes
- `SigmaParser` — loads Sigma YAML rules
- `SuricataParser` — loads Suricata .rules files
- Clean separation from DetectionEngine

### REQ-ZOTE-004: CIDR suppression
- IP range matching in suppress_ip()
- Support for /8, /16, /24, /32

### REQ-ZOTE-005: Sliding window engine
- Time-series aware threshold evaluation
- Sliding window counter per rule
- Decay functions for temporal scoring

### REQ-ZOTE-006: Full mobile ATT&CK matrix
- Complete T14xx/T16xx technique coverage
- Mobile-specific actor mappings

### REQ-ZOTE-007: Campaign merge
- Merge campaigns from same actor using different IPs
- Attribution-driven merge heuristics

### REQ-ZOTE-008: Feature-based inference
- `KillChainFeature` — weighted feature extraction
- Replace keyword matching with feature scoring
- `KillChainEngine` instance with campaign context

### REQ-ZOTE-009: Temporal progression
- Kill chain progression over time
- Stage transition tracking
- Campaign-aware stage inference

### REQ-ZOTE-010: MITRE many-to-many
- `MitreTechnique.tactics` as vector
- True many-to-many tactic mapping

### REQ-ZOTE-011: Confidence normalization v2
- Normalized confidence across all engines
- Versioned `ConfidenceModel` enforcement

### REQ-ZOTE-012: JSON import/export
- `campaign_to_json()` / `campaign_from_json()`
- No external library required

### REQ-ZOTE-013: O(1) lookup tables
- `unordered_map` for all technique lookups
- Actor/software/service indexed at startup

### REQ-ZOTE-014: Graph-based stage reasoning
- Technique relationship graph
- Multi-hop attribution

---

## v1.0 — Enterprise Grade

**Target:** Q1 2027

### Performance
- String interning (`FieldId`, `TechniqueIndex`)
- Lock-free ingestion pipeline
- Parallel batch processing
- Arena allocator for hot path
- Target: 100k EPS single thread

### Intelligence
- Full UEBA v2 — baselines, beaconing, temporal anomalies
- Peer group analysis
- Behavioral fingerprinting

### Platform
- Graph-based threat model (IP/host/user/technique nodes)
- Threat hunting API — `hunt(technique_id, time_range)`
- Streaming interface — `subscribe(callback)`
- Multi-source correlation — EDR/firewall/DNS/NetFlow fusion

### Developer Experience
- Plugin SDK — custom scoring, exporters, rule loaders
- Dynamic rule loading — hot-swap without restart
- Audit logging — rule/config/intel change tracking
- Deterministic replay — `replay(alert_stream)`

### Quality
- Fuzz testing — all parsers and signal inputs
- Benchmark suite — 1k/10k/100k/1M EPS
- Property-based tests
- Full SAST/DAST pipeline

---

## Contributing

See [CONTRIBUTING.md](contribution/CONTRIBUTING.md) for how to contribute
rules, techniques, examples, or code.

Issues and discussions: [github.com/zenithcpp/zote](https://github.com/zenithcpp/zote)
'''

pathlib.Path("docs/ROADMAP.md").write_text(roadmap, encoding="utf-8")
print(f"OK -- docs/ROADMAP.md written ({len(roadmap.splitlines())} lines)")

print("")
print("ALL FILES WRITTEN:")
print("  .github/workflows/ci.yml")
print("  examples/threat_hunting.cpp")
print("  examples/campaign_analysis.cpp")
print("  examples/confidence_scoring.cpp")
print("  docs/ROADMAP.md")
