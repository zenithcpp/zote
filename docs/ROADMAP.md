# ZOTE Roadmap

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
