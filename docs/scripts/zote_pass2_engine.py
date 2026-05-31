#!/usr/bin/env python3
# zote_pass2_engine.py
# Run from ~/Desktop/ZOTE/
# Pass 2: engine.hpp — restore noexcept on hot path,
#          named internal structs, EPS doc, pipeline contract

import pathlib

p = pathlib.Path("include/zote/engine.hpp")
content = p.read_text()

# Restore noexcept on hot path evaluate functions
content = content.replace(
    "    [[nodiscard]] std::vector<DetectionResult>\n    evaluate(const Signal& signal);",
    "    [[nodiscard]] std::vector<DetectionResult>\n    evaluate(const Signal& signal) noexcept;"
)
content = content.replace(
    "    void evaluate(const Signal&  signal,\n                  AlertCallback  cb) noexcept;",
    "    void evaluate(const Signal&  signal,\n                  AlertCallback  cb) noexcept;"  # already correct
)
content = content.replace(
    "    [[nodiscard]] std::vector<DetectionResult>\n    evaluate_batch(std::span<const Signal> signals);",
    "    [[nodiscard]] std::vector<DetectionResult>\n    evaluate_batch(std::span<const Signal> signals) noexcept;"
)
content = content.replace(
    "    [[nodiscard]] std::optional<DetectionResult>\n    test_rule(const DetectionRule& rule,\n              const Signal&        signal) const;",
    "    [[nodiscard]] std::optional<DetectionResult>\n    test_rule(const DetectionRule& rule,\n              const Signal&        signal) const noexcept;"
)
content = content.replace(
    "    [[nodiscard]] std::optional<DetectionRule>\n    get_rule(RuleId rule_id) const;",
    "    [[nodiscard]] std::optional<DetectionRule>\n    get_rule(RuleId rule_id) const noexcept;"
)

# Update pipeline documentation to numbered contract
content = content.replace(
"""// ── Evaluation pipeline (in order) ───────────────────────────────────────
//
//   1. Whitelist check      → suppress if IP matches whitelist
//   2. IP suppression       → suppress if IP is temporarily suppressed
//   3. Rule suppression     → suppress if rule ID is suppressed
//   4. FP score filter      → suppress if fp_score >= cfg.fp_threshold
//   5. Condition evaluation → structured conditions OR legacy pattern
//   6. Threshold check      → fire only after N matches in window
//   7. Evidence collection  → which fields triggered the match
//   8. Confidence scoring   → weighted sum of matched conditions
//   9. Severity score       → severity enum mapped to 0.0-10.0 float""",
"""// ── Evaluation pipeline contract (deterministic, in order) ──────────────
//
//   STEP 1: Whitelist check
//     → if signal.net.src matches whitelist → return empty, no alerts
//   STEP 2: IP suppression check
//     → if signal.net.src is suppressed (TTL not expired) → return empty
//   STEP 3: For each rule (in insertion order):
//     STEP 3a: Rule enabled check → skip if !rule.enabled
//     STEP 3b: FP filter → skip if rule.fp_score >= cfg.fp_threshold
//     STEP 3c: Rule suppression → skip if rule suppressed (TTL)
//     STEP 3d: Condition evaluation
//               → structured conditions (AND semantics) if non-empty
//               → legacy pattern fallback otherwise
//     STEP 3e: Threshold check → skip if count < rule.threshold in window
//     STEP 3f: Evidence collection → populate result.evidence
//     STEP 3g: Confidence scoring
//               → weighted sum of matched condition weights / total weights
//               → legacy rules: 0.80f fixed
//     STEP 3h: Severity score → severity_score(rule.severity) → 0.0-10.0
//     STEP 3i: timestamp_us = now_us()
//     STEP 3j: Kill chain → KillChainMapper::map(signal)
//   STEP 4: Return matched results vector
//
// ── Performance targets (v0.1 baseline) ──────────────────────────────────
//
//   Target throughput:  10k EPS (single thread, 1000 rules)
//   Max latency:        < 1ms per signal (single thread)
//   Memory ceiling:     < 100MB for 100k rules loaded
//   v0.2 target:        100k EPS with RuleIndex + CompiledRule""")

# Update thread safety section
content = content.replace(
"""// ── Thread-safety contract ───────────────────────────────────────────────
//
//   All public member functions are thread-safe.
//   Multiple evaluate() calls may run concurrently.
//   Rule modifications may occur concurrently with evaluation.
//   Callers observe a consistent snapshot of the active rule set.""",
"""// ── Thread-safety contract (v0.1: mutex per engine) ──────────────────────
//
//   Model: std::mutex guards all state. Single lock per operation.
//   v0.2 target: lock-free reads + locked writes (RW lock model).
//
//   Safe concurrently:
//     evaluate(), evaluate_batch() — multiple threads OK
//     stats(), rule_count(), alert_count() — read-only, safe
//   Serialized (one at a time):
//     add_rule(), remove_rule(), set_*() — write operations
//     suppress_*(), whitelist_*() — write operations
//     reset(), clear() — full state writes""")

p.write_text(content)
print("OK -- engine.hpp Pass 2 complete")
print("     + noexcept restored on hot path")
print("     + 9-step pipeline contract documented")
print("     + EPS targets documented")
print("     + thread safety model documented")

# Update engine.cpp — restore noexcept on hot path definitions
p = pathlib.Path("src/engine.cpp")
content = p.read_text()

content = content.replace(
    "DetectionEngine::evaluate(const Signal& signal) {",
    "DetectionEngine::evaluate(const Signal& signal) noexcept {"
)
content = content.replace(
    "DetectionEngine::evaluate_batch(\n    std::span<const Signal> signals) {",
    "DetectionEngine::evaluate_batch(\n    std::span<const Signal> signals) noexcept {"
)
content = content.replace(
    "DetectionEngine::test_rule(\n    const DetectionRule& rule,\n    const Signal& signal) const {",
    "DetectionEngine::test_rule(\n    const DetectionRule& rule,\n    const Signal& signal) const noexcept {"
)
content = content.replace(
    "DetectionEngine::get_rule(RuleId rule_id) const {",
    "DetectionEngine::get_rule(RuleId rule_id) const noexcept {"
)

# Update field access for new Signal structure
# category is now an enum — update get_field to handle it
content = content.replace(
"""        if (field == "description")  return s.description;
        if (field == "category")     return s.category;
        if (field == "detection_rule") return s.detection_rule;
        if (field == "raw")          return s.raw;
        if (field == "net.src")      return s.net.src.value;
        if (field == "net.dst")      return s.net.dst.value;
        if (field == "net.protocol") return s.net.protocol;
        if (field == "proc.name")    return s.proc.process_name;
        if (field == "proc.cmdline") return s.proc.cmdline;
        if (field == "proc.file")    return s.proc.file_path;
        if (field == "proc.user")    return s.proc.username;
        if (field == "mitre_id")     return s.mitre_id.value;
        return {};""",
"""        if (field == "description")  return s.description;
        if (field == "category")     return s.category_str;
        if (field == "detection_rule") return s.detection_rule;
        if (field == "raw")          return s.raw;
        if (field == "net.src")      return s.net.src.value;
        if (field == "net.dst")      return s.net.dst.value;
        if (field == "net.protocol") return s.net.protocol_str;
        if (field == "proc.name")    return s.proc.process_name;
        if (field == "proc.cmdline") return s.proc.cmdline;
        if (field == "proc.file")    return s.proc.file_path;
        if (field == "proc.user")    return s.proc.username;
        if (field == "mitre_id")     return s.mitre_id.value;
        return {};""")

# Update match_signature legacy path — category is now enum
content = content.replace(
"""        auto has = [&](const std::string& f) {
            return lower(f).find(kw) != std::string::npos;
        };
        return has(sig.description)   ||
               has(sig.category)      ||
               has(sig.detection_rule)||
               has(sig.proc.process_name) ||
               has(sig.proc.file_path);""",
"""        auto has = [&](const std::string& f) {
            return lower(f).find(kw) != std::string::npos;
        };
        return has(sig.description)      ||
               has(sig.category_str)     ||
               has(sig.detection_rule)   ||
               has(sig.proc.process_name)||
               has(sig.proc.file_path);""")

# Update whitelist/suppression to use net.src
# (already using net.src.value — no change needed)

# Add reserve() in evaluate hot loop
content = content.replace(
"""    std::vector<DetectionResult> results;
    if (!impl_) return results;
    std::lock_guard lock(impl_->mtx);
    ++impl_->signals_processed;""",
"""    std::vector<DetectionResult> results;
    if (!impl_) return results;
    std::lock_guard lock(impl_->mtx);
    ++impl_->signals_processed;
    results.reserve(8); // preallocate — typical match count""")

p.write_text(content)
print("OK -- engine.cpp Pass 2 complete")
print("     + noexcept restored on hot path definitions")
print("     + field access updated for enum Signal")
print("     + reserve(8) in evaluate hot loop")
