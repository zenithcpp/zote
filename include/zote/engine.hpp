#pragma once
// include/zote/engine.hpp
// ZOTE — zenithcpp Open Source Threat Engine
// ISO C++23 compliant — zero external dependencies
// Apache 2.0 License — https://github.com/zenithcpp/zote
//
// Detection Runtime Kernel (DRK) — evaluates signals against
// detection rules with evidence-based confidence scoring.
//
// ── Evaluation pipeline contract (deterministic, in order) ──────────────
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
//   v0.2 target:        100k EPS with RuleIndex + CompiledRule
//
// ── Confidence calibration model ─────────────────────────────────────────
//
//   Confidence is deterministic: same rule + same signal = same value.
//   For structured condition rules:
//     confidence = sum(matched_condition.weight) / sum(all_condition.weight)
//   For legacy pattern rules (single pattern string):
//     confidence = 0.80f (fixed — upgrade to conditions for tuning)
//   For YARA hex rules:
//     confidence = 0.95f (binary match — high confidence)
//   For Sigma/Suricata reference rules:
//     confidence = 0.90f (reference match — high confidence)
//   For threshold rules:
//     confidence = 0.85f (count exceeded — high confidence)
//
// ── Thread-safety contract (v0.1: mutex per engine) ──────────────────────
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
//     reset(), clear() — full state writes
//
// ── Suppression model ────────────────────────────────────────────────────
//
//   IP suppression:   exact string match only (v0.1).
//                     CIDR expansion planned for v0.2.
//   Rule suppression: by RuleId, expires after TTL.
//   Whitelist:        permanent, exact string match.
//   Priority:         whitelist > IP suppression > rule suppression > FP.
//   Bounds:           max_suppressed in DetectionEngineConfig.
//                     Oldest entries evicted when limit reached.
//
// ── v0.1 limitations (documented upgrade path) ───────────────────────────
//
//   Rules are interpreted at evaluation time O(n) per signal.
//   v0.2: CompiledRule + RuleIndex for O(1) field-indexed dispatch.
//   v0.2: SigmaParser and SuricataParser as separate classes.
//   v0.2: Sliding window engine for time-series detection.
//   v1.0: Parallel batch ingestion pipeline.
//
#include <zote/types.hpp>
#include <chrono>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace zote {

class DetectionEngine {
public:
    // Config applied at construction.
    // Use DetectionEngineConfig{} for all defaults.
    explicit DetectionEngine(
        DetectionEngineConfig cfg = {}) noexcept;

    ~DetectionEngine();

    // Not copyable — use move semantics or shared_ptr.
    DetectionEngine(const DetectionEngine&)            = delete;
    DetectionEngine& operator=(const DetectionEngine&) = delete;

    DetectionEngine(DetectionEngine&&) noexcept;
    DetectionEngine& operator=(DetectionEngine&&) noexcept;

    // ── Rule management ───────────────────────────────────────────────

    // Add or replace a rule (replaces if ID already exists).
    void add_rule(const DetectionRule& rule) noexcept;

    // Add multiple rules in a single lock acquisition.
    // Preferred over repeated add_rule() for bulk loading.
    void add_rules(std::span<const DetectionRule> rules) noexcept;

    // Remove rule by ID. No-op if not found.
    void remove_rule(RuleId rule_id) noexcept;

    // Enable or disable a rule without removing it.
    void set_rule_enabled(RuleId rule_id, bool enabled) noexcept;

    // Set false positive score (0.0-1.0).
    // Rule suppressed when fp_score >= cfg.fp_threshold.
    void set_fp_score(RuleId rule_id, float score) noexcept;

    // Set count/window threshold for a rule.
    // Rule fires only after count matches within window_sec.
    void set_threshold(RuleId        rule_id,
                       std::uint32_t count,
                       std::uint32_t window_sec) noexcept;

    // ── Rule queries ──────────────────────────────────────────────────

    [[nodiscard]] bool
    has_rule(RuleId rule_id) const noexcept;

    [[nodiscard]] std::optional<DetectionRule>
    get_rule(RuleId rule_id) const noexcept;

    // ── Suppression ───────────────────────────────────────────────────

    // Suppress all alerts from an IP for the given duration.
    // Note: exact string match only in v0.1. CIDR in v0.2.
    // Evicts oldest entry if max_suppressed limit reached.
    void suppress_ip(std::string_view     ip,
                     std::chrono::seconds ttl) noexcept;

    // Suppress a specific rule for the given duration.
    void suppress_rule(RuleId               rule_id,
                       std::chrono::seconds ttl) noexcept;

    // Add IP or CIDR string to permanent whitelist.
    // Whitelist takes priority over all suppression.
    void whitelist_add(std::string_view ip_or_cidr) noexcept;

    // Remove from whitelist.
    void whitelist_remove(std::string_view ip_or_cidr) noexcept;

    // Check if IP matches whitelist.
    [[nodiscard]] bool
    is_whitelisted(std::string_view ip) const noexcept;

    // ── Evaluation ────────────────────────────────────────────────────

    // Vector API — usability-oriented.
    // Returns only matched results.
    // Allocates result vector on heap — use callback API for
    // high-throughput streaming pipelines.
    [[nodiscard]] std::vector<DetectionResult>
    evaluate(const Signal& signal) noexcept;

    // Callback API — streaming-oriented, zero heap allocation.
    // Calls cb for each matched result immediately.
    // Preferred for high-throughput SOC pipelines (>100k EPS).
    void evaluate(const Signal&  signal,
                  AlertCallback  cb) noexcept;

    // Batch evaluation — evaluates multiple signals.
    // Returns all matched results across all signals.
    [[nodiscard]] std::vector<DetectionResult>
    evaluate_batch(std::span<const Signal> signals) noexcept;

    // Batch evaluation with callback — streaming batch.
    void evaluate_batch(std::span<const Signal> signals,
                        AlertCallback           cb) noexcept;

    // Test a single rule — no counters incremented, no callbacks.
    // Returns nullopt if rule does not match signal.
    // Confidence and evidence ARE populated on match.
    [[nodiscard]] std::optional<DetectionResult>
    test_rule(const DetectionRule& rule,
              const Signal&        signal) const noexcept;

    // ── Rule loading ──────────────────────────────────────────────────
    //
    // Note: These functions couple loading to the engine.
    // v0.2 will introduce SigmaParser and SuricataParser
    // as separate classes for cleaner architecture.
    // These convenience functions will remain as wrappers.

    // Load Suricata .rules file.
    // Returns count of rules loaded.
    // Does not throw — returns 0 on file open failure.
    [[nodiscard]] std::size_t
    load_suricata_rules(const std::string& path);

    // Load directory of Sigma .yml files.
    // Returns count of rules loaded.
    // Does not throw — returns 0 on directory open failure.
    [[nodiscard]] std::size_t
    load_sigma_rules(const std::string& directory);

    // Add a hex byte pattern rule (YARA-like).
    // Pattern format: "4D 5A 90 00" (space-separated hex bytes).
    // Matches against signal.raw field only.
    // Not full YARA language — hex byte matching only in v0.1.
    void add_yara_rule(const std::string& name,
                       const std::string& hex_pattern,
                       Severity           severity) noexcept;

    // ── Stats and observability ───────────────────────────────────────

    [[nodiscard]] std::size_t   rule_count()  const noexcept;
    [[nodiscard]] std::uint64_t alert_count() const noexcept;
    [[nodiscard]] EngineStats   stats()       const noexcept;

    // Reset runtime state (counters, suppression, thresholds).
    // Rules remain loaded. Call before replaying events.
    void reset() noexcept;

    // Clear all rules and runtime state.
    void clear() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace zote
