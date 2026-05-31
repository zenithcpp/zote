#pragma once
// include/zote/zote_engine.hpp
// ZOTE — zenithcpp Open Source Threat Engine
// ISO C++23 compliant — zero external dependencies
// Apache 2.0 License — https://github.com/zenithcpp/zote
//
// ZoteEngine — unified product interface.
//
// This is the primary entry point for ZOTE.
// Wires DetectionEngine + KillChainMapper +
// CorrelationEngine into a single deterministic pipeline:
//
//   Signal
//     ↓  Step 1: DetectionEngine::evaluate()
//   DetectionResult{confidence, evidence, kill_chain}
//     ↓  Step 2: KillChainMapper::assess()
//   KillChainAssessment{stage, candidates, reasons}
//     ↓  Step 3: ConfidenceNormalizer::combine()
//   combined_confidence
//     ↓  Step 4: CorrelationEngine::ingest()
//   Campaign{timeline, attribution, UEBA}
//     ↓  Step 5: ThreatAssessment assembly
//   ThreatAssessment{risk, attribution, kill_chain,
//                    coverage, timeline, recommendations}
//
// ── Basic usage ──────────────────────────────────────────────────────────
//
//   zote::ZoteEngine engine;
//
//   zote::DetectionRule rule;
//   rule.id = zote::RuleId{1};
//   rule.pattern = "ransomware";
//   rule.severity = zote::Severity::Critical;
//   engine.add_rule(rule);
//
//   zote::Signal sig;
//   sig.net.src = zote::IpAddress{"1.2.3.4"};
//   sig.description = "ransomware encrypting files";
//
//   auto assessment = engine.process(sig);
//   // assessment.risk.score — overall risk 0-10
//   // assessment.attribution.actor — attributed threat actor
//   // assessment.kill_chain.stage — kill chain stage
//
// ── Thread-safety ────────────────────────────────────────────────────────
//
//   process() is thread-safe — multiple threads may call concurrently.
//   add_rule() / configure() serialize with process().

#include <zote/engine.hpp>
#include <zote/killchain.hpp>
#include <zote/correlation.hpp>
#include <zote/mitre.hpp>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace zote {

// ─── ZoteEngine ──────────────────────────────────────────────────────────
class ZoteEngine {
public:
    // Construct with default configuration.
    ZoteEngine() noexcept;

    // Construct with custom engine configs.
    explicit ZoteEngine(DetectionEngineConfig  det_cfg,
                        CorrelationConfig      corr_cfg = {}) noexcept;

    ~ZoteEngine();

    ZoteEngine(const ZoteEngine&)            = delete;
    ZoteEngine& operator=(const ZoteEngine&) = delete;

    ZoteEngine(ZoteEngine&&) noexcept;
    ZoteEngine& operator=(ZoteEngine&&) noexcept;

    // ── Rule management ───────────────────────────────────────────────

    void add_rule(const DetectionRule& rule) noexcept;
    void add_rules(std::span<const DetectionRule> rules) noexcept;
    void remove_rule(RuleId rule_id) noexcept;
    void set_rule_enabled(RuleId rule_id, bool enabled) noexcept;
    void whitelist_add(std::string_view ip) noexcept;
    void whitelist_remove(std::string_view ip) noexcept;
    void suppress_ip(std::string_view ip,
                     std::chrono::seconds ttl) noexcept;

    // ── Signal processing ─────────────────────────────────────────────

    // Process a single signal through the full pipeline.
    // Returns ThreatAssessment — unified view of all engine outputs.
    // Thread-safe — multiple threads may call concurrently.
    [[nodiscard]] ThreatAssessment
    process(const Signal& signal) noexcept;

    // Process with callback — fires for each matched detection.
    // Callback called before correlation for low-latency alerting.
    void process(const Signal&  signal,
                 AlertCallback  on_detection) noexcept;

    // Batch processing.
    [[nodiscard]] std::vector<ThreatAssessment>
    process_batch(std::span<const Signal> signals) noexcept;

    // ── Campaign access ───────────────────────────────────────────────

    // Safe snapshot of all campaigns.
    [[nodiscard]] std::vector<Campaign>
    campaigns_snapshot() const noexcept;

    // Read-only campaign view for an IP.
    [[nodiscard]] const Campaign*
    campaign_for_ip(std::string_view ip) const noexcept;

    // ── Intelligence queries ──────────────────────────────────────────

    // Attribute a campaign to a known threat actor.
    [[nodiscard]] Attribution
    attribute_actor(CampaignId campaign_id) const noexcept;

    // D3FEND countermeasures for a technique.
    [[nodiscard]] static std::vector<std::string>
    countermeasures_for(const TechniqueId& tid);

    // ── Stats and observability ───────────────────────────────────────

    [[nodiscard]] EngineStats   detection_stats() const noexcept;
    [[nodiscard]] std::size_t   rule_count()      const noexcept;
    [[nodiscard]] std::size_t   campaign_count()  const noexcept;

    // Reset all runtime state. Rules remain loaded.
    void reset() noexcept;

    // ── Direct engine access ──────────────────────────────────────────
    // For advanced use cases requiring direct engine access.

    [[nodiscard]] DetectionEngine&   detection_engine() noexcept;
    [[nodiscard]] CorrelationEngine& correlation_engine() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace zote
