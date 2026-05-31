// src/zote_engine.cpp
// ZOTE — zenithcpp Open Source Threat Engine
// ISO C++23 compliant — zero external dependencies
// Apache 2.0 License — https://github.com/zenithcpp/zote

#include <zote/zote_engine.hpp>
#include <chrono>
#include <memory>
#include <vector>

namespace zote {

// ─── Impl ────────────────────────────────────────────────────────────────
struct ZoteEngine::Impl {
    DetectionEngine   det;
    CorrelationEngine corr;
    ConfidenceModel   conf_model = DEFAULT_CONFIDENCE_MODEL;

    explicit Impl(DetectionEngineConfig  det_cfg,
                  CorrelationConfig      corr_cfg) noexcept
        : det(std::move(det_cfg))
        , corr(std::move(corr_cfg)) {}
};

// ─── Construction ────────────────────────────────────────────────────────

ZoteEngine::ZoteEngine() noexcept
    : impl_(std::make_unique<Impl>(
        DetectionEngineConfig{}, CorrelationConfig{})) {}

ZoteEngine::ZoteEngine(
    DetectionEngineConfig det_cfg,
    CorrelationConfig     corr_cfg) noexcept
    : impl_(std::make_unique<Impl>(
        std::move(det_cfg), std::move(corr_cfg))) {}

ZoteEngine::~ZoteEngine() = default;
ZoteEngine::ZoteEngine(ZoteEngine&&) noexcept = default;
ZoteEngine& ZoteEngine::operator=(ZoteEngine&&) noexcept = default;

// ─── Rule management ─────────────────────────────────────────────────────

void ZoteEngine::add_rule(
    const DetectionRule& rule) noexcept {
    if (impl_) impl_->det.add_rule(rule);
}

void ZoteEngine::add_rules(
    std::span<const DetectionRule> rules) noexcept {
    if (impl_) impl_->det.add_rules(rules);
}

void ZoteEngine::remove_rule(RuleId rule_id) noexcept {
    if (impl_) impl_->det.remove_rule(rule_id);
}

void ZoteEngine::set_rule_enabled(
    RuleId rule_id, bool enabled) noexcept {
    if (impl_) impl_->det.set_rule_enabled(rule_id, enabled);
}

void ZoteEngine::whitelist_add(std::string_view ip) noexcept {
    if (impl_) impl_->det.whitelist_add(ip);
}

void ZoteEngine::whitelist_remove(std::string_view ip) noexcept {
    if (impl_) impl_->det.whitelist_remove(ip);
}

void ZoteEngine::suppress_ip(
    std::string_view     ip,
    std::chrono::seconds ttl) noexcept {
    if (impl_) impl_->det.suppress_ip(ip, ttl);
}

// ─── Signal processing ───────────────────────────────────────────────────

ThreatAssessment ZoteEngine::process(
    const Signal& signal) noexcept {
    ThreatAssessment assessment;
    if (!impl_) return assessment;

    // Step 1: Detection engine
    auto det_results = impl_->det.evaluate(signal);

    // Step 2: Kill chain assessment
    auto kc = KillChainMapper::assess(signal);
    assessment.kill_chain.furthest_stage = kc.stage;
    if (kc.stage != KillChainStage::Unknown)
        assessment.kill_chain.observed_stages.push_back(kc.stage);

    // Step 3: Build risk from detection results
    float det_conf   = 0.0f;
    float risk_score = 0.0f;
    for (const auto& r : det_results) {
        if (r.confidence > det_conf) det_conf = r.confidence;
        if (r.severity_score > risk_score)
            risk_score = r.severity_score;
        assessment.risk.evidence.push_back(r);
    }

    // Step 4: Normalize confidence
    float combined = impl_->conf_model.apply(
        det_conf, 0.0f, kc.confidence);
    assessment.risk.score      = risk_score;
    assessment.risk.confidence = combined;

    // Step 5: Correlation ingestion
    if (!det_results.empty()) {
        CorrelatedAlert ca;
        ca.src_ip      = signal.net.src;
        ca.dst_ip      = signal.net.dst;
        ca.mitre_id    = det_results[0].mitre_id;
        ca.kill_chain  = kc.stage;
        ca.risk_score  = risk_score;
        ca.severity    = det_results[0].severity;
        ca.description = signal.description;
        impl_->corr.ingest(ca);
    }

    // Step 6: Attribution
    if (!signal.net.src.empty()) {
        auto* camp = impl_->corr.campaign_for_ip(
            signal.net.src.value);
        if (camp) {
            assessment.attribution =
                impl_->corr.attribute_actor(camp->id);
            assessment.timeline    = camp->timeline;
            // Kill chain progress
            assessment.kill_chain.observed_stages =
                camp->stages;
            if (!camp->stages.empty()) {
                assessment.kill_chain.furthest_stage =
                    camp->stages.back();
                assessment.kill_chain.completion =
                    static_cast<float>(camp->stages.size())
                    / 7.0f; // 7 kill chain stages
            }
        }
    }

    // Step 7: Recommendations
    if (risk_score >= 8.0f)
        assessment.recommendations.push_back(
            "Isolate host immediately");
    if (kc.stage == KillChainStage::CommandControl)
        assessment.recommendations.push_back(
            "Block outbound C2 communication");
    if (kc.stage == KillChainStage::ActionsOnObj)
        assessment.recommendations.push_back(
            "Activate incident response plan");

    return assessment;
}

void ZoteEngine::process(
    const Signal&  signal,
    AlertCallback  on_detection) noexcept {
    if (!impl_) return;
    impl_->det.evaluate(signal, on_detection);
    // Also run full pipeline for correlation
    auto kc = KillChainMapper::assess(signal);
    CorrelatedAlert ca;
    ca.src_ip      = signal.net.src;
    ca.kill_chain  = kc.stage;
    ca.risk_score  = 5.0f;
    ca.description = signal.description;
    impl_->corr.ingest(ca);
}

std::vector<ThreatAssessment>
ZoteEngine::process_batch(
    std::span<const Signal> signals) noexcept {
    std::vector<ThreatAssessment> results;
    results.reserve(signals.size());
    for (const auto& sig : signals)
        results.push_back(process(sig));
    return results;
}

// ─── Campaign access ─────────────────────────────────────────────────────

std::vector<Campaign>
ZoteEngine::campaigns_snapshot() const noexcept {
    if (!impl_) return {};
    return impl_->corr.campaigns_snapshot();
}

const Campaign* ZoteEngine::campaign_for_ip(
    std::string_view ip) const noexcept {
    if (!impl_) return nullptr;
    return impl_->corr.campaign_for_ip(ip);
}

Attribution ZoteEngine::attribute_actor(
    CampaignId campaign_id) const noexcept {
    if (!impl_) return {};
    return impl_->corr.attribute_actor(campaign_id);
}

std::vector<std::string>
ZoteEngine::countermeasures_for(
    const TechniqueId& tid) {
    return MitreDb::d3fend_for(tid.value);
}

// ─── Stats ───────────────────────────────────────────────────────────────

EngineStats ZoteEngine::detection_stats() const noexcept {
    if (!impl_) return {};
    return impl_->det.stats();
}

std::size_t ZoteEngine::rule_count() const noexcept {
    if (!impl_) return 0;
    return impl_->det.rule_count();
}

std::size_t ZoteEngine::campaign_count() const noexcept {
    if (!impl_) return 0;
    return impl_->corr.campaigns_snapshot().size();
}

void ZoteEngine::reset() noexcept {
    if (!impl_) return;
    impl_->det.reset();
    impl_->corr.reset();
}

DetectionEngine& ZoteEngine::detection_engine() noexcept {
    return impl_->det;
}

CorrelationEngine& ZoteEngine::correlation_engine() noexcept {
    return impl_->corr;
}

} // namespace zote
