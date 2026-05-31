#pragma once
// include/zote/correlation.hpp
// ZOTE — zenithcpp Open Source Threat Engine
// ISO C++23 compliant — zero external dependencies
// Apache 2.0 License — https://github.com/zenithcpp/zote
//
// Correlation engine — groups alerts into campaigns,
// tracks kill chain progression, builds UEBA profiles,
// and attributes threat actors.
//
// Thread-safety contract:
//   ingest() is thread-safe — multiple threads may ingest concurrently.
//   campaigns() and ueba_profile() are safe to call during ingestion.
//   campaign_for_ip() returns a raw pointer — valid until next reset().
//   Do not hold the pointer across ingest() calls from other threads.
//
// Campaign grouping: currently groups by source IP.
//   Same actor using different IPs creates separate campaigns.
//   Campaign merging planned for v0.2.

#include <zote/types.hpp>
#include <optional>
#include <zote/killchain.hpp>
#include <memory>
#include <string_view>
#include <vector>

namespace zote {

// ─── Campaign ────────────────────────────────────────────────────────────
struct Campaign {
    CampaignId                  id;
    std::string                 name;
    CampaignState               state         = CampaignState::Active;
    float                       risk_score    = 0.0f;  // 0-10
    std::uint64_t               first_seen_us = 0;
    std::uint64_t               last_seen_us  = 0;
    std::uint32_t               alert_count   = 0;
    std::vector<IpAddress>      src_ips;
    std::vector<TechniqueId>    mitre_ids;
    std::vector<KillChainStage> stages;
    std::vector<TimelineEvent>  timeline;     // Full attack timeline
};

// ─── Correlated alert ─────────────────────────────────────────────────────
struct CorrelatedAlert {
    AlertId        id;
    IpAddress      src_ip;
    IpAddress      dst_ip;
    std::string    description;
    TechniqueId    mitre_id;
    std::string    category;
    KillChainStage kill_chain    = KillChainStage::Unknown;
    Severity       severity      = Severity::Medium;
    float          risk_score    = 0.0f;
    std::uint64_t  timestamp_us  = 0;
};

// ─── UEBA profile ─────────────────────────────────────────────────────────
struct UebaProfile {
    IpAddress      ip;
    std::uint32_t  alert_count_24h  = 0;
    std::uint32_t  unique_dst_count  = 0;
    float          anomaly_score     = 0.0f;  // 0-10
    std::uint64_t  last_seen_us      = 0;
    bool           is_anomalous      = false;
};

// ─── Correlation engine ───────────────────────────────────────────────────
class CorrelationEngine {
public:
    explicit CorrelationEngine(
        CorrelationConfig cfg = {}) noexcept;

    ~CorrelationEngine();

    CorrelationEngine(const CorrelationEngine&)            = delete;
    CorrelationEngine& operator=(const CorrelationEngine&) = delete;

    CorrelationEngine(CorrelationEngine&&) noexcept;
    CorrelationEngine& operator=(CorrelationEngine&&) noexcept;

    // Ingest alert — campaign grouping + kill chain + UEBA update.
    void ingest(const CorrelatedAlert& alert) noexcept;

    // All campaigns — safe snapshot copy.
    // Safe to hold across ingest() calls from other threads.
    [[nodiscard]] std::vector<Campaign>
    campaigns_snapshot() const noexcept;

    // Read-only view of campaign for IP.
    // Returns nullptr if not found.
    // Valid only until next ingest() or reset() from ANY thread.
    // For thread-safe access, use campaigns_snapshot() instead.
    [[nodiscard]] const Campaign*
    campaign_for_ip(std::string_view ip) const noexcept;

    // Mutable access to campaign for IP.
    // Returns nullptr if not found.
    // Valid only until next ingest() or reset() from ANY thread.
    // Must not be called concurrently with ingest().
    [[nodiscard]] Campaign*
    campaign_for_ip_mut(std::string_view ip) noexcept;

    // Accumulated risk score for IP (0-10).
    [[nodiscard]] float
    risk_score(std::string_view ip) const noexcept;

    // UEBA profile for IP.
    [[nodiscard]] UebaProfile
    ueba_profile(std::string_view ip) const noexcept;

    // Map alert to kill chain stage with confidence.
    [[nodiscard]] static KillChainAssessment
    map_kill_chain(const CorrelatedAlert& alert) noexcept;

    // Attribute campaign to known threat actor.
    // Returns Attribution with actor, confidence, matched techniques.
    // Returns empty Attribution if campaign not found or no match.
    [[nodiscard]] Attribution
    attribute_actor(CampaignId campaign_id) const noexcept;

    // Submit a KillChainAssessment directly from KCIE.
    // Creates or updates a campaign for src_ip using the assessment.
    // Integration hook: KillChainMapper → CorrelationEngine pipeline.
    // Equivalent to ingesting a CorrelatedAlert with pre-mapped stage.
    void submit(const KillChainAssessment& assessment,
                std::string_view           src_ip,
                float                      risk_score = 5.0f) noexcept;

    // Total alerts ingested.
    [[nodiscard]] std::uint64_t
    alert_count() const noexcept;

    // Reset all state.
    void reset() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace zote
