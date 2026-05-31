// src/correlation.cpp
// ZOTE — zenithcpp Open Source Threat Engine
// ISO C++23 compliant — zero external dependencies
// Apache 2.0 License — https://github.com/zenithcpp/zote

#include <zote/correlation.hpp>
#include <optional>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace zote {

static std::uint64_t now_us() noexcept {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now()
                .time_since_epoch()).count());
}

// ─── Actor attribution table ─────────────────────────────────────────────
struct ActorSig {
    const char* mitre_id;
    const char* actor;
};
static constexpr ActorSig ACTOR_SIGS[] = {
    {"T1566", "APT28"},
    {"T1059", "APT29"},
    {"T1486", "LockBit"},
    {"T1190", "APT41"},
    {"T1003", "Lazarus"},
    {"T1021", "Cobalt"},
    {"T1055", "FIN7"},
    {"T1485", "Sandworm"},
    {"T1490", "WizardSpider"},
    {"T1558", "APT29"},
    {"T1550", "APT28"},
    {"T1071", "Cobalt"},
};
static constexpr std::size_t ACTOR_SIG_COUNT =
    sizeof(ACTOR_SIGS)/sizeof(ACTOR_SIGS[0]);

// ─── Impl ────────────────────────────────────────────────────────────────
struct CorrelationEngine::Impl {
    std::vector<CorrelatedAlert>                          alerts;
    std::vector<Campaign>                                 campaigns;
    std::unordered_map<std::string, UebaProfile>          ueba;
    std::unordered_map<std::string, std::uint64_t>        ip_campaign_idx;
    std::atomic<std::uint64_t>                            alert_count{0};
    std::uint64_t                                         next_campaign_id{1};
    mutable std::mutex                                    mtx;
    CorrelationConfig                                     cfg;

    void update_campaign(const CorrelatedAlert& a) noexcept {
        // O(1) lookup via IP→CampaignId index
        auto it = ip_campaign_idx.find(a.src_ip.value);
        if (it != ip_campaign_idx.end()) {
            for (auto& c : campaigns) {
                if (c.id.value != it->second) continue;
                c.last_seen_us = a.timestamp_us;
                c.alert_count++;
                c.state = CampaignState::Active;
                c.risk_score = std::min(10.0f,
                    c.risk_score + a.risk_score * 0.1f);
                if (!a.mitre_id.empty()) {
                    bool found = false;
                    for (const auto& m : c.mitre_ids)
                        if (m.value == a.mitre_id.value)
                            { found = true; break; }
                    if (!found) c.mitre_ids.push_back(a.mitre_id);
                }
                bool sfound = false;
                for (const auto& s : c.stages)
                    if (s == a.kill_chain)
                        { sfound = true; break; }
                if (!sfound) c.stages.push_back(a.kill_chain);
                c.timeline.push_back({
                    a.timestamp_us, a.kill_chain,
                    a.mitre_id, a.description,
                    a.src_ip, a.severity
                });
                return;
            }
        }
        // New campaign
        Campaign c;
        c.id             = CampaignId{next_campaign_id++};
        c.name           = "Campaign-" +
                           std::to_string(c.id.value);
        c.first_seen_us  = a.timestamp_us;
        c.last_seen_us   = a.timestamp_us;
        c.risk_score     = a.risk_score;
        c.alert_count    = 1;
        c.state          = CampaignState::Active;
        c.src_ips.push_back(a.src_ip);
        if (!a.mitre_id.empty())
            c.mitre_ids.push_back(a.mitre_id);
        c.stages.push_back(a.kill_chain);
        c.timeline.push_back({
            a.timestamp_us, a.kill_chain,
            a.mitre_id, a.description,
            a.src_ip, a.severity
        });
        ip_campaign_idx[a.src_ip.value] = c.id.value;
        campaigns.push_back(std::move(c));
    }

    void update_ueba(const CorrelatedAlert& a) noexcept {
        auto& p        = ueba[a.src_ip.value];
        p.ip           = a.src_ip;
        p.alert_count_24h++;
        p.last_seen_us = a.timestamp_us;
        if (!a.dst_ip.empty()) p.unique_dst_count++;
        p.anomaly_score = std::min(10.0f,
            static_cast<float>(p.alert_count_24h) * 0.5f);
        p.is_anomalous = p.anomaly_score >=
                         cfg.anomaly_threshold;
    }
};

// ─── Construction ─────────────────────────────────────────────────────────

CorrelationEngine::CorrelationEngine(
    CorrelationConfig cfg) noexcept
    : impl_(std::make_unique<Impl>()) {
    if (impl_) impl_->cfg = std::move(cfg);
}

CorrelationEngine::~CorrelationEngine() = default;

CorrelationEngine::CorrelationEngine(
    CorrelationEngine&&) noexcept = default;
CorrelationEngine& CorrelationEngine::operator=(
    CorrelationEngine&&) noexcept = default;

// ─── Ingest ───────────────────────────────────────────────────────────────

void CorrelationEngine::ingest(
    const CorrelatedAlert& alert) noexcept {
    if (!impl_) return;
    std::lock_guard lock(impl_->mtx);
    auto a = alert;
    if (a.timestamp_us == 0) a.timestamp_us = now_us();
    a.kill_chain = map_kill_chain(a).stage;
    impl_->alerts.push_back(a);
    impl_->update_campaign(a);
    impl_->update_ueba(a);
    ++impl_->alert_count;
}

// ─── Campaign access ──────────────────────────────────────────────────────

std::vector<Campaign>
CorrelationEngine::campaigns_snapshot() const noexcept {
    if (!impl_) return {};
    std::lock_guard lock(impl_->mtx);
    return impl_->campaigns;
}

const Campaign* CorrelationEngine::campaign_for_ip(
    std::string_view ip) const noexcept {
    if (!impl_) return nullptr;
    std::lock_guard lock(impl_->mtx);
    auto it = impl_->ip_campaign_idx.find(std::string(ip));
    if (it == impl_->ip_campaign_idx.end()) return nullptr;
    for (const auto& c : impl_->campaigns)
        if (c.id.value == it->second) return &c;
    return nullptr;
}

Campaign* CorrelationEngine::campaign_for_ip_mut(
    std::string_view ip) noexcept {
    if (!impl_) return nullptr;
    std::lock_guard lock(impl_->mtx);
    auto it = impl_->ip_campaign_idx.find(std::string(ip));
    if (it == impl_->ip_campaign_idx.end()) return nullptr;
    for (auto& c : impl_->campaigns)
        if (c.id.value == it->second) return &c;
    return nullptr;
}

float CorrelationEngine::risk_score(
    std::string_view ip) const noexcept {
    if (!impl_) return 0.0f;
    std::lock_guard lock(impl_->mtx);
    float score = 0.0f;
    for (const auto& a : impl_->alerts)
        if (a.src_ip.value == ip)
            score = std::min(10.0f,
                score + a.risk_score * 0.2f);
    return score;
}

UebaProfile CorrelationEngine::ueba_profile(
    std::string_view ip) const noexcept {
    if (!impl_) return {};
    std::lock_guard lock(impl_->mtx);
    auto it = impl_->ueba.find(std::string(ip));
    if (it == impl_->ueba.end()) return {};
    return it->second;
}

KillChainAssessment CorrelationEngine::map_kill_chain(
    const CorrelatedAlert& alert) noexcept {
    Signal sig;
    sig.description  = alert.description;
    sig.category_str = alert.category;
    sig.mitre_id     = alert.mitre_id;
    return KillChainMapper::assess(sig);
}

Attribution CorrelationEngine::attribute_actor(
    CampaignId campaign_id) const noexcept {
    if (!impl_) return {};
    std::lock_guard lock(impl_->mtx);
    const Campaign* camp = nullptr;
    for (const auto& c : impl_->campaigns)
        if (c.id == campaign_id) { camp = &c; break; }
    if (!camp) return {};
    std::unordered_map<std::string, int> scores;
    std::unordered_map<std::string, std::vector<TechniqueId>> matched;
    for (const auto& mid : camp->mitre_ids)
        for (std::size_t i = 0; i < ACTOR_SIG_COUNT; ++i)
            if (mid.value == ACTOR_SIGS[i].mitre_id) {
                scores[ACTOR_SIGS[i].actor]++;
                matched[ACTOR_SIGS[i].actor].push_back(mid);
            }
    if (scores.empty()) return {};
    std::string best; int best_score = 0;
    for (const auto& [actor, score] : scores)
        if (score > best_score)
            { best_score = score; best = actor; }
    Attribution attr;
    attr.actor      = ActorId{best};
    attr.confidence = std::min(1.0f,
        static_cast<float>(best_score) * 0.2f);
    attr.matched_techniques = matched[best];
    return attr;
}

std::uint64_t CorrelationEngine::alert_count() const noexcept {
    if (!impl_) return 0;
    return impl_->alert_count.load();
}

void CorrelationEngine::submit(
    const KillChainAssessment& assessment,
    std::string_view           src_ip,
    float                      risk_score) noexcept {
    if (!impl_) return;
    CorrelatedAlert a;
    a.src_ip      = IpAddress{std::string(src_ip)};
    a.kill_chain  = assessment.stage;
    a.risk_score  = risk_score;
    a.severity    = Severity::Medium;
    if (!assessment.reasons.empty())
        a.description = assessment.reasons[0].field +
                        ": " + assessment.reasons[0].match;
    else
        a.description = KillChainMapper::stage_name(assessment.stage);
    ingest(a);
}

void CorrelationEngine::reset() noexcept {
    if (!impl_) return;
    std::lock_guard lock(impl_->mtx);
    impl_->alerts.clear();
    impl_->campaigns.clear();
    impl_->ueba.clear();
    impl_->ip_campaign_idx.clear();
    impl_->alert_count.store(0);
    impl_->next_campaign_id = 1;
}

} // namespace zote
