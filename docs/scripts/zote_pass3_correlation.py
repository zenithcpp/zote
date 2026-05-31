#!/usr/bin/env python3
# zote_pass3_correlation.py
# Run from ~/Desktop/ZOTE/
# Pass 3: correlation — three-function campaign access,
#          IP→CampaignId index, max_ueba_entities

import pathlib

# ── correlation.hpp ───────────────────────────────────────────────────────
p = pathlib.Path("include/zote/correlation.hpp")
content = p.read_text()

# Add max_ueba_entities to CorrelationConfig — done via types.hpp
# Replace campaign access API
content = content.replace(
"""    // All campaigns (copy — safe to hold across ingest calls).
    [[nodiscard]] std::vector<Campaign>
    campaigns() const;

    // Find campaign containing IP.
    // Returns a copy — safe to hold across ingest() calls.
    // Returns nullopt if no campaign found for this IP.
    [[nodiscard]] std::optional<Campaign>
    campaign_for_ip(std::string_view ip) const;""",
"""    // All campaigns — safe snapshot copy.
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
    campaign_for_ip_mut(std::string_view ip) noexcept;""")

# Update attribute_actor noexcept
content = content.replace(
    "    [[nodiscard]] Attribution\n    attribute_actor(CampaignId campaign_id) const;",
    "    [[nodiscard]] Attribution\n    attribute_actor(CampaignId campaign_id) const noexcept;"
)

p.write_text(content)
print("OK -- correlation.hpp: three-function campaign access model")

# ── correlation.cpp ───────────────────────────────────────────────────────
p = pathlib.Path("src/correlation.cpp")
content = p.read_text()

# Add IP→CampaignId index to Impl
content = content.replace(
"""struct CorrelationEngine::Impl {
    std::vector<CorrelatedAlert>                    alerts;
    std::vector<Campaign>                           campaigns;
    std::unordered_map<std::string, UebaProfile>   ueba;
    std::atomic<std::uint64_t>                      alert_count{0};
    std::uint64_t                                   next_campaign_id{1};
    mutable std::mutex                              mtx;
    CorrelationConfig                               cfg;""",
"""struct CorrelationEngine::Impl {
    std::vector<CorrelatedAlert>                          alerts;
    std::vector<Campaign>                                 campaigns;
    std::unordered_map<std::string, UebaProfile>          ueba;
    std::unordered_map<std::string, std::uint64_t>        ip_campaign_idx; // O(1) IP lookup
    std::atomic<std::uint64_t>                            alert_count{0};
    std::uint64_t                                         next_campaign_id{1};
    mutable std::mutex                                    mtx;
    CorrelationConfig                                     cfg;""")

# Update update_campaign to maintain the IP→CampaignId index
content = content.replace(
"""    void update_campaign(const CorrelatedAlert& a) noexcept {
        for (auto& c : campaigns) {
            for (const auto& ip : c.src_ips) {
                if (ip.value != a.src_ip.value) continue;
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
                // Add timeline event
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
        campaigns.push_back(std::move(c));
    }""",
"""    void update_campaign(const CorrelatedAlert& a) noexcept {
        // O(1) lookup via IP→CampaignId index
        auto it = ip_campaign_idx.find(a.src_ip.value);
        if (it != ip_campaign_idx.end()) {
            // Find campaign by ID
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
        // Register in index
        ip_campaign_idx[a.src_ip.value] = c.id.value;
        campaigns.push_back(std::move(c));
    }""")

# Replace campaigns() with campaigns_snapshot()
content = content.replace(
"""std::vector<Campaign>
CorrelationEngine::campaigns() const noexcept {
    if (!impl_) return {};
    std::lock_guard lock(impl_->mtx);
    return impl_->campaigns;
}""",
"""std::vector<Campaign>
CorrelationEngine::campaigns_snapshot() const noexcept {
    if (!impl_) return {};
    std::lock_guard lock(impl_->mtx);
    return impl_->campaigns;
}""")

# Replace campaign_for_ip with three-function model
content = content.replace(
"""std::optional<Campaign> CorrelationEngine::campaign_for_ip(
    std::string_view ip) const noexcept {
    if (!impl_) return std::nullopt;
    std::lock_guard lock(impl_->mtx);
    for (const auto& c : impl_->campaigns)
        for (const auto& cip : c.src_ips)
            if (cip.value == ip) return c;
    return std::nullopt;
}""",
"""const Campaign* CorrelationEngine::campaign_for_ip(
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
}""")

# Update attribute_actor noexcept
content = content.replace(
    "Attribution CorrelationEngine::attribute_actor(\n    CampaignId campaign_id) const {",
    "Attribution CorrelationEngine::attribute_actor(\n    CampaignId campaign_id) const noexcept {"
)

# Update reset() to clear index
content = content.replace(
"""    impl_->alerts.clear();
    impl_->campaigns.clear();
    impl_->ueba.clear();
    impl_->alert_count.store(0);
    impl_->next_campaign_id = 1;""",
"""    impl_->alerts.clear();
    impl_->campaigns.clear();
    impl_->ueba.clear();
    impl_->ip_campaign_idx.clear();
    impl_->alert_count.store(0);
    impl_->next_campaign_id = 1;""")

p.write_text(content)
print("OK -- correlation.cpp: three-function model + O(1) IP index")
print("     + campaigns_snapshot()")
print("     + campaign_for_ip() read-only O(1)")
print("     + campaign_for_ip_mut() mutable O(1)")
print("     + ip_campaign_idx unordered_map")
print("     + reset() clears index")

# ── Add max_ueba_entities to CorrelationConfig in types.hpp ──────────────
p = pathlib.Path("include/zote/types.hpp")
content = p.read_text()
content = content.replace(
"""struct CorrelationConfig {
    std::uint32_t max_campaigns      = 10000;
    std::uint32_t max_alerts         = 100000;
    std::uint32_t retention_sec      = 604800; // 7 days
    std::uint32_t campaign_age_sec   = 86400;  // 1 day dormant threshold
    std::uint32_t ueba_window_sec    = 86400;  // 24h UEBA window
    float         anomaly_threshold  = 5.0f;   // UEBA anomaly score
};""",
"""struct CorrelationConfig {
    std::uint32_t max_campaigns      = 10000;
    std::uint32_t max_alerts         = 100000;
    std::uint32_t max_ueba_entities  = 50000;  // Max IP profiles tracked
    std::uint32_t retention_sec      = 604800; // 7 days
    std::uint32_t campaign_age_sec   = 86400;  // 1 day dormant threshold
    std::uint32_t ueba_window_sec    = 86400;  // 24h UEBA window
    float         anomaly_threshold  = 5.0f;   // UEBA anomaly score
};""")
p.write_text(content)
print("OK -- types.hpp: max_ueba_entities added to CorrelationConfig")
