// src/engine.cpp
// ZOTE — zenithcpp Open Source Threat Engine
// ISO C++23 compliant — zero external dependencies
// Apache 2.0 License — https://github.com/zenithcpp/zote

#include <zote/engine.hpp>
#include <zote/killchain.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace zote {

// ─── Time helper ─────────────────────────────────────────────────────────
static std::uint64_t now_us() noexcept {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now()
                .time_since_epoch()).count());
}

// ─── Suppression entry ───────────────────────────────────────────────────
struct SuppressEntry {
    std::uint64_t expires_us;
};

// ─── Threshold counter ───────────────────────────────────────────────────
struct ThresholdCounter {
    std::uint32_t count;
    std::uint64_t window_start_us;
};

// ─── Impl ────────────────────────────────────────────────────────────────
struct DetectionEngine::Impl {
    std::vector<DetectionRule>                              rules;
    std::vector<std::string>                                whitelist;
    std::unordered_map<std::string,  SuppressEntry>         suppressed_ips;
    std::unordered_map<std::uint64_t, SuppressEntry>        suppressed_rules;
    std::unordered_map<std::uint64_t, ThresholdCounter>     thresholds;
    std::atomic<std::uint64_t>                              alert_count{0};
    std::atomic<std::uint64_t>                              signals_processed{0};
    std::atomic<std::uint64_t>                              suppressed_count{0};
    std::uint64_t                                           next_id{1000};
    mutable std::mutex                                      mtx;
    DetectionEngineConfig                                   cfg;

    static std::string lower(const std::string& s) noexcept {
        std::string r = s;
        for (auto& c : r)
            c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
        return r;
    }

    bool ip_suppressed(const std::string& ip) noexcept {
        auto it = suppressed_ips.find(ip);
        if (it == suppressed_ips.end()) return false;
        if (now_us() > it->second.expires_us) {
            suppressed_ips.erase(it); return false;
        }
        return true;
    }

    bool rule_suppressed(std::uint64_t id) noexcept {
        auto it = suppressed_rules.find(id);
        if (it == suppressed_rules.end()) return false;
        if (now_us() > it->second.expires_us) {
            suppressed_rules.erase(it); return false;
        }
        return true;
    }

    bool check_threshold(const DetectionRule& rule) noexcept {
        if (rule.threshold == 0) return true;
        auto& tc = thresholds[rule.id.value];
        std::uint64_t window_us =
            static_cast<std::uint64_t>(rule.window_sec) * 1000000ULL;
        std::uint64_t now = now_us();
        if (now - tc.window_start_us > window_us) {
            tc.count = 0; tc.window_start_us = now;
        }
        ++tc.count;
        return tc.count >= rule.threshold;
    }

    bool in_whitelist(const std::string& ip) const noexcept {
        for (const auto& e : whitelist)
            if (ip == e) return true;
        return false;
    }

    // Extract field value from signal by name
    std::string get_field(const Signal& s,
                          const std::string& field) const noexcept {
        if (field == "description")  return s.description;
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
        return {};
    }

    // Match a single condition against a signal
    bool match_condition(const RuleCondition& cond,
                         const Signal& sig) const noexcept {
        std::string fval = lower(get_field(sig, cond.field));
        std::string pat  = lower(cond.value);
        switch (cond.type) {
        case ConditionType::Contains:
            return fval.find(pat) != std::string::npos;
        case ConditionType::Equals:
            return fval == pat;
        case ConditionType::StartsWith:
            return fval.rfind(pat, 0) == 0;
        case ConditionType::EndsWith:
            return fval.size() >= pat.size() &&
                   fval.compare(fval.size() - pat.size(),
                                pat.size(), pat) == 0;
        case ConditionType::Threshold:
            return true; // handled separately
        }
        return false;
    }

    // Match signature rule — conditions or legacy pattern
    bool match_signature(const DetectionRule& rule,
                         const Signal& sig) const noexcept {
        // Structured conditions take precedence
        if (!rule.conditions.empty()) {
            for (const auto& cond : rule.conditions)
                if (!match_condition(cond, sig)) return false;
            return true;
        }
        // Legacy single pattern — search common fields
        if (rule.pattern.empty()) return false;
        const std::string kw = lower(rule.pattern);
        auto has = [&](const std::string& f) {
            return lower(f).find(kw) != std::string::npos;
        };
        return has(sig.description)      ||
               has(sig.category_str)     ||
               has(sig.detection_rule)   ||
               has(sig.proc.process_name)||
               has(sig.proc.file_path);
    }

    // Build evidence for a matched rule
    std::vector<Evidence> build_evidence(
        const DetectionRule& rule,
        const Signal& sig) const noexcept {
        std::vector<Evidence> ev;
        if (!rule.conditions.empty()) {
            for (const auto& cond : rule.conditions) {
                std::string fval = get_field(sig, cond.field);
                if (!fval.empty())
                    ev.push_back({cond.field, fval, cond.weight});
            }
        } else if (!rule.pattern.empty()) {
            ev.push_back({"pattern", rule.pattern, 1.0f});
        }
        return ev;
    }

    // Compute confidence from conditions
    float compute_confidence(const DetectionRule& rule,
                              const Signal& sig) const noexcept {
        if (rule.conditions.empty()) return 0.8f; // legacy rule default
        float total = 0.0f, matched = 0.0f;
        for (const auto& cond : rule.conditions) {
            total += cond.weight;
            if (match_condition(cond, sig))
                matched += cond.weight;
        }
        return total > 0.0f ? matched / total : 0.0f;
    }

    DetectionResult eval_rule(const DetectionRule& rule,
                              const Signal& sig) noexcept {
        DetectionResult r;
        r.rule_id   = rule.id;
        r.rule_name = rule.name;
        r.mitre_id  = rule.mitre_id.empty()
                      ? sig.mitre_id : rule.mitre_id;
        r.severity  = rule.severity;
        r.kill_chain = KillChainMapper::map(sig);
        r.matched   = false;
        r.confidence = 0.0f;

        switch (rule.type) {
        case RuleType::Signature:
        case RuleType::Behavioral:
            r.matched = match_signature(rule, sig);
            if (r.matched) {
                r.confidence = compute_confidence(rule, sig);
                r.evidence   = build_evidence(rule, sig);
            }
            break;
        case RuleType::Threshold:
            if (match_signature(rule, sig))
                r.matched = check_threshold(rule);
            if (r.matched) r.confidence = 0.85f;
            break;
        case RuleType::Yara:
            if (!rule.hex_pattern.empty() && !sig.raw.empty())
                r.matched = lower(sig.raw).find(
                    lower(rule.hex_pattern)) != std::string::npos;
            if (r.matched) {
                r.confidence = 0.95f;
                r.evidence.push_back({"raw", sig.raw, 1.0f});
            }
            break;
        case RuleType::Sigma:
        case RuleType::Suricata:
            r.matched = !rule.name.empty() &&
                lower(sig.detection_rule).find(
                    lower(rule.name)) != std::string::npos;
            if (r.matched) r.confidence = 0.90f;
            break;
        case RuleType::Whitelist:
            r.matched = false;
            break;
        }

        // Compute severity score using centralized helper
        if (r.matched) {
            r.severity_score = zote::severity_score(r.severity);
            r.timestamp_us   = now_us();
            r.description = rule.description.empty()
                ? rule.name + " matched" : rule.description;
        }
        return r;
    }
};

// ─── Public API ───────────────────────────────────────────────────────────

DetectionEngine::DetectionEngine(
    DetectionEngineConfig cfg) noexcept
    : impl_(std::make_unique<Impl>()) {
    if (impl_) impl_->cfg = std::move(cfg);
}

DetectionEngine::~DetectionEngine() = default;

DetectionEngine::DetectionEngine(DetectionEngine&&) noexcept = default;
DetectionEngine& DetectionEngine::operator=(DetectionEngine&&) noexcept = default;

void DetectionEngine::add_rule(
    const DetectionRule& rule) noexcept {
    if (!impl_) return;
    std::lock_guard lock(impl_->mtx);
    for (auto& r : impl_->rules)
        if (r.id == rule.id) { r = rule; return; }
    impl_->rules.push_back(rule);
}

void DetectionEngine::remove_rule(RuleId rule_id) noexcept {
    if (!impl_) return;
    std::lock_guard lock(impl_->mtx);
    impl_->rules.erase(
        std::remove_if(impl_->rules.begin(), impl_->rules.end(),
            [rule_id](const DetectionRule& r) {
                return r.id == rule_id;
            }),
        impl_->rules.end());
}

void DetectionEngine::set_rule_enabled(
    RuleId rule_id, bool enabled) noexcept {
    if (!impl_) return;
    std::lock_guard lock(impl_->mtx);
    for (auto& r : impl_->rules)
        if (r.id == rule_id) { r.enabled = enabled; return; }
}

void DetectionEngine::set_fp_score(
    RuleId rule_id, float score) noexcept {
    if (!impl_) return;
    std::lock_guard lock(impl_->mtx);
    for (auto& r : impl_->rules)
        if (r.id == rule_id) { r.fp_score = score; return; }
}

void DetectionEngine::set_threshold(
    RuleId rule_id,
    std::uint32_t count,
    std::uint32_t window_sec) noexcept {
    if (!impl_) return;
    std::lock_guard lock(impl_->mtx);
    for (auto& r : impl_->rules)
        if (r.id == rule_id) {
            r.threshold = count;
            r.window_sec = window_sec;
            return;
        }
}

void DetectionEngine::suppress_ip(
    std::string_view ip,
    std::chrono::seconds ttl) noexcept {
    if (!impl_) return;
    std::lock_guard lock(impl_->mtx);
    impl_->suppressed_ips[std::string(ip)] = {
        now_us() + static_cast<std::uint64_t>(ttl.count()) * 1000000ULL
    };
}

void DetectionEngine::suppress_rule(
    RuleId rule_id,
    std::chrono::seconds ttl) noexcept {
    if (!impl_) return;
    std::lock_guard lock(impl_->mtx);
    impl_->suppressed_rules[rule_id.value] = {
        now_us() + static_cast<std::uint64_t>(ttl.count()) * 1000000ULL
    };
}

void DetectionEngine::whitelist_add(
    std::string_view ip_or_cidr) noexcept {
    if (!impl_) return;
    std::lock_guard lock(impl_->mtx);
    std::string s(ip_or_cidr);
    for (const auto& e : impl_->whitelist)
        if (e == s) return;
    impl_->whitelist.push_back(std::move(s));
}

void DetectionEngine::whitelist_remove(
    std::string_view ip_or_cidr) noexcept {
    if (!impl_) return;
    std::lock_guard lock(impl_->mtx);
    std::string s(ip_or_cidr);
    impl_->whitelist.erase(
        std::remove(impl_->whitelist.begin(),
                    impl_->whitelist.end(), s),
        impl_->whitelist.end());
}

bool DetectionEngine::is_whitelisted(
    std::string_view ip) const noexcept {
    if (!impl_) return false;
    std::lock_guard lock(impl_->mtx);
    return impl_->in_whitelist(std::string(ip));
}

bool DetectionEngine::has_rule(RuleId rule_id) const noexcept {
    if (!impl_) return false;
    std::lock_guard lock(impl_->mtx);
    for (const auto& r : impl_->rules)
        if (r.id == rule_id) return true;
    return false;
}

std::optional<DetectionRule>
DetectionEngine::get_rule(RuleId rule_id) const noexcept {
    if (!impl_) return std::nullopt;
    std::lock_guard lock(impl_->mtx);
    for (const auto& r : impl_->rules)
        if (r.id == rule_id) return r;
    return std::nullopt;
}

void DetectionEngine::add_rules(
    std::span<const DetectionRule> rules) noexcept {
    if (!impl_) return;
    std::lock_guard lock(impl_->mtx);
    for (const auto& rule : rules) {
        bool found = false;
        for (auto& r : impl_->rules)
            if (r.id == rule.id) { r = rule; found = true; break; }
        if (!found) impl_->rules.push_back(rule);
    }
}

std::vector<DetectionResult>
DetectionEngine::evaluate(const Signal& signal) noexcept {
    std::vector<DetectionResult> results;
    if (!impl_) return results;
    std::lock_guard lock(impl_->mtx);
    ++impl_->signals_processed;
    results.reserve(8); // preallocate — typical match count

    // Whitelist check
    if (!signal.net.src.empty() &&
        impl_->in_whitelist(signal.net.src.value))
        return results;

    // IP suppression check
    if (!signal.net.src.empty() &&
        impl_->ip_suppressed(signal.net.src.value)) {
        ++impl_->suppressed_count;
        return results;
    }

    for (auto& rule : impl_->rules) {
        if (!rule.enabled) continue;
        if (rule.fp_score >= impl_->cfg.fp_threshold) continue;
        if (impl_->rule_suppressed(rule.id.value)) continue;

        auto result = impl_->eval_rule(rule, signal);
        if (result.matched) {
            ++impl_->alert_count;
            results.push_back(std::move(result));
        }
    }
    return results;
}

void DetectionEngine::evaluate(
    const Signal& signal,
    AlertCallback cb) noexcept {
    if (!impl_ || !cb) return;
    auto results = evaluate(signal);
    for (const auto& r : results)
        cb(r);
}

std::vector<DetectionResult>
DetectionEngine::evaluate_batch(
    std::span<const Signal> signals) noexcept {
    std::vector<DetectionResult> all;
    for (const auto& sig : signals) {
        auto r = evaluate(sig);
        for (auto& res : r)
            all.push_back(std::move(res));
    }
    return all;
}

void DetectionEngine::evaluate_batch(
    std::span<const Signal> signals,
    AlertCallback           cb) noexcept {
    if (!cb) return;
    for (const auto& sig : signals)
        evaluate(sig, cb);
}

std::optional<DetectionResult>
DetectionEngine::test_rule(
    const DetectionRule& rule,
    const Signal& signal) const noexcept {
    if (!impl_) return std::nullopt;
    auto r = impl_->eval_rule(rule, signal);
    if (!r.matched) return std::nullopt;
    return r;
}

std::size_t DetectionEngine::load_suricata_rules(
    const std::string& path) {
    if (!impl_) return 0;
    std::ifstream f(path);
    if (!f.is_open()) return 0;
    std::size_t loaded = 0;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        DetectionRule rule;
        rule.type = RuleType::Suricata;
        auto msg_pos = line.find("msg:\"");
        if (msg_pos != std::string::npos) {
            auto end = line.find('"', msg_pos + 5);
            if (end != std::string::npos)
                rule.name = line.substr(msg_pos + 5, end - msg_pos - 5);
        }
        auto sid_pos = line.find("sid:");
        if (sid_pos != std::string::npos) {
            auto end = line.find(';', sid_pos);
            if (end != std::string::npos) {
                std::string sid_str =
                    line.substr(sid_pos + 4, end - sid_pos - 4);
                try {
                    rule.id = RuleId{static_cast<std::uint64_t>(
                        std::stoul(sid_str))};
                } catch (...) {
                    rule.id = RuleId{impl_->next_id++};
                }
            }
        }
        if (rule.id.value == 0)
            rule.id = RuleId{impl_->next_id++};
        if (!rule.name.empty()) {
            rule.enabled = true;
            std::lock_guard lock(impl_->mtx);
            impl_->rules.push_back(rule);
            ++loaded;
        }
    }
    return loaded;
}

std::size_t DetectionEngine::load_sigma_rules(
    const std::string& directory) {
    if (!impl_) return 0;
    std::size_t loaded = 0;
    try {
        for (const auto& entry :
             std::filesystem::directory_iterator(directory)) {
            if (entry.path().extension() != ".yml") continue;
            std::ifstream f(entry.path());
            if (!f.is_open()) continue;
            DetectionRule rule;
            rule.type = RuleType::Sigma;
            rule.id   = RuleId{impl_->next_id++};
            std::string line;
            while (std::getline(f, line)) {
                if (line.rfind("title:", 0) == 0)
                    rule.name = line.substr(7);
                if (line.rfind("description:", 0) == 0)
                    rule.description = line.substr(13);
                if (line.find("detection:") != std::string::npos)
                    rule.pattern = entry.path().stem().string();
            }
            if (!rule.name.empty()) {
                rule.enabled = true;
                std::lock_guard lock(impl_->mtx);
                impl_->rules.push_back(rule);
                ++loaded;
            }
        }
    } catch (...) {}
    return loaded;
}

void DetectionEngine::add_yara_rule(
    const std::string& name,
    const std::string& hex_pattern,
    Severity severity) noexcept {
    if (!impl_) return;
    DetectionRule rule;
    rule.id          = RuleId{impl_->next_id++};
    rule.type        = RuleType::Yara;
    rule.name        = name;
    rule.hex_pattern = hex_pattern;
    rule.severity    = severity;
    rule.enabled     = true;
    std::lock_guard lock(impl_->mtx);
    impl_->rules.push_back(rule);
}

std::size_t DetectionEngine::rule_count() const noexcept {
    if (!impl_) return 0;
    std::lock_guard lock(impl_->mtx);
    return impl_->rules.size();
}

std::uint64_t DetectionEngine::alert_count() const noexcept {
    if (!impl_) return 0;
    return impl_->alert_count.load();
}

EngineStats DetectionEngine::stats() const noexcept {
    if (!impl_) return {};
    return EngineStats{
        impl_->signals_processed.load(),
        impl_->alert_count.load(),
        impl_->suppressed_count.load(),
        impl_->alert_count.load(),
        impl_->rules.size()
    };
}

void DetectionEngine::reset() noexcept {
    if (!impl_) return;
    std::lock_guard lock(impl_->mtx);
    impl_->suppressed_ips.clear();
    impl_->suppressed_rules.clear();
    impl_->thresholds.clear();
    impl_->alert_count.store(0);
    impl_->signals_processed.store(0);
    impl_->suppressed_count.store(0);
}

void DetectionEngine::clear() noexcept {
    if (!impl_) return;
    std::lock_guard lock(impl_->mtx);
    impl_->rules.clear();
    impl_->suppressed_ips.clear();
    impl_->suppressed_rules.clear();
    impl_->thresholds.clear();
    impl_->whitelist.clear();
    impl_->alert_count.store(0);
    impl_->signals_processed.store(0);
    impl_->suppressed_count.store(0);
}

} // namespace zote
