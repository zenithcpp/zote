// examples/campaign_analysis.cpp
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
    std::cout << "ZOTE Campaign Analysis Example\n\n";

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
              << attacker << " ===\n\n";

    for (const auto& ev : events) {
        zote::Signal sig;
        sig.net.src     = zote::IpAddress{std::string(attacker)};
        sig.description = ev.description;
        sig.mitre_id    = zote::TechniqueId{ev.mitre_id};

        auto assessment = engine.process(sig);

        std::cout << "  Signal: " << ev.description << "\n";
        if (assessment.risk.score > 0.0f) {
            std::cout << "    Risk:       " << assessment.risk.score
                      << "/10\n";
            std::cout << "    Confidence: " << assessment.risk.confidence
                      << "\n";
            std::cout << "    Stage:      "
                      << zote::KillChainMapper::stage_name(
                             assessment.kill_chain.furthest_stage)
                      << "\n";
            if (!assessment.attribution.actor.empty())
                std::cout << "    Actor:      "
                          << assessment.attribution.actor.value
                          << " (conf="
                          << assessment.attribution.confidence
                          << ")\n";
            for (const auto& rec : assessment.recommendations)
                std::cout << "    → " << rec << "\n";
        } else {
            std::cout << "    (no detection)\n";
        }
        std::cout << "\n";
    }

    // Campaign summary
    auto camps = engine.campaigns_snapshot();
    if (!camps.empty()) {
        const auto& camp = camps[0];
        std::cout << "=== Campaign Summary ===\n";
        std::cout << "  Name:        " << camp.name << "\n";
        std::cout << "  Risk score:  " << camp.risk_score << "/10\n";
        std::cout << "  Alerts:      " << camp.alert_count << "\n";
        std::cout << "  Stages seen: " << camp.stages.size() << "\n";
        std::cout << "  Timeline:    " << camp.timeline.size()
                  << " events\n";

        auto attr = engine.attribute_actor(camp.id);
        if (!attr.actor.empty()) {
            std::cout << "  Attribution: " << attr.actor.value
                      << " (confidence=" << attr.confidence << ")\n";
            std::cout << "  Techniques matched: "
                      << attr.matched_techniques.size() << "\n";
        }
    }

    return 0;
}
