// examples/basic_detection.cpp
// ZOTE — zenithcpp Open Source Threat Engine
// Basic usage example

#include <zote/engine.hpp>
#include <zote/mitre.hpp>
#include <zote/killchain.hpp>
#include <zote/correlation.hpp>
#include <iostream>

int main() {
    // ── Detection engine ──────────────────────────────────────────────
    zote::DetectionEngine eng;

    zote::DetectionRule rule;
    rule.id       = zote::RuleId{1};
    rule.type     = zote::RuleType::Signature;
    rule.name     = "MalwareDetection";
    rule.pattern  = "malware";
    rule.severity = zote::Severity::High;
    rule.enabled  = true;
    eng.add_rule(rule);

    zote::Signal sig;
    sig.net.src    = zote::IpAddress{std::string{"1.2.3.4"}};
    sig.description = "malware.exe detected on host";
    sig.category_str = "trojan";

    auto results = eng.evaluate(sig);
    for (const auto& r : results) {
        std::cout << "[DETECT] " << r.rule_name
                  << " | confidence: " << r.confidence
                  << " | stage: "
                  << zote::KillChainMapper::stage_name(r.kill_chain)
                  << "\n";
        for (const auto& e : r.evidence)
            std::cout << "  evidence: " << e.field
                      << "=" << e.value << "\n";
    }

    // ── MITRE lookup ──────────────────────────────────────────────────
    auto* t = zote::MitreDb::lookup("T1566");
    if (t)
        std::cout << "[MITRE] " << t->id
                  << " — " << t->name << "\n";

    // ── Correlation ───────────────────────────────────────────────────
    zote::CorrelationEngine corr;
    zote::CorrelatedAlert alert;
    alert.src_ip      = zote::IpAddress{std::string{"1.2.3.4"}};
    alert.description = "ransomware encrypting files";
    alert.mitre_id    = zote::TechniqueId{"T1486"};
    alert.risk_score  = 9.0f;
    corr.ingest(alert);

    auto camps = corr.campaigns_snapshot();
    if (!camps.empty()) {
        auto attr = corr.attribute_actor(camps[0].id);
        std::cout << "[CORR] Campaign: " << camps[0].name
                  << " | actor: " << attr.actor.value
                  << " | confidence: " << attr.confidence << "\n";
    }

    return 0;
}
