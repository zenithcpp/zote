// examples/confidence_scoring.cpp
// ZOTE — zenithcpp Open Source Threat Engine
//
// Example: Confidence normalization across engines
// Demonstrates:
//   - DetectionEngine confidence
//   - KillChainMapper confidence
//   - ConfidenceNormalizer combining scores
//   - ConfidenceModel versioning

#include <zote/engine.hpp>
#include <zote/killchain.hpp>
#include <zote/types.hpp>
#include <iostream>
#include <iomanip>

int main() {
    std::cout << "ZOTE Confidence Scoring Example\n";
    std::cout << "ZOTE v" << zote::version().to_string() << "\n\n";

    // ── Detection engine setup ────────────────────────────────────────────
    zote::DetectionEngine eng;

    // Rule with structured conditions for precise confidence
    zote::DetectionRule rule;
    rule.id      = zote::RuleId{1};
    rule.name    = "C2BeaconDetection";
    rule.type    = zote::RuleType::Signature;
    rule.enabled = true;
    rule.severity = zote::Severity::High;
    rule.mitre_id = zote::TechniqueId{"T1071"};

    // Multiple weighted conditions
    rule.conditions.push_back({
        "description", zote::ConditionType::Contains,
        "beacon", 0.8f});
    rule.conditions.push_back({
        "description", zote::ConditionType::Contains,
        "outbound", 0.6f});
    rule.conditions.push_back({
        "proc.name", zote::ConditionType::Contains,
        "powershell", 1.0f});
    eng.add_rule(rule);

    // ── Test signals with varying confidence ─────────────────────────────
    struct TestCase {
        std::string description;
        std::string proc_name;
        std::string label;
    };

    std::vector<TestCase> cases = {
        {"outbound beacon detected",   "powershell.exe", "Full match"},
        {"beacon detected",            "",               "Partial match"},
        {"suspicious outbound traffic","",               "Weak match"},
        {"normal web traffic",         "",               "No match"},
    };

    std::cout << std::fixed << std::setprecision(2);
    std::cout << "=== Detection confidence ===\n";

    for (const auto& tc : cases) {
        zote::Signal sig;
        sig.description     = tc.description;
        sig.proc.process_name = tc.proc_name;
        sig.net.src = zote::IpAddress{std::string("1.2.3.4")};

        auto results = eng.evaluate(sig);
        auto kc      = zote::KillChainMapper::assess(sig);

        float det_conf = results.empty() ? 0.0f : results[0].confidence;
        float kc_conf  = kc.confidence;

        // Simulate UEBA score (would come from CorrelationEngine)
        float ueba_conf = det_conf > 0.5f ? 0.7f : 0.1f;

        float combined = zote::ConfidenceNormalizer::combine(
            det_conf, ueba_conf, kc_conf);

        std::cout << "  " << tc.label << ":\n";
        std::cout << "    Detection:   " << det_conf << "\n";
        std::cout << "    Kill chain:  " << kc_conf
                  << " (" << zote::KillChainMapper::stage_name(kc.stage)
                  << ")\n";
        std::cout << "    UEBA:        " << ueba_conf << "\n";
        std::cout << "    Combined:    " << combined << "\n";
        if (!results.empty()) {
            std::cout << "    Severity:    "
                      << results[0].severity_score << "/10\n";
            std::cout << "    Evidence:    "
                      << results[0].evidence.size() << " items\n";
        }
        std::cout << "\n";
    }

    // ── Custom confidence model ───────────────────────────────────────────
    std::cout << "=== Custom confidence model (EDR-heavy) ===\n";
    zote::ConfidenceModel edr_model;
    edr_model.w_detection  = 0.70f; // trust EDR more
    edr_model.w_ueba       = 0.20f;
    edr_model.w_kill_chain = 0.10f;
    edr_model.version      = 2;

    float custom = edr_model.apply(0.9f, 0.6f, 0.8f);
    float default_score = zote::DEFAULT_CONFIDENCE_MODEL.apply(
        0.9f, 0.6f, 0.8f);

    std::cout << "  Default model (v"
              << zote::DEFAULT_CONFIDENCE_MODEL.version
              << "): " << default_score << "\n";
    std::cout << "  EDR model     (v"
              << edr_model.version << "): " << custom << "\n";

    return 0;
}
