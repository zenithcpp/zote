// tests/unit/test_zote_engine.cpp
// ZOTE — zenithcpp Open Source Threat Engine
// ZoteEngine integration tests

#include <catch2/catch_test_macros.hpp>
#include <zote/zote_engine.hpp>

static zote::DetectionRule make_rule(
    std::uint64_t id, const std::string& name,
    const std::string& pattern,
    zote::Severity sev = zote::Severity::High) {
    zote::DetectionRule r;
    r.id       = zote::RuleId{id};
    r.type     = zote::RuleType::Signature;
    r.name     = name;
    r.pattern  = pattern;
    r.severity = sev;
    r.enabled  = true;
    return r;
}

static zote::Signal make_signal(
    const std::string& src,
    const std::string& desc) {
    zote::Signal s;
    s.net.src     = zote::IpAddress{std::string(src)};
    s.description = desc;
    return s;
}

// ════════════════════════════════════════════════════════════════════════
// Initialisation
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("ZoteEngine: initialises with zero rules",
          "[zote_engine][init]") {
    zote::ZoteEngine eng;
    REQUIRE(eng.rule_count()    == 0);
    REQUIRE(eng.campaign_count() == 0);
}

TEST_CASE("ZoteEngine: accepts custom config",
          "[zote_engine][init]") {
    zote::DetectionEngineConfig dcfg;
    dcfg.fp_threshold = 0.9f;
    zote::ZoteEngine eng(dcfg);
    REQUIRE(eng.rule_count() == 0);
}

// ════════════════════════════════════════════════════════════════════════
// Rule management
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("ZoteEngine: add rule increments count",
          "[zote_engine][rules]") {
    zote::ZoteEngine eng;
    eng.add_rule(make_rule(1, "TestRule", "malware"));
    REQUIRE(eng.rule_count() == 1);
}

TEST_CASE("ZoteEngine: add_rules bulk loads",
          "[zote_engine][rules]") {
    zote::ZoteEngine eng;
    std::vector<zote::DetectionRule> rules = {
        make_rule(1, "R1", "scan"),
        make_rule(2, "R2", "exploit"),
        make_rule(3, "R3", "beacon"),
    };
    eng.add_rules(rules);
    REQUIRE(eng.rule_count() == 3);
}

// ════════════════════════════════════════════════════════════════════════
// process() — full pipeline
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("ZoteEngine: process returns ThreatAssessment",
          "[zote_engine][process]") {
    zote::ZoteEngine eng;
    eng.add_rule(make_rule(1, "RansomRule", "ransomware",
                          zote::Severity::Critical));
    auto a = eng.process(
        make_signal("1.2.3.4", "ransomware encrypting files"));
    REQUIRE(a.risk.score > 0.0f);
}

TEST_CASE("ZoteEngine: process populates kill chain",
          "[zote_engine][process]") {
    zote::ZoteEngine eng;
    eng.add_rule(make_rule(1, "BeaconRule", "beacon"));
    auto a = eng.process(
        make_signal("1.2.3.4", "c2 beacon detected"));
    REQUIRE(a.kill_chain.furthest_stage ==
            zote::KillChainStage::CommandControl);
}

TEST_CASE("ZoteEngine: process with no matching rule",
          "[zote_engine][process]") {
    zote::ZoteEngine eng;
    eng.add_rule(make_rule(1, "Rule", "malware"));
    auto a = eng.process(
        make_signal("1.2.3.4", "normal web traffic"));
    REQUIRE(a.risk.score == 0.0f);
    REQUIRE(a.risk.evidence.empty());
}

TEST_CASE("ZoteEngine: process creates campaign",
          "[zote_engine][campaign]") {
    zote::ZoteEngine eng;
    eng.add_rule(make_rule(1, "Rule", "exploit"));
    static_cast<void>(eng.process(make_signal("5.6.7.8", "exploit attempt")));
    REQUIRE(eng.campaign_count() > 0);
}

TEST_CASE("ZoteEngine: campaign_for_ip finds campaign",
          "[zote_engine][campaign]") {
    zote::ZoteEngine eng;
    eng.add_rule(make_rule(1, "Rule", "attack"));
    static_cast<void>(eng.process(make_signal("2.3.4.5", "attack detected")));
    auto* camp = eng.campaign_for_ip("2.3.4.5");
    REQUIRE(camp != nullptr);
}

TEST_CASE("ZoteEngine: multiple signals group into campaign",
          "[zote_engine][campaign]") {
    zote::ZoteEngine eng;
    eng.add_rule(make_rule(1, "Rule", "attack"));
    static_cast<void>(eng.process(make_signal("3.4.5.6", "attack detected")));
    static_cast<void>(eng.process(make_signal("3.4.5.6", "attack escalating")));
    auto camps = eng.campaigns_snapshot();
    REQUIRE(camps.size() == 1);
    REQUIRE(camps[0].alert_count == 2);
}

// ════════════════════════════════════════════════════════════════════════
// callback API
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("ZoteEngine: callback fires on detection",
          "[zote_engine][callback]") {
    zote::ZoteEngine eng;
    eng.add_rule(make_rule(1, "Rule", "exploit"));
    int fired = 0;
    eng.process(make_signal("1.2.3.4", "exploit attempt"),
        [&fired](const zote::DetectionResult&) { ++fired; });
    REQUIRE(fired == 1);
}

// ════════════════════════════════════════════════════════════════════════
// batch processing
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("ZoteEngine: process_batch returns assessments",
          "[zote_engine][batch]") {
    zote::ZoteEngine eng;
    eng.add_rule(make_rule(1, "Rule", "malware"));
    std::vector<zote::Signal> signals = {
        make_signal("1.2.3.4", "malware detected"),
        make_signal("5.6.7.8", "clean traffic"),
        make_signal("1.2.3.4", "malware spreading"),
    };
    auto results = eng.process_batch(signals);
    REQUIRE(results.size() == 3);
}

// ════════════════════════════════════════════════════════════════════════
// stats + observability
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("ZoteEngine: detection_stats tracks signals",
          "[zote_engine][stats]") {
    zote::ZoteEngine eng;
    eng.add_rule(make_rule(1, "Rule", "attack"));
    static_cast<void>(eng.process(make_signal("1.2.3.4", "attack detected")));
    static_cast<void>(eng.process(make_signal("1.2.3.4", "attack spreading")));
    auto s = eng.detection_stats();
    REQUIRE(s.signals_processed >= 2);
}

// ════════════════════════════════════════════════════════════════════════
// reset
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("ZoteEngine: reset clears state but keeps rules",
          "[zote_engine][reset]") {
    zote::ZoteEngine eng;
    eng.add_rule(make_rule(1, "Rule", "attack"));
    static_cast<void>(eng.process(make_signal("1.2.3.4", "attack detected")));
    eng.reset();
    REQUIRE(eng.rule_count() == 1);
    REQUIRE(eng.campaign_count() == 0);
}

// ════════════════════════════════════════════════════════════════════════
// direct engine access
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("ZoteEngine: direct detection engine access",
          "[zote_engine][advanced]") {
    zote::ZoteEngine eng;
    auto& det = eng.detection_engine();
    det.add_rule(make_rule(99, "DirectRule", "direct"));
    REQUIRE(eng.rule_count() == 1);
}
