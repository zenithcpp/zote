// tests/unit/test_correlation.cpp
// ZOTE — zenithcpp Open Source Threat Engine
// Correlation engine unit tests

#include <catch2/catch_test_macros.hpp>
#include <zote/correlation.hpp>

static zote::CorrelatedAlert make_alert(
    const std::string& src,
    const std::string& desc,
    float risk = 5.0f,
    const std::string& mitre = "") {
    zote::CorrelatedAlert a;
    a.src_ip      = zote::IpAddress{src};
    a.description = desc;
    a.risk_score  = risk;
    a.mitre_id    = zote::TechniqueId{mitre};
    return a;
}

TEST_CASE("Correlation: initialises with zero alerts and campaigns",
          "[correlation][init]") {
    zote::CorrelationEngine eng;
    REQUIRE(eng.alert_count()   == 0);
    REQUIRE(eng.campaigns_snapshot().empty());
}

TEST_CASE("Correlation: ingest increments alert count",
          "[correlation][ingest]") {
    zote::CorrelationEngine eng;
    eng.ingest(make_alert("1.2.3.4", "port scan"));
    REQUIRE(eng.alert_count() == 1);
}

TEST_CASE("Correlation: first alert creates new campaign",
          "[correlation][campaign]") {
    zote::CorrelationEngine eng;
    eng.ingest(make_alert("1.2.3.4", "exploit attempt", 8.0f));
    auto camps = eng.campaigns_snapshot();
    REQUIRE(camps.size() == 1);
    REQUIRE(camps[0].src_ips[0].value == "1.2.3.4");
}

TEST_CASE("Correlation: campaign has active state on creation",
          "[correlation][campaign]") {
    zote::CorrelationEngine eng;
    eng.ingest(make_alert("1.2.3.4", "scan"));
    REQUIRE(eng.campaigns_snapshot()[0].state == zote::CampaignState::Active);
}

TEST_CASE("Correlation: campaign has timeline event on ingest",
          "[correlation][campaign]") {
    zote::CorrelationEngine eng;
    eng.ingest(make_alert("1.2.3.4", "exploit attempt", 8.0f));
    auto camps = eng.campaigns_snapshot();
    REQUIRE(!camps[0].timeline.empty());
    REQUIRE(camps[0].timeline[0].src_ip.value == "1.2.3.4");
}

TEST_CASE("Correlation: same IP groups into one campaign",
          "[correlation][campaign]") {
    zote::CorrelationEngine eng;
    eng.ingest(make_alert("1.2.3.4", "scan",    3.0f));
    eng.ingest(make_alert("1.2.3.4", "exploit", 7.0f));
    eng.ingest(make_alert("1.2.3.4", "beacon",  9.0f));
    REQUIRE(eng.campaigns_snapshot().size()        == 1);
    REQUIRE(eng.campaigns_snapshot()[0].alert_count == 3);
}

TEST_CASE("Correlation: different IPs create separate campaigns",
          "[correlation][campaign]") {
    zote::CorrelationEngine eng;
    eng.ingest(make_alert("1.2.3.4", "scan"));
    eng.ingest(make_alert("5.6.7.8", "scan"));
    REQUIRE(eng.campaigns_snapshot().size() == 2);
}

TEST_CASE("Correlation: campaign_for_ip finds correct campaign",
          "[correlation][campaign]") {
    zote::CorrelationEngine eng;
    eng.ingest(make_alert("1.2.3.4", "attack", 9.0f));
    auto* camp = eng.campaign_for_ip("1.2.3.4");
    REQUIRE(camp != nullptr);
    REQUIRE(camp->src_ips[0].value == "1.2.3.4");
}

TEST_CASE("Correlation: campaign_for_ip returns nullptr for unknown IP",
          "[correlation][campaign]") {
    zote::CorrelationEngine eng;
    REQUIRE(eng.campaign_for_ip("9.9.9.9") == nullptr);
}

TEST_CASE("Correlation: risk score accumulates per IP",
          "[correlation][risk]") {
    zote::CorrelationEngine eng;
    eng.ingest(make_alert("1.2.3.4", "attack1", 8.0f));
    eng.ingest(make_alert("1.2.3.4", "attack2", 8.0f));
    float score = eng.risk_score("1.2.3.4");
    REQUIRE(score > 0.0f);
    REQUIRE(score <= 10.0f);
}

TEST_CASE("Correlation: risk score zero for unknown IP",
          "[correlation][risk]") {
    zote::CorrelationEngine eng;
    REQUIRE(eng.risk_score("9.9.9.9") == 0.0f);
}

TEST_CASE("Correlation: UEBA profile tracks alert count",
          "[correlation][ueba]") {
    zote::CorrelationEngine eng;
    for (int i = 0; i < 12; ++i)
        eng.ingest(make_alert("5.6.7.8", "alert", 5.0f));
    auto p = eng.ueba_profile("5.6.7.8");
    REQUIRE(p.ip.value == "5.6.7.8");
    REQUIRE(p.alert_count_24h == 12);
    REQUIRE(p.is_anomalous);
}

TEST_CASE("Correlation: UEBA profile empty for unknown IP",
          "[correlation][ueba]") {
    zote::CorrelationEngine eng;
    auto p = eng.ueba_profile("9.9.9.9");
    REQUIRE(p.ip.empty());
    REQUIRE(p.alert_count_24h == 0);
}

TEST_CASE("Correlation: actor attribution returns actor and confidence",
          "[correlation][attribution]") {
    zote::CorrelationEngine eng;
    eng.ingest(make_alert("1.2.3.4", "ransomware", 9.0f, "T1486"));
    auto camps = eng.campaigns_snapshot();
    REQUIRE(!camps.empty());
    auto attr = eng.attribute_actor(camps[0].id);
    REQUIRE(attr.actor.value == "LockBit");
    REQUIRE(attr.confidence > 0.0f);
    REQUIRE(!attr.matched_techniques.empty());
}

TEST_CASE("Correlation: actor attribution empty for unknown campaign",
          "[correlation][attribution]") {
    zote::CorrelationEngine eng;
    auto attr = eng.attribute_actor(zote::CampaignId{9999});
    REQUIRE(attr.actor.empty());
}

TEST_CASE("Correlation: kill chain mapped on ingest",
          "[correlation][killchain]") {
    zote::CorrelationEngine eng;
    eng.ingest(make_alert("1.2.3.4", "c2 beacon", 8.0f));
    auto camps = eng.campaigns_snapshot();
    REQUIRE(!camps.empty());
    bool found = false;
    for (const auto& s : camps[0].stages)
        if (s == zote::KillChainStage::CommandControl)
            found = true;
    REQUIRE(found);
}

TEST_CASE("Correlation: map_kill_chain returns assessment with confidence",
          "[correlation][killchain]") {
    zote::CorrelatedAlert a;
    a.description = "exploit attempt";
    auto assessment =
        zote::CorrelationEngine::map_kill_chain(a);
    REQUIRE(assessment.stage ==
        zote::KillChainStage::Exploitation);
    REQUIRE(assessment.confidence > 0.0f);
}

TEST_CASE("Correlation: reset clears all state",
          "[correlation][reset]") {
    zote::CorrelationEngine eng;
    eng.ingest(make_alert("1.2.3.4", "attack"));
    eng.reset();
    REQUIRE(eng.alert_count()    == 0);
    REQUIRE(eng.campaigns_snapshot().empty());
}

// ════════════════════════════════════════════════════════════════════════
// ConfidenceNormalizer
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("ConfidenceNormalizer: combines three scores correctly",
          "[normalizer]") {
    float c = zote::ConfidenceNormalizer::combine(0.9f, 0.8f, 0.7f);
    REQUIRE(c > 0.0f);
    REQUIRE(c <= 1.0f);
    // Expected: (0.5*0.9 + 0.3*0.8 + 0.2*0.7) = 0.45+0.24+0.14 = 0.83
    REQUIRE(c > 0.80f);
    REQUIRE(c < 0.90f);
}

TEST_CASE("ConfidenceNormalizer: clamps to 0-1 range",
          "[normalizer]") {
    REQUIRE(zote::ConfidenceNormalizer::combine(
        1.0f, 1.0f, 1.0f) <= 1.0f);
    REQUIRE(zote::ConfidenceNormalizer::combine(
        0.0f, 0.0f, 0.0f) >= 0.0f);
}

TEST_CASE("ConfidenceNormalizer: det+kc combines without UEBA",
          "[normalizer]") {
    float c = zote::ConfidenceNormalizer::combine_det_kc(0.9f, 0.8f);
    REQUIRE(c > 0.0f);
    REQUIRE(c <= 1.0f);
}

TEST_CASE("ConfidenceNormalizer: det+ueba combines without kill chain",
          "[normalizer]") {
    float c = zote::ConfidenceNormalizer::combine_det_ueba(0.9f, 0.7f);
    REQUIRE(c > 0.0f);
    REQUIRE(c <= 1.0f);
}

TEST_CASE("ConfidenceNormalizer: higher inputs produce higher output",
          "[normalizer]") {
    float low  = zote::ConfidenceNormalizer::combine(0.3f, 0.3f, 0.3f);
    float high = zote::ConfidenceNormalizer::combine(0.9f, 0.9f, 0.9f);
    REQUIRE(high > low);
}

// ════════════════════════════════════════════════════════════════════════
// submit() — KillChainAssessment integration hook
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("Correlation: submit KillChainAssessment creates campaign",
          "[correlation][submit]") {
    zote::CorrelationEngine eng;
    zote::KillChainAssessment a;
    a.stage      = zote::KillChainStage::CommandControl;
    a.confidence = 0.90f;
    a.reasons.push_back({"description", "beacon", 0.9f, 0.9f});
    eng.submit(a, "1.2.3.4", 8.0f);
    REQUIRE(eng.alert_count() == 1);
    REQUIRE(!eng.campaigns_snapshot().empty());
}

TEST_CASE("Correlation: submit uses kill chain stage from assessment",
          "[correlation][submit]") {
    zote::CorrelationEngine eng;
    zote::KillChainAssessment a;
    a.stage      = zote::KillChainStage::Exploitation;
    a.confidence = 0.85f;
    eng.submit(a, "5.6.7.8", 7.0f);
    auto camps = eng.campaigns_snapshot();
    REQUIRE(!camps.empty());
    bool found = false;
    for (const auto& s : camps[0].stages)
        if (s == zote::KillChainStage::Exploitation)
            found = true;
    REQUIRE(found);
}

TEST_CASE("Correlation: submit multiple assessments groups by IP",
          "[correlation][submit]") {
    zote::CorrelationEngine eng;
    zote::KillChainAssessment a1, a2;
    a1.stage = zote::KillChainStage::Reconnaissance;
    a2.stage = zote::KillChainStage::Exploitation;
    eng.submit(a1, "1.2.3.4");
    eng.submit(a2, "1.2.3.4");
    REQUIRE(eng.campaigns_snapshot().size() == 1);
    REQUIRE(eng.campaigns_snapshot()[0].alert_count == 2);
}
