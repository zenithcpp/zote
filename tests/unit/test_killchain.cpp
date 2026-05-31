// tests/unit/test_killchain.cpp
// ZOTE — zenithcpp Open Source Threat Engine
// Kill chain mapper unit tests

#include <catch2/catch_test_macros.hpp>
#include <zote/killchain.hpp>
#include <zote/types.hpp>

static zote::Signal make_sig(const std::string& desc,
                             const std::string& cat = "",
                             const std::string& mid = "") {
    zote::Signal s;
    s.description  = desc;
    s.category_str = cat;
    s.mitre_id     = zote::TechniqueId{mid};
    return s;
}

// ════════════════════════════════════════════════════════════════════════
// assess() — primary API
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("KillChain: assess returns stage and confidence",
          "[killchain][assess]") {
    auto a = zote::KillChainMapper::assess(make_sig("port scan detected"));
    REQUIRE(a.stage == zote::KillChainStage::Reconnaissance);
    REQUIRE(a.confidence > 0.0f);
    REQUIRE(!a.reasons.empty());
}

TEST_CASE("KillChain: assess includes reason field and match",
          "[killchain][assess]") {
    auto a = zote::KillChainMapper::assess(make_sig("exploit attempt"));
    REQUIRE(!a.reasons.empty());
    REQUIRE(!a.reasons[0].field.empty());
    REQUIRE(!a.reasons[0].match.empty());
    REQUIRE(a.reasons[0].weight > 0.0f);
}

TEST_CASE("KillChain: reason includes contribution field",
          "[killchain][assess]") {
    auto a = zote::KillChainMapper::assess(make_sig("beacon outbound c2"));
    REQUIRE(!a.reasons.empty());
    REQUIRE(a.reasons[0].contribution >= 0.0f);
    REQUIRE(a.reasons[0].contribution <= 1.0f);
}

// ════════════════════════════════════════════════════════════════════════
// candidates — multi-stage output
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("KillChain: assess returns candidates vector",
          "[killchain][candidates]") {
    auto a = zote::KillChainMapper::assess(
        make_sig("exploit attempt with payload delivery"));
    REQUIRE(!a.candidates.empty());
}

TEST_CASE("KillChain: candidates contain primary stage",
          "[killchain][candidates]") {
    auto a = zote::KillChainMapper::assess(make_sig("c2 beacon detected"));
    bool found = false;
    for (const auto& sc : a.candidates)
        if (sc.stage == a.stage) { found = true; break; }
    REQUIRE(found);
}

TEST_CASE("KillChain: candidates have valid confidence range",
          "[killchain][candidates]") {
    auto a = zote::KillChainMapper::assess(make_sig("ransomware encrypting"));
    for (const auto& sc : a.candidates) {
        REQUIRE(sc.confidence >= 0.0f);
        REQUIRE(sc.confidence <= 1.0f);
    }
}

TEST_CASE("KillChain: primary confidence is highest among candidates",
          "[killchain][candidates]") {
    auto a = zote::KillChainMapper::assess(make_sig("exploit attempt"));
    for (const auto& sc : a.candidates)
        REQUIRE(a.confidence >= sc.confidence);
}

// ════════════════════════════════════════════════════════════════════════
// keyword mapping
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("KillChain: reconnaissance keywords map correctly",
          "[killchain][keywords]") {
    REQUIRE(zote::KillChainMapper::map(make_sig("port scan detected"))
        == zote::KillChainStage::Reconnaissance);
    REQUIRE(zote::KillChainMapper::map(make_sig("host enumeration"))
        == zote::KillChainStage::Reconnaissance);
}

TEST_CASE("KillChain: exploitation keywords map correctly",
          "[killchain][keywords]") {
    REQUIRE(zote::KillChainMapper::map(make_sig("exploit attempt"))
        == zote::KillChainStage::Exploitation);
    REQUIRE(zote::KillChainMapper::map(make_sig("shellcode detected"))
        == zote::KillChainStage::Exploitation);
    REQUIRE(zote::KillChainMapper::map(make_sig("rce vulnerability"))
        == zote::KillChainStage::Exploitation);
}

TEST_CASE("KillChain: C2 keywords map correctly",
          "[killchain][keywords]") {
    REQUIRE(zote::KillChainMapper::map(make_sig("c2 beacon detected"))
        == zote::KillChainStage::CommandControl);
    REQUIRE(zote::KillChainMapper::map(make_sig("cobaltstrike beacon"))
        == zote::KillChainStage::CommandControl);
    REQUIRE(zote::KillChainMapper::map(make_sig("dns tunnel outbound"))
        == zote::KillChainStage::CommandControl);
}

TEST_CASE("KillChain: installation keywords map correctly",
          "[killchain][keywords]") {
    REQUIRE(zote::KillChainMapper::map(make_sig("backdoor installed"))
        == zote::KillChainStage::Installation);
    REQUIRE(zote::KillChainMapper::map(make_sig("persistence via cron"))
        == zote::KillChainStage::Installation);
}

TEST_CASE("KillChain: actions on objectives map correctly",
          "[killchain][keywords]") {
    REQUIRE(zote::KillChainMapper::map(make_sig("data exfil detected"))
        == zote::KillChainStage::ActionsOnObj);
    REQUIRE(zote::KillChainMapper::map(make_sig("ransomware encrypting"))
        == zote::KillChainStage::ActionsOnObj);
    REQUIRE(zote::KillChainMapper::map(make_sig("lateral movement smb"))
        == zote::KillChainStage::ActionsOnObj);
}

TEST_CASE("KillChain: unknown signal maps to Unknown",
          "[killchain][keywords]") {
    REQUIRE(zote::KillChainMapper::map(make_sig("generic log entry"))
        == zote::KillChainStage::Unknown);
}

TEST_CASE("KillChain: category field contributes to mapping",
          "[killchain][keywords]") {
    zote::Signal sig;
    sig.description = "suspicious activity";
    sig.category_str = "c2.beacon";
    REQUIRE(zote::KillChainMapper::map(sig)
        == zote::KillChainStage::CommandControl);
}

// ════════════════════════════════════════════════════════════════════════
// MITRE ID mapping
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("KillChain: MITRE ID takes priority over keywords",
          "[killchain][mitre]") {
    auto sig = make_sig("port scan", "", "T1486");
    REQUIRE(zote::KillChainMapper::map(sig)
        == zote::KillChainStage::ActionsOnObj);
}

TEST_CASE("KillChain: MITRE ID assessment has high confidence",
          "[killchain][mitre]") {
    auto sig = make_sig("", "", "T1566");
    auto a = zote::KillChainMapper::assess(sig);
    REQUIRE(a.stage == zote::KillChainStage::Delivery);
    REQUIRE(a.confidence >= 0.9f);
}

TEST_CASE("KillChain: from_mitre_id maps known techniques",
          "[killchain][mitre]") {
    REQUIRE(zote::KillChainMapper::from_mitre_id("T1566")
        == zote::KillChainStage::Delivery);
    REQUIRE(zote::KillChainMapper::from_mitre_id("T1190")
        == zote::KillChainStage::Exploitation);
    REQUIRE(zote::KillChainMapper::from_mitre_id("T1071")
        == zote::KillChainStage::CommandControl);
    REQUIRE(zote::KillChainMapper::from_mitre_id("T1486")
        == zote::KillChainStage::ActionsOnObj);
}

TEST_CASE("KillChain: from_mitre_id handles sub-techniques",
          "[killchain][mitre]") {
    REQUIRE(zote::KillChainMapper::from_mitre_id("T1566.001")
        == zote::KillChainStage::Delivery);
}

TEST_CASE("KillChain: from_mitre_id returns Unknown for unknown ID",
          "[killchain][mitre]") {
    REQUIRE(zote::KillChainMapper::from_mitre_id("T9999")
        == zote::KillChainStage::Unknown);
}

TEST_CASE("KillChain: from_technique_id uses TechniqueId type",
          "[killchain][mitre]") {
    zote::TechniqueId tid{"T1486"};
    REQUIRE(zote::KillChainMapper::from_technique_id(tid)
        == zote::KillChainStage::ActionsOnObj);
}

// ════════════════════════════════════════════════════════════════════════
// stages_for_technique — multi-stage
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("KillChain: stages_for_technique returns all stages",
          "[killchain][multistage]") {
    auto stages = zote::KillChainMapper::stages_for_technique("T1566");
    REQUIRE(!stages.empty());
    bool found = false;
    for (const auto& sc : stages)
        if (sc.stage == zote::KillChainStage::Delivery)
            found = true;
    REQUIRE(found);
}

TEST_CASE("KillChain: stages_for_technique confidence in valid range",
          "[killchain][multistage]") {
    auto stages = zote::KillChainMapper::stages_for_technique("T1071");
    REQUIRE(!stages.empty());
    for (const auto& sc : stages) {
        REQUIRE(sc.confidence > 0.0f);
        REQUIRE(sc.confidence <= 1.0f);
    }
}

TEST_CASE("KillChain: stages_for_technique empty for unknown technique",
          "[killchain][multistage]") {
    REQUIRE(zote::KillChainMapper::stages_for_technique("T9999").empty());
}

// ════════════════════════════════════════════════════════════════════════
// metadata
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("KillChain: stage_name returns non-empty string",
          "[killchain][names]") {
    REQUIRE(std::string(zote::KillChainMapper::stage_name(
        zote::KillChainStage::Reconnaissance)).length() > 0);
    REQUIRE(std::string(zote::KillChainMapper::stage_name(
        zote::KillChainStage::CommandControl)).length() > 0);
    REQUIRE(std::string(zote::KillChainMapper::stage_name(
        zote::KillChainStage::Unknown)).length() > 0);
}
