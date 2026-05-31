// tests/unit/test_mitre.cpp
// ZOTE — zenithcpp Open Source Threat Engine
// MITRE ATT&CK database unit tests

#include <catch2/catch_test_macros.hpp>
#include <zote/mitre.hpp>

TEST_CASE("MITRE: lookup known technique by ID",
          "[mitre][lookup]") {
    auto* t = zote::MitreDb::lookup("T1566");
    REQUIRE(t != nullptr);
    REQUIRE(std::string(t->id) == "T1566");
    REQUIRE(std::string(t->name) == "Phishing");
    REQUIRE(std::string(t->tactic) == "TA0001");
}

TEST_CASE("MITRE: lookup sub-technique by full ID",
          "[mitre][lookup]") {
    auto* t = zote::MitreDb::lookup("T1566.001");
    REQUIRE(t != nullptr);
    REQUIRE(std::string(t->name) == "Spearphishing Attachment");
}

TEST_CASE("MITRE: lookup unknown ID returns nullptr",
          "[mitre][lookup]") {
    REQUIRE(zote::MitreDb::lookup("T9999") == nullptr);
}

TEST_CASE("MITRE: lookup ICS technique",
          "[mitre][ics]") {
    auto* t = zote::MitreDb::lookup("T0814");
    REQUIRE(t != nullptr);
    REQUIRE(std::string(t->name) == "Denial of Service");
}

TEST_CASE("MITRE: by_tactic returns non-empty for Initial Access",
          "[mitre][tactic]") {
    auto techs = zote::MitreDb::by_tactic("TA0001");
    REQUIRE(!techs.empty());
    for (const auto* t : techs)
        REQUIRE(std::string(t->tactic) == "TA0001");
}

TEST_CASE("MITRE: by_tactic returns empty for unknown tactic",
          "[mitre][tactic]") {
    REQUIRE(zote::MitreDb::by_tactic("TA9999").empty());
}

TEST_CASE("MITRE: by_actor returns techniques for APT28",
          "[mitre][actor]") {
    REQUIRE(!zote::MitreDb::by_actor("APT28").empty());
}

TEST_CASE("MITRE: by_actor returns techniques for LockBit",
          "[mitre][actor]") {
    auto techs = zote::MitreDb::by_actor("LockBit");
    REQUIRE(!techs.empty());
    bool found = false;
    for (const auto* t : techs)
        if (std::string(t->id) == "T1486") { found = true; break; }
    REQUIRE(found);
}

TEST_CASE("MITRE: by_actor returns empty for unknown actor",
          "[mitre][actor]") {
    REQUIRE(zote::MitreDb::by_actor("UnknownActor99").empty());
}

TEST_CASE("MITRE: by_actor is case-insensitive",
          "[mitre][actor]") {
    auto upper = zote::MitreDb::by_actor("APT28");
    auto lower = zote::MitreDb::by_actor("apt28");
    REQUIRE(upper.size() == lower.size());
}

TEST_CASE("MITRE: by_software returns techniques for Mimikatz",
          "[mitre][software]") {
    auto techs = zote::MitreDb::by_software("Mimikatz");
    REQUIRE(!techs.empty());
    bool found = false;
    for (const auto* t : techs)
        if (std::string(t->id) == "T1003") { found = true; break; }
    REQUIRE(found);
}

TEST_CASE("MITRE: by_software returns techniques for BloodHound",
          "[mitre][software]") {
    REQUIRE(!zote::MitreDb::by_software("BloodHound").empty());
}

TEST_CASE("MITRE: by_service returns techniques for ssh",
          "[mitre][service]") {
    REQUIRE(!zote::MitreDb::by_service("ssh").empty());
}

TEST_CASE("MITRE: by_service returns techniques for smb",
          "[mitre][service]") {
    REQUIRE(!zote::MitreDb::by_service("smb").empty());
}

TEST_CASE("MITRE: by_service returns empty for unknown service",
          "[mitre][service]") {
    REQUIRE(zote::MitreDb::by_service("unknownproto").empty());
}

TEST_CASE("MITRE: d3fend_for returns countermeasures for T1566",
          "[mitre][d3fend]") {
    REQUIRE(!zote::MitreDb::d3fend_for("T1566").empty());
}

TEST_CASE("MITRE: d3fend_for returns empty for unknown technique",
          "[mitre][d3fend]") {
    REQUIRE(zote::MitreDb::d3fend_for("T9999").empty());
}

TEST_CASE("MITRE: navigator_export produces valid JSON string",
          "[mitre][navigator]") {
    std::vector<std::string> ids = {"T1566", "T1059", "T1003"};
    auto json = zote::MitreDb::navigator_export(ids, "TestLayer");
    REQUIRE(!json.empty());
    REQUIRE(json.find("TestLayer") != std::string::npos);
    REQUIRE(json.find("T1566")    != std::string::npos);
    REQUIRE(json.front() == '{');
    REQUIRE(json.back()  == '}');
}

TEST_CASE("MITRE: enterprise database has substantial coverage",
          "[mitre][size]") {
    REQUIRE(zote::MitreDb::enterprise_size() >= 80);
}

TEST_CASE("MITRE: ICS database has substantial coverage",
          "[mitre][size]") {
    REQUIRE(zote::MitreDb::ics_techniques().size() >= 80);
}

TEST_CASE("MITRE: total database size is enterprise plus ICS",
          "[mitre][size]") {
    REQUIRE(zote::MitreDb::total_size() ==
            zote::MitreDb::enterprise_size() +
            zote::MitreDb::ics_techniques().size());
}
