#!/usr/bin/env python3
# zote_pass5_tests.py
# Run from ~/Desktop/ZOTE/
# Pass 5: update all test files + add ZoteEngine tests
#          + update CMakeLists.txt

import pathlib

# ── Fix test_correlation.cpp — campaigns() → campaigns_snapshot() ─────────
p = pathlib.Path("tests/unit/test_correlation.cpp")
content = p.read_text()

# Replace all .campaigns() with .campaigns_snapshot()
content = content.replace(
    "eng.campaigns()", "eng.campaigns_snapshot()")
content = content.replace(
    "corr.campaigns()", "corr.campaigns_snapshot()")

# Fix campaign_for_ip — now returns const Campaign*
content = content.replace(
    """    auto camp = eng.campaign_for_ip("1.2.3.4");
    REQUIRE(camp.has_value());
    REQUIRE(camp->src_ips[0].value == "1.2.3.4");""",
    """    auto* camp = eng.campaign_for_ip("1.2.3.4");
    REQUIRE(camp != nullptr);
    REQUIRE(camp->src_ips[0].value == "1.2.3.4");"""
)
content = content.replace(
    '    REQUIRE(!eng.campaign_for_ip("9.9.9.9").has_value());',
    '    REQUIRE(eng.campaign_for_ip("9.9.9.9") == nullptr);'
)

# Fix attribution test — uses campaigns_snapshot()
content = content.replace(
    "    auto attr = eng.attribute_actor(camps[0].id);",
    "    auto attr = eng.attribute_actor(camps[0].id);"
)

p.write_text(content)
print("OK -- test_correlation.cpp: campaigns_snapshot() + raw ptr")

# ── Fix test_engine.cpp — Signal struct changes ──────────────────────────
p = pathlib.Path("tests/unit/test_engine.cpp")
content = p.read_text()

# category is now SignalCategory enum — fix category-based test
content = content.replace(
    '    sig.category = "trojan.generic";',
    '    sig.category    = zote::SignalCategory::MalwareDetected;\n    sig.category_str = "trojan.generic";'
)
p.write_text(content)
print("OK -- test_engine.cpp: Signal.category enum updated")

# ── Fix test_killchain.cpp — Signal.category is now enum ─────────────────
p = pathlib.Path("tests/unit/test_killchain.cpp")
content = p.read_text()

content = content.replace(
    '    sig.category    = "c2.beacon";',
    '    sig.category     = zote::SignalCategory::CommandControl;\n    sig.category_str = "c2.beacon";'
)
p.write_text(content)
print("OK -- test_killchain.cpp: Signal.category enum updated")

# ── Write test_zote_engine.cpp ────────────────────────────────────────────
tests = []
tests.append("// tests/unit/test_zote_engine.cpp")
tests.append("// ZOTE — zenithcpp Open Source Threat Engine")
tests.append("// ZoteEngine integration tests")
tests.append("")
tests.append("#include <catch2/catch_test_macros.hpp>")
tests.append("#include <zote/zote_engine.hpp>")
tests.append("")
tests.append("static zote::DetectionRule make_rule(")
tests.append("    std::uint64_t id, const std::string& name,")
tests.append("    const std::string& pattern,")
tests.append("    zote::Severity sev = zote::Severity::High) {")
tests.append("    zote::DetectionRule r;")
tests.append("    r.id       = zote::RuleId{id};")
tests.append("    r.type     = zote::RuleType::Signature;")
tests.append("    r.name     = name;")
tests.append("    r.pattern  = pattern;")
tests.append("    r.severity = sev;")
tests.append("    r.enabled  = true;")
tests.append("    return r;")
tests.append("}")
tests.append("")
tests.append("static zote::Signal make_signal(")
tests.append("    const std::string& src,")
tests.append("    const std::string& desc) {")
tests.append("    zote::Signal s;")
tests.append("    s.net.src     = zote::IpAddress{std::string(src)};")
tests.append("    s.description = desc;")
tests.append("    return s;")
tests.append("}")
tests.append("")
tests.append("// ════════════════════════════════════════════════════════════════════════")
tests.append("// Initialisation")
tests.append("// ════════════════════════════════════════════════════════════════════════")
tests.append("")
tests.append("TEST_CASE(\"ZoteEngine: initialises with zero rules\",")
tests.append("          \"[zote_engine][init]\") {")
tests.append("    zote::ZoteEngine eng;")
tests.append("    REQUIRE(eng.rule_count()    == 0);")
tests.append("    REQUIRE(eng.campaign_count() == 0);")
tests.append("}")
tests.append("")
tests.append("TEST_CASE(\"ZoteEngine: accepts custom config\",")
tests.append("          \"[zote_engine][init]\") {")
tests.append("    zote::DetectionEngineConfig dcfg;")
tests.append("    dcfg.fp_threshold = 0.9f;")
tests.append("    zote::ZoteEngine eng(dcfg);")
tests.append("    REQUIRE(eng.rule_count() == 0);")
tests.append("}")
tests.append("")
tests.append("// ════════════════════════════════════════════════════════════════════════")
tests.append("// Rule management")
tests.append("// ════════════════════════════════════════════════════════════════════════")
tests.append("")
tests.append("TEST_CASE(\"ZoteEngine: add rule increments count\",")
tests.append("          \"[zote_engine][rules]\") {")
tests.append("    zote::ZoteEngine eng;")
tests.append("    eng.add_rule(make_rule(1, \"TestRule\", \"malware\"));")
tests.append("    REQUIRE(eng.rule_count() == 1);")
tests.append("}")
tests.append("")
tests.append("TEST_CASE(\"ZoteEngine: add_rules bulk loads\",")
tests.append("          \"[zote_engine][rules]\") {")
tests.append("    zote::ZoteEngine eng;")
tests.append("    std::vector<zote::DetectionRule> rules = {")
tests.append("        make_rule(1, \"R1\", \"scan\"),")
tests.append("        make_rule(2, \"R2\", \"exploit\"),")
tests.append("        make_rule(3, \"R3\", \"beacon\"),")
tests.append("    };")
tests.append("    eng.add_rules(rules);")
tests.append("    REQUIRE(eng.rule_count() == 3);")
tests.append("}")
tests.append("")
tests.append("// ════════════════════════════════════════════════════════════════════════")
tests.append("// process() — full pipeline")
tests.append("// ════════════════════════════════════════════════════════════════════════")
tests.append("")
tests.append("TEST_CASE(\"ZoteEngine: process returns ThreatAssessment\",")
tests.append("          \"[zote_engine][process]\") {")
tests.append("    zote::ZoteEngine eng;")
tests.append("    eng.add_rule(make_rule(1, \"RansomRule\", \"ransomware\",")
tests.append("                          zote::Severity::Critical));")
tests.append("    auto a = eng.process(")
tests.append("        make_signal(\"1.2.3.4\", \"ransomware encrypting files\"));")
tests.append("    REQUIRE(a.risk.score > 0.0f);")
tests.append("}")
tests.append("")
tests.append("TEST_CASE(\"ZoteEngine: process populates kill chain\",")
tests.append("          \"[zote_engine][process]\") {")
tests.append("    zote::ZoteEngine eng;")
tests.append("    eng.add_rule(make_rule(1, \"BeaconRule\", \"beacon\"));")
tests.append("    auto a = eng.process(")
tests.append("        make_signal(\"1.2.3.4\", \"c2 beacon detected\"));")
tests.append("    REQUIRE(a.kill_chain.furthest_stage ==")
tests.append("            zote::KillChainStage::CommandControl);")
tests.append("}")
tests.append("")
tests.append("TEST_CASE(\"ZoteEngine: process with no matching rule\",")
tests.append("          \"[zote_engine][process]\") {")
tests.append("    zote::ZoteEngine eng;")
tests.append("    eng.add_rule(make_rule(1, \"Rule\", \"malware\"));")
tests.append("    auto a = eng.process(")
tests.append("        make_signal(\"1.2.3.4\", \"normal web traffic\"));")
tests.append("    REQUIRE(a.risk.score == 0.0f);")
tests.append("    REQUIRE(a.risk.evidence.empty());")
tests.append("}")
tests.append("")
tests.append("TEST_CASE(\"ZoteEngine: process creates campaign\",")
tests.append("          \"[zote_engine][campaign]\") {")
tests.append("    zote::ZoteEngine eng;")
tests.append("    eng.add_rule(make_rule(1, \"Rule\", \"exploit\"));")
tests.append("    eng.process(make_signal(\"5.6.7.8\", \"exploit attempt\"));")
tests.append("    REQUIRE(eng.campaign_count() > 0);")
tests.append("}")
tests.append("")
tests.append("TEST_CASE(\"ZoteEngine: campaign_for_ip finds campaign\",")
tests.append("          \"[zote_engine][campaign]\") {")
tests.append("    zote::ZoteEngine eng;")
tests.append("    eng.add_rule(make_rule(1, \"Rule\", \"attack\"));")
tests.append("    eng.process(make_signal(\"2.3.4.5\", \"attack detected\"));")
tests.append("    auto* camp = eng.campaign_for_ip(\"2.3.4.5\");")
tests.append("    REQUIRE(camp != nullptr);")
tests.append("}")
tests.append("")
tests.append("TEST_CASE(\"ZoteEngine: multiple signals group into campaign\",")
tests.append("          \"[zote_engine][campaign]\") {")
tests.append("    zote::ZoteEngine eng;")
tests.append("    eng.add_rule(make_rule(1, \"Rule\", \"attack\"));")
tests.append("    eng.process(make_signal(\"3.4.5.6\", \"attack detected\"));")
tests.append("    eng.process(make_signal(\"3.4.5.6\", \"attack escalating\"));")
tests.append("    auto camps = eng.campaigns_snapshot();")
tests.append("    REQUIRE(camps.size() == 1);")
tests.append("    REQUIRE(camps[0].alert_count == 2);")
tests.append("}")
tests.append("")
tests.append("// ════════════════════════════════════════════════════════════════════════")
tests.append("// callback API")
tests.append("// ════════════════════════════════════════════════════════════════════════")
tests.append("")
tests.append("TEST_CASE(\"ZoteEngine: callback fires on detection\",")
tests.append("          \"[zote_engine][callback]\") {")
tests.append("    zote::ZoteEngine eng;")
tests.append("    eng.add_rule(make_rule(1, \"Rule\", \"exploit\"));")
tests.append("    int fired = 0;")
tests.append("    eng.process(make_signal(\"1.2.3.4\", \"exploit attempt\"),")
tests.append("        [&fired](const zote::DetectionResult&) { ++fired; });")
tests.append("    REQUIRE(fired == 1);")
tests.append("}")
tests.append("")
tests.append("// ════════════════════════════════════════════════════════════════════════")
tests.append("// batch processing")
tests.append("// ════════════════════════════════════════════════════════════════════════")
tests.append("")
tests.append("TEST_CASE(\"ZoteEngine: process_batch returns assessments\",")
tests.append("          \"[zote_engine][batch]\") {")
tests.append("    zote::ZoteEngine eng;")
tests.append("    eng.add_rule(make_rule(1, \"Rule\", \"malware\"));")
tests.append("    std::vector<zote::Signal> signals = {")
tests.append("        make_signal(\"1.2.3.4\", \"malware detected\"),")
tests.append("        make_signal(\"5.6.7.8\", \"clean traffic\"),")
tests.append("        make_signal(\"1.2.3.4\", \"malware spreading\"),")
tests.append("    };")
tests.append("    auto results = eng.process_batch(signals);")
tests.append("    REQUIRE(results.size() == 3);")
tests.append("}")
tests.append("")
tests.append("// ════════════════════════════════════════════════════════════════════════")
tests.append("// stats + observability")
tests.append("// ════════════════════════════════════════════════════════════════════════")
tests.append("")
tests.append("TEST_CASE(\"ZoteEngine: detection_stats tracks signals\",")
tests.append("          \"[zote_engine][stats]\") {")
tests.append("    zote::ZoteEngine eng;")
tests.append("    eng.add_rule(make_rule(1, \"Rule\", \"attack\"));")
tests.append("    eng.process(make_signal(\"1.2.3.4\", \"attack detected\"));")
tests.append("    eng.process(make_signal(\"1.2.3.4\", \"attack spreading\"));")
tests.append("    auto s = eng.detection_stats();")
tests.append("    REQUIRE(s.signals_processed >= 2);")
tests.append("}")
tests.append("")
tests.append("// ════════════════════════════════════════════════════════════════════════")
tests.append("// reset")
tests.append("// ════════════════════════════════════════════════════════════════════════")
tests.append("")
tests.append("TEST_CASE(\"ZoteEngine: reset clears state but keeps rules\",")
tests.append("          \"[zote_engine][reset]\") {")
tests.append("    zote::ZoteEngine eng;")
tests.append("    eng.add_rule(make_rule(1, \"Rule\", \"attack\"));")
tests.append("    eng.process(make_signal(\"1.2.3.4\", \"attack detected\"));")
tests.append("    eng.reset();")
tests.append("    REQUIRE(eng.rule_count() == 1);")
tests.append("    REQUIRE(eng.campaign_count() == 0);")
tests.append("}")
tests.append("")
tests.append("// ════════════════════════════════════════════════════════════════════════")
tests.append("// direct engine access")
tests.append("// ════════════════════════════════════════════════════════════════════════")
tests.append("")
tests.append("TEST_CASE(\"ZoteEngine: direct detection engine access\",")
tests.append("          \"[zote_engine][advanced]\") {")
tests.append("    zote::ZoteEngine eng;")
tests.append("    auto& det = eng.detection_engine();")
tests.append("    det.add_rule(make_rule(99, \"DirectRule\", \"direct\"));")
tests.append("    REQUIRE(eng.rule_count() == 1);")
tests.append("}")
tests.append("")

pathlib.Path("tests/unit/test_zote_engine.cpp").write_text(
    "\n".join(tests), encoding="utf-8")
print(f"OK -- tests/unit/test_zote_engine.cpp written ({len(tests)} lines)")

# ── Update CMakeLists.txt ─────────────────────────────────────────────────
p = pathlib.Path("CMakeLists.txt")
content = p.read_text()

# Add zote_engine.cpp to sources
content = content.replace(
    "    src/killchain.cpp\n    src/mitre_map.cpp\n    src/correlation.cpp",
    "    src/killchain.cpp\n    src/mitre_map.cpp\n    src/correlation.cpp\n    src/zote_engine.cpp"
)

# Add test_zote_engine.cpp to test sources
content = content.replace(
    "    tests/unit/test_correlation.cpp",
    "    tests/unit/test_correlation.cpp\n    tests/unit/test_zote_engine.cpp"
)

p.write_text(content)
print("OK -- CMakeLists.txt: zote_engine sources added")
