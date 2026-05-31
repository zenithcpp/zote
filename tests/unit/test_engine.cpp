// tests/unit/test_engine.cpp
// ZOTE — zenithcpp Open Source Threat Engine
// Detection engine unit tests

#include <catch2/catch_test_macros.hpp>
#include <zote/engine.hpp>
#include <zote/types.hpp>

// ─── Helpers ─────────────────────────────────────────────────────────────

static zote::DetectionRule make_rule(
    std::uint64_t id,
    const std::string& name,
    const std::string& pattern,
    zote::Severity sev = zote::Severity::Medium) {
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
    const std::string& desc,
    const std::string& cat = "") {
    zote::Signal s;
    s.net.src      = zote::IpAddress{std::string(src)};
    s.description  = desc;
    s.category_str = cat;
    return s;
}

// ════════════════════════════════════════════════════════════════════════
// Initialisation
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("Engine: initialises with zero rules and zero alerts",
          "[engine][init]") {
    zote::DetectionEngine eng;
    REQUIRE(eng.rule_count()  == 0);
    REQUIRE(eng.alert_count() == 0);
}

TEST_CASE("Engine: stats initialise to zero",
          "[engine][init]") {
    zote::DetectionEngine eng;
    auto s = eng.stats();
    REQUIRE(s.alerts_fired      == 0);
    REQUIRE(s.signals_processed == 0);
    REQUIRE(s.rules_loaded      == 0);
}

// ════════════════════════════════════════════════════════════════════════
// Rule management
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("Engine: add single rule increments count",
          "[engine][rules]") {
    zote::DetectionEngine eng;
    eng.add_rule(make_rule(1, "TestRule", "malware"));
    REQUIRE(eng.rule_count() == 1);
}

TEST_CASE("Engine: add duplicate ID replaces existing rule",
          "[engine][rules]") {
    zote::DetectionEngine eng;
    eng.add_rule(make_rule(1, "OldName", "pattern1"));
    eng.add_rule(make_rule(1, "NewName", "pattern2"));
    REQUIRE(eng.rule_count() == 1);
}

TEST_CASE("Engine: remove rule decrements count",
          "[engine][rules]") {
    zote::DetectionEngine eng;
    eng.add_rule(make_rule(99, "TempRule", "temp"));
    REQUIRE(eng.rule_count() == 1);
    eng.remove_rule(zote::RuleId{99});
    REQUIRE(eng.rule_count() == 0);
}

TEST_CASE("Engine: disabled rule does not fire",
          "[engine][rules]") {
    zote::DetectionEngine eng;
    eng.add_rule(make_rule(1, "DisabledRule", "attack"));
    eng.set_rule_enabled(zote::RuleId{1}, false);
    auto r = eng.evaluate(make_signal("1.2.3.4", "attack"));
    REQUIRE(r.empty());
}

TEST_CASE("Engine: has_rule returns true for existing rule",
          "[engine][rules]") {
    zote::DetectionEngine eng;
    eng.add_rule(make_rule(42, "Rule", "pattern"));
    REQUIRE(eng.has_rule(zote::RuleId{42}));
    REQUIRE(!eng.has_rule(zote::RuleId{99}));
}

TEST_CASE("Engine: get_rule returns rule for existing ID",
          "[engine][rules]") {
    zote::DetectionEngine eng;
    eng.add_rule(make_rule(7, "MyRule", "pattern"));
    auto r = eng.get_rule(zote::RuleId{7});
    REQUIRE(r.has_value());
    REQUIRE(r->name == "MyRule");
}

TEST_CASE("Engine: get_rule returns nullopt for missing ID",
          "[engine][rules]") {
    zote::DetectionEngine eng;
    auto r = eng.get_rule(zote::RuleId{999});
    REQUIRE(!r.has_value());
}

TEST_CASE("Engine: add_rules bulk loads multiple rules",
          "[engine][rules]") {
    zote::DetectionEngine eng;
    std::vector<zote::DetectionRule> rules = {
        make_rule(1, "Rule1", "pattern1"),
        make_rule(2, "Rule2", "pattern2"),
        make_rule(3, "Rule3", "pattern3"),
    };
    eng.add_rules(rules);
    REQUIRE(eng.rule_count() == 3);
}

// ════════════════════════════════════════════════════════════════════════
// Detection
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("Engine: signature matches description field",
          "[engine][detection]") {
    zote::DetectionEngine eng;
    eng.add_rule(make_rule(1, "MalwareRule", "malware",
                          zote::Severity::High));
    auto r = eng.evaluate(
        make_signal("1.2.3.4", "malware.exe detected"));
    REQUIRE(!r.empty());
    REQUIRE(r[0].matched);
    REQUIRE(r[0].rule_id == zote::RuleId{1});
    REQUIRE(r[0].severity == zote::Severity::High);
    REQUIRE(r[0].confidence > 0.0f);
}

TEST_CASE("Engine: detection result includes evidence",
          "[engine][detection]") {
    zote::DetectionEngine eng;
    eng.add_rule(make_rule(1, "Rule", "exploit"));
    auto r = eng.evaluate(
        make_signal("1.2.3.4", "exploit attempt detected"));
    REQUIRE(!r.empty());
    REQUIRE(!r[0].evidence.empty());
}

TEST_CASE("Engine: severity score computed on match",
          "[engine][detection]") {
    zote::DetectionEngine eng;
    eng.add_rule(make_rule(1, "Rule", "attack",
                          zote::Severity::Critical));
    auto r = eng.evaluate(make_signal("1.2.3.4", "attack"));
    REQUIRE(!r.empty());
    REQUIRE(r[0].severity_score > 0.0f);
}

TEST_CASE("Engine: signature matches category field",
          "[engine][detection]") {
    zote::DetectionEngine eng;
    eng.add_rule(make_rule(1, "TrojanRule", "trojan"));
    zote::Signal sig;
    sig.net.src  = zote::IpAddress{"1.2.3.4"};
    sig.category_str = "trojan.generic";
    auto r = eng.evaluate(sig);
    REQUIRE(!r.empty());
    REQUIRE(r[0].matched);
}

TEST_CASE("Engine: no match on unrelated signal",
          "[engine][detection]") {
    zote::DetectionEngine eng;
    eng.add_rule(make_rule(1, "MalwareRule", "malware"));
    auto r = eng.evaluate(
        make_signal("1.2.3.4", "normal web traffic", "info"));
    REQUIRE(r.empty());
}

TEST_CASE("Engine: case-insensitive pattern matching",
          "[engine][detection]") {
    zote::DetectionEngine eng;
    eng.add_rule(make_rule(1, "Rule", "MALWARE"));
    auto r = eng.evaluate(
        make_signal("1.2.3.4", "Malware.exe detected"));
    REQUIRE(!r.empty());
    REQUIRE(r[0].matched);
}

TEST_CASE("Engine: alert count increments on each match",
          "[engine][detection]") {
    zote::DetectionEngine eng;
    eng.add_rule(make_rule(1, "Rule", "attack"));
    static_cast<void>(eng.evaluate(make_signal("1.2.3.4", "attack")));
    static_cast<void>(eng.evaluate(make_signal("1.2.3.4", "attack")));
    REQUIRE(eng.alert_count() == 2);
}

TEST_CASE("Engine: condition-based rule matches correctly",
          "[engine][detection]") {
    zote::DetectionEngine eng;
    zote::DetectionRule rule;
    rule.id      = zote::RuleId{1};
    rule.type    = zote::RuleType::Signature;
    rule.name    = "ProcRule";
    rule.enabled = true;
    rule.conditions.push_back({
        "proc.name", zote::ConditionType::Contains,
        "netcat", 1.0f});
    eng.add_rule(rule);
    zote::Signal sig;
    sig.proc.process_name = "netcat";
    auto r = eng.evaluate(sig);
    REQUIRE(!r.empty());
    REQUIRE(r[0].matched);
    REQUIRE(r[0].confidence > 0.0f);
}

// ════════════════════════════════════════════════════════════════════════
// Threshold
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("Engine: threshold rule fires only after N matches",
          "[engine][threshold]") {
    zote::DetectionEngine eng;
    zote::DetectionRule rule = make_rule(1, "ScanRule", "scan");
    rule.type       = zote::RuleType::Threshold;
    rule.threshold  = 3;
    rule.window_sec = 60;
    eng.add_rule(rule);
    auto sig = make_signal("1.2.3.4", "port scan");
    REQUIRE(eng.evaluate(sig).empty());
    REQUIRE(eng.evaluate(sig).empty());
    auto r3 = eng.evaluate(sig);
    REQUIRE(!r3.empty());
    REQUIRE(r3[0].matched);
}

// ════════════════════════════════════════════════════════════════════════
// Whitelist
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("Engine: whitelisted IP suppresses all alerts",
          "[engine][whitelist]") {
    zote::DetectionEngine eng;
    eng.add_rule(make_rule(1, "Rule", "malware"));
    eng.whitelist_add("10.0.0.1");
    REQUIRE(eng.is_whitelisted("10.0.0.1"));
    auto r = eng.evaluate(
        make_signal("10.0.0.1", "malware detected"));
    REQUIRE(r.empty());
}

TEST_CASE("Engine: whitelist remove restores detection",
          "[engine][whitelist]") {
    zote::DetectionEngine eng;
    eng.add_rule(make_rule(1, "Rule", "attack"));
    eng.whitelist_add("10.0.0.1");
    eng.whitelist_remove("10.0.0.1");
    REQUIRE(!eng.is_whitelisted("10.0.0.1"));
    auto r = eng.evaluate(
        make_signal("10.0.0.1", "attack detected"));
    REQUIRE(!r.empty());
}

// ════════════════════════════════════════════════════════════════════════
// Suppression
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("Engine: suppressed IP produces no alerts",
          "[engine][suppression]") {
    zote::DetectionEngine eng;
    eng.add_rule(make_rule(1, "Rule", "attack"));
    eng.suppress_ip("5.6.7.8",
        std::chrono::seconds{3600});
    auto r = eng.evaluate(
        make_signal("5.6.7.8", "attack detected"));
    REQUIRE(r.empty());
}

TEST_CASE("Engine: suppressed rule ID produces no alerts",
          "[engine][suppression]") {
    zote::DetectionEngine eng;
    eng.add_rule(make_rule(42, "NoisyRule", "scan"));
    eng.suppress_rule(zote::RuleId{42},
        std::chrono::seconds{3600});
    auto r = eng.evaluate(
        make_signal("1.2.3.4", "port scan"));
    REQUIRE(r.empty());
}

// ════════════════════════════════════════════════════════════════════════
// False positive score
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("Engine: high FP score suppresses rule",
          "[engine][fp]") {
    zote::DetectionEngine eng;
    eng.add_rule(make_rule(1, "NoisyRule", "scan"));
    eng.set_fp_score(zote::RuleId{1}, 0.9f);
    auto r = eng.evaluate(
        make_signal("1.2.3.4", "port scan"));
    REQUIRE(r.empty());
}

// ════════════════════════════════════════════════════════════════════════
// test_rule — no side effects
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("Engine: test_rule returns result on match",
          "[engine][test_rule]") {
    zote::DetectionEngine eng;
    auto rule = make_rule(1, "Rule", "exploit");
    auto sig  = make_signal("1.2.3.4", "exploit attempt");
    auto r = eng.test_rule(rule, sig);
    REQUIRE(r.has_value());
    REQUIRE(r->matched);
    REQUIRE(eng.alert_count() == 0);
}

TEST_CASE("Engine: test_rule returns nullopt on no match",
          "[engine][test_rule]") {
    zote::DetectionEngine eng;
    auto rule = make_rule(1, "Rule", "exploit");
    auto sig  = make_signal("1.2.3.4", "normal traffic");
    auto r = eng.test_rule(rule, sig);
    REQUIRE(!r.has_value());
}

// ════════════════════════════════════════════════════════════════════════
// YARA
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("Engine: YARA hex pattern matches raw field",
          "[engine][yara]") {
    zote::DetectionEngine eng;
    eng.add_yara_rule("PEHeader", "4d 5a", zote::Severity::High);
    zote::Signal sig;
    sig.raw = "4d 5a 90 00 03 00";
    auto r = eng.evaluate(sig);
    REQUIRE(!r.empty());
    REQUIRE(r[0].matched);
    REQUIRE(r[0].confidence >= 0.9f);
}

// ════════════════════════════════════════════════════════════════════════
// Reset and clear
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("Engine: reset clears counters but keeps rules",
          "[engine][reset]") {
    zote::DetectionEngine eng;
    eng.add_rule(make_rule(1, "Rule", "attack"));
    static_cast<void>(eng.evaluate(make_signal("1.2.3.4", "attack")));
    eng.reset();
    REQUIRE(eng.alert_count() == 0);
    REQUIRE(eng.rule_count()  == 1);
}

TEST_CASE("Engine: clear removes rules and counters",
          "[engine][reset]") {
    zote::DetectionEngine eng;
    eng.add_rule(make_rule(1, "Rule", "attack"));
    eng.clear();
    REQUIRE(eng.rule_count()  == 0);
    REQUIRE(eng.alert_count() == 0);
}

// ════════════════════════════════════════════════════════════════════════
// severity_score() centralized helper
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("severity_score: Info maps to 1.0",
          "[types][severity]") {
    REQUIRE(zote::severity_score(zote::Severity::Info)     == 1.0f);
}

TEST_CASE("severity_score: Critical maps to 10.0",
          "[types][severity]") {
    REQUIRE(zote::severity_score(zote::Severity::Critical) == 10.0f);
}

TEST_CASE("severity_score: scores are monotonically increasing",
          "[types][severity]") {
    REQUIRE(zote::severity_score(zote::Severity::Info)   <
            zote::severity_score(zote::Severity::Low));
    REQUIRE(zote::severity_score(zote::Severity::Low)    <
            zote::severity_score(zote::Severity::Medium));
    REQUIRE(zote::severity_score(zote::Severity::Medium) <
            zote::severity_score(zote::Severity::High));
    REQUIRE(zote::severity_score(zote::Severity::High)   <
            zote::severity_score(zote::Severity::Critical));
}

// ════════════════════════════════════════════════════════════════════════
// DetectionResult timestamp
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("Engine: matched result has non-zero timestamp",
          "[engine][result]") {
    zote::DetectionEngine eng;
    eng.add_rule(make_rule(1, "Rule", "attack"));
    auto results = eng.evaluate(make_signal("1.2.3.4", "attack"));
    REQUIRE(!results.empty());
    REQUIRE(results[0].timestamp_us > 0);
}

// ════════════════════════════════════════════════════════════════════════
// Rule tags
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("Engine: rule tags stored and retrievable",
          "[engine][tags]") {
    zote::DetectionEngine eng;
    auto rule = make_rule(1, "Rule", "attack");
    rule.tags = {"lateral-movement", "windows", "credential-access"};
    eng.add_rule(rule);
    auto r = eng.get_rule(zote::RuleId{1});
    REQUIRE(r.has_value());
    REQUIRE(r->tags.size() == 3);
    REQUIRE(r->tags[0] == "lateral-movement");
}

// ════════════════════════════════════════════════════════════════════════
// TechniqueId view() and string_view conversion
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("TechniqueId: view() returns string_view",
          "[types][id]") {
    zote::TechniqueId tid{"T1566"};
    REQUIRE(tid.view() == "T1566");
}

TEST_CASE("TechniqueId: operator string_view conversion",
          "[types][id]") {
    zote::TechniqueId tid{"T1486"};
    std::string_view sv = static_cast<std::string_view>(tid);
    REQUIRE(sv == "T1486");
}

// ════════════════════════════════════════════════════════════════════════
// version() query
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("version: returns valid version struct",
          "[types][version]") {
    auto v = zote::version();
    REQUIRE(v.major == 0);
    REQUIRE(v.minor == 1);
    REQUIRE(v.patch == 0);
    REQUIRE(v.to_string() == "0.1.0");
}

// ════════════════════════════════════════════════════════════════════════
// IpAddress::is_private() — no-throw validation
// ════════════════════════════════════════════════════════════════════════

TEST_CASE("IpAddress: is_private detects RFC1918 ranges",
          "[types][ip]") {
    REQUIRE(zote::IpAddress{std::string("10.0.0.1")}.is_private());
    REQUIRE(zote::IpAddress{std::string("192.168.1.1")}.is_private());
    REQUIRE(zote::IpAddress{std::string("172.16.0.1")}.is_private());
    REQUIRE(zote::IpAddress{std::string("172.31.255.254")}.is_private());
    REQUIRE(!zote::IpAddress{std::string("172.32.0.1")}.is_private());
    REQUIRE(!zote::IpAddress{std::string("8.8.8.8")}.is_private());
}

TEST_CASE("IpAddress: is_loopback detects loopback",
          "[types][ip]") {
    REQUIRE(zote::IpAddress{std::string("127.0.0.1")}.is_loopback());
    REQUIRE(zote::IpAddress{std::string("::1")}.is_loopback());
    REQUIRE(!zote::IpAddress{std::string("10.0.0.1")}.is_loopback());
}

TEST_CASE("IpAddress: is_valid accepts valid IPv4",
          "[types][ip]") {
    REQUIRE(zote::IpAddress{std::string("1.2.3.4")}.is_valid());
    REQUIRE(zote::IpAddress{std::string("255.255.255.255")}.is_valid());
    REQUIRE(!zote::IpAddress{std::string("999.0.0.1")}.is_valid());
    REQUIRE(!zote::IpAddress{std::string("not-an-ip")}.is_valid());
}
