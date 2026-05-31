#pragma once
// include/zote/types.hpp
// ZOTE — zenithcpp Open Source Threat Engine
// ISO C++23 compliant — zero external dependencies
// Apache 2.0 License — https://github.com/zenithcpp/zote
//
// This header is the single source of truth for all
// shared types across the ZOTE engine. Every other
// header depends on this file and nothing else.
//
// Dependency order:
//   types.hpp
//     ← killchain.hpp
//     ← mitre.hpp
//     ← engine.hpp  (also depends on killchain.hpp)
//     ← correlation.hpp (depends on all above)

#include <array>
#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace zote {

// ═══════════════════════════════════════════════════════════════════════
// SECTION 1 — VERSION
// ═══════════════════════════════════════════════════════════════════════

struct Version {
    std::uint32_t major = 0;
    std::uint32_t minor = 1;
    std::uint32_t patch = 0;
    [[nodiscard]] std::string to_string() const {
        return std::to_string(major) + '.' +
               std::to_string(minor) + '.' +
               std::to_string(patch);
    }
};
inline constexpr Version ZOTE_VERSION{0, 1, 0};

// ═══════════════════════════════════════════════════════════════════════
// SECTION 2 — ERROR MODEL
// std::expected<T, ZoteError> — explicit error propagation.
// No exceptions. Errors are part of every fallible API signature.
// ═══════════════════════════════════════════════════════════════════════

enum class ZoteError : std::uint8_t {
    InvalidIp,            // Malformed IP address string
    InvalidMitreId,       // Malformed technique ID
    InvalidPattern,       // Malformed detection pattern
    RuleNotFound,         // Rule ID does not exist
    CampaignNotFound,     // Campaign ID does not exist
    CampaignLimitReached, // max_campaigns config exceeded
    AlertLimitReached,    // max_alerts config exceeded
    ParseError,           // Failed to parse rule/sigma/suricata file
    IoError,              // File read/write failure
    InvalidArgument,      // General invalid argument
};

// Convenience alias — use throughout ZOTE public API
template<typename T>
#if defined(__cpp_lib_expected) && __cpp_lib_expected >= 202211L
using Result = std::expected<T, ZoteError>;
#endif

// ═══════════════════════════════════════════════════════════════════════
// SECTION 3 — STRONG ID TYPES
// Prevent ID confusion across API boundaries.
// Each ID type is distinct — compiler enforces correct usage.
// ═══════════════════════════════════════════════════════════════════════

struct RuleId {
    std::uint64_t value = 0;
    auto operator<=>(const RuleId&) const noexcept = default;
};

struct CampaignId {
    std::uint64_t value = 0;
    auto operator<=>(const CampaignId&) const noexcept = default;
};

struct AlertId {
    std::uint64_t value = 0;
    auto operator<=>(const AlertId&) const noexcept = default;
};

struct TechniqueId {
    std::string value;
    [[nodiscard]] bool empty() const noexcept { return value.empty(); }
    [[nodiscard]] std::string_view view() const noexcept { return value; }
    explicit operator std::string_view() const noexcept { return value; }
    auto operator<=>(const TechniqueId&) const noexcept = default;
};

struct ActorId {
    std::string value;
    [[nodiscard]] bool empty() const noexcept { return value.empty(); }
    [[nodiscard]] std::string_view view() const noexcept { return value; }
    explicit operator std::string_view() const noexcept { return value; }
    auto operator<=>(const ActorId&) const noexcept = default;
};

struct SoftwareId {
    std::string value;
    [[nodiscard]] bool empty() const noexcept { return value.empty(); }
    [[nodiscard]] std::string_view view() const noexcept { return value; }
    explicit operator std::string_view() const noexcept { return value; }
    auto operator<=>(const SoftwareId&) const noexcept = default;
};

struct ServiceId {
    std::string value;
    [[nodiscard]] bool empty() const noexcept { return value.empty(); }
    [[nodiscard]] std::string_view view() const noexcept { return value; }
    explicit operator std::string_view() const noexcept { return value; }
    auto operator<=>(const ServiceId&) const noexcept = default;
};

// ═══════════════════════════════════════════════════════════════════════
// SECTION 4 — IP ADDRESS
// String-based with validation. Suitable for a correlation engine
// where IPs arrive as strings from logs, rules, and signals.
// Upgrade to binary representation in v1.0 if benchmarks demand it.
// ═══════════════════════════════════════════════════════════════════════

struct IpAddress {
    std::string value;

    IpAddress() noexcept = default;
    explicit IpAddress(std::string v) noexcept
        : value(std::move(v)) {}
    // Construct from string_view via explicit conversion
    static IpAddress from_view(std::string_view v) { return IpAddress{std::string(v)}; }

    // Returns true if value is a valid IPv4 address.
    [[nodiscard]] bool is_ipv4() const noexcept;

    // Returns true if value is a valid IPv6 address.
    [[nodiscard]] bool is_ipv6() const noexcept;

    // Returns true if IPv4 or IPv6.
    [[nodiscard]] bool is_valid() const noexcept {
        return is_ipv4() || is_ipv6();
    }

    // Returns true if RFC1918 private address.
    [[nodiscard]] bool is_private() const noexcept;

    // Returns true if loopback (127.x.x.x or ::1).
    [[nodiscard]] bool is_loopback() const noexcept;

    [[nodiscard]] bool empty() const noexcept { return value.empty(); }

    auto operator<=>(const IpAddress&) const noexcept = default;
};

// ═══════════════════════════════════════════════════════════════════════
// SECTION 5 — SEVERITY
// ═══════════════════════════════════════════════════════════════════════

enum class Severity : std::uint8_t {
    Info     = 0,
    Low      = 1,
    Medium   = 2,
    High     = 3,
    Critical = 4,
};

// Centralized severity → float score mapping (0.0-10.0).
// Use this everywhere instead of duplicating the mapping.
// Info=1.0, Low=3.0, Medium=5.0, High=8.0, Critical=10.0
[[nodiscard]] inline constexpr float
severity_score(Severity s) noexcept {
    switch (s) {
    case Severity::Info:     return 1.0f;
    case Severity::Low:      return 3.0f;
    case Severity::Medium:   return 5.0f;
    case Severity::High:     return 8.0f;
    case Severity::Critical: return 10.0f;
    }
    return 0.0f;
}

[[nodiscard]] inline constexpr const char*
severity_name(Severity s) noexcept {
    switch (s) {
    case Severity::Info:     return "Info";
    case Severity::Low:      return "Low";
    case Severity::Medium:   return "Medium";
    case Severity::High:     return "High";
    case Severity::Critical: return "Critical";
    }
    return "Unknown";
}

// ═══════════════════════════════════════════════════════════════════════
// SECTION 5b — SIGNAL ENUMS
// Strong enum types for high-frequency signal fields.
// Replaces string comparisons in the hot evaluation path.
// At 100k+ EPS, string hashing per rule per signal is a bottleneck.
// These enums allow O(1) integer comparison.
// ═══════════════════════════════════════════════════════════════════════

// Signal source category — what kind of event generated this signal.
enum class SignalCategory : std::uint8_t {
    Unknown         = 0,
    NetworkIntrusion,   // IDS/IPS alert
    MalwareDetected,    // AV/EDR detection
    PolicyViolation,    // DLP/firewall policy
    Authentication,     // Auth success/fail
    ProcessExecution,   // Process launch event
    FileActivity,       // File create/modify/delete
    RegistryActivity,   // Registry change (Windows)
    NetworkScan,        // Port/host scan
    DataExfiltration,   // Data leaving network
    LateralMovement,    // Internal lateral move
    CommandControl,     // C2 beacon/communication
    Exploitation,       // Exploit attempt
    Reconnaissance,     // Recon activity
    Custom          = 255,
};

// Network protocol for NetworkContext.
enum class Protocol : std::uint8_t {
    Unknown = 0,
    TCP, UDP, ICMP,
    HTTP, HTTPS, DNS, FTP, SSH,
    SMB, RDP, LDAP, SMTP, SNMP,
    Custom = 255,
};

// Traffic direction.
enum class Direction : std::uint8_t {
    Unknown  = 0,
    Inbound,
    Outbound,
    Internal, // East-west
    Custom   = 255,
};

// ═══════════════════════════════════════════════════════════════════════
// SECTION 6 — KILL CHAIN
// ═══════════════════════════════════════════════════════════════════════

// Lockheed Martin 7-stage Cyber Kill Chain
enum class KillChainStage : std::uint8_t {
    Reconnaissance = 0,
    Weaponization  = 1,
    Delivery       = 2,
    Exploitation   = 3,
    Installation   = 4,
    CommandControl = 5,
    ActionsOnObj   = 6,
    Unknown        = 7,
};

// Kill chain framework selection
enum class Framework : std::uint8_t {
    LockheedMartin,   // 7-stage (default)
    UnifiedKillChain, // 18-phase
    MITRE,            // Tactic-based (TA00xx)
};

// Evidence item — explains WHY a detection fired
struct Evidence {
    std::string field;   // e.g. "description", "category", "mitre_id"
    std::string value;   // e.g. "beacon", "T1071"
    float       weight;  // 0.0-1.0 contribution to confidence
};

// Kill chain reason — evidence for stage mapping
struct KillChainReason {
    std::string field;        // Field that triggered mapping
    std::string match;        // Keyword or ID that matched
    float       weight;       // 0.0-1.0 importance of this feature
    float       contribution; // Actual contribution to final confidence
};

// A candidate stage with its confidence score.
// KillChainAssessment may contain multiple candidates
// when a signal spans multiple kill chain stages.
// e.g. T1566.001 (Spearphishing Attachment) spans
//      both Delivery and Exploitation.
struct StageConfidence {
    KillChainStage stage      = KillChainStage::Unknown;
    float          confidence = 0.0f; // 0.0-1.0
};

// Kill chain assessment — replaces raw KillChainStage return
//
// primary stage + confidence: highest-confidence stage.
// candidates: ALL matching stages with individual confidence.
//   A signal may span multiple stages simultaneously.
//   e.g. phishing with payload = Delivery + Exploitation.
// reasons: evidence explaining the primary stage mapping.
struct KillChainAssessment {
    KillChainStage               stage      = KillChainStage::Unknown;
    float                        confidence = 0.0f; // 0.0-1.0
    std::vector<KillChainReason> reasons;
    std::vector<StageConfidence> candidates; // All matching stages
};

// Kill chain progression — per campaign
struct KillChainProgress {
    float          completion     = 0.0f; // 0.0-1.0
    KillChainStage furthest_stage = KillChainStage::Unknown;
    std::vector<KillChainStage> observed_stages;
};

// ATT&CK coverage report — per campaign
struct AttackCoverage {
    std::vector<std::string> observed_tactics;
    std::vector<std::string> observed_techniques;
};

// ═══════════════════════════════════════════════════════════════════════
// SECTION 7 — SIGNAL (STRUCTURED)
// Flat Signal replaced with structured contexts.
// NetworkContext and ProcessContext group related fields.
// Rules can target specific contexts for precise matching.
// ═══════════════════════════════════════════════════════════════════════

struct NetworkContext {
    IpAddress      src;
    IpAddress      dst;
    std::uint16_t  src_port  = 0;
    std::uint16_t  dst_port  = 0;
    Protocol       protocol  = Protocol::Unknown;
    Direction      direction = Direction::Unknown;
    // String overrides — set when protocol/direction not in enum.
    // If protocol != Unknown, protocol_str is ignored.
    std::string    protocol_str;
    std::string    direction_str;
};

struct ProcessContext {
    std::string    process_name;
    std::string    file_path;
    std::string    cmdline;
    std::string    username;
    std::uint32_t  pid  = 0;
    std::uint32_t  ppid = 0;
    std::string    parent_name;
};

struct Signal {
    NetworkContext net;
    ProcessContext proc;

    std::string    description;
    SignalCategory category     = SignalCategory::Unknown;
    std::string    category_str; // Free-form override when category=Custom
    std::string    detection_rule; // Rule or signature that fired
    TechniqueId    mitre_id;       // Known technique if available
    std::string    raw;            // Raw log line or event

    Severity       severity     = Severity::Medium;
    std::uint64_t  timestamp_us = 0; // 0 = use current time
};

// ═══════════════════════════════════════════════════════════════════════
// SECTION 8 — DETECTION RULE (STRUCTURED)
// RuleCondition replaces single pattern string.
// Multiple conditions with different match types per rule.
// ═══════════════════════════════════════════════════════════════════════

enum class RuleType : std::uint8_t {
    Signature   = 0, // Pattern match on signal fields
    Threshold   = 1, // Count-based trigger (N events in T seconds)
    Behavioral  = 2, // Category + threshold combination
    Sigma       = 3, // Sigma YAML rule reference
    Yara        = 4, // Hex byte pattern match
    Suricata    = 5, // Suricata SID reference
    Whitelist   = 6, // Suppress matching signals
};

enum class ConditionType : std::uint8_t {
    Contains,   // Field contains substring (case-insensitive)
    Equals,     // Field equals value exactly
    StartsWith, // Field starts with value
    EndsWith,   // Field ends with value
    Threshold,  // Count-based: fires after N matches in window
};

// A single condition within a detection rule.
// Field names: "description", "category", "net.src",
//   "net.dst", "proc.name", "proc.cmdline", "raw"
struct RuleCondition {
    std::string   field;   // Which signal field to inspect
    ConditionType type     = ConditionType::Contains;
    std::string   value;   // Pattern or threshold count (as string)
    float         weight   = 1.0f; // Contribution to confidence
};

struct DetectionRule {
    RuleId       id;
    RuleType     type        = RuleType::Signature;
    std::string  name;
    std::string  description;
    std::string  author;
    TechniqueId  mitre_id;
    Severity     severity    = Severity::Medium;
    float        fp_score    = 0.0f;  // 0.0-1.0 false positive score
    std::uint32_t threshold  = 0;     // Count trigger (0 = disabled)
    std::uint32_t window_sec = 60;    // Threshold time window
    bool         enabled     = true;

    // Structured conditions (preferred over legacy pattern)
    std::vector<RuleCondition> conditions;

    // Legacy single pattern — supported for backward compatibility
    // and simple signature rules. If conditions is non-empty,
    // conditions takes precedence.
    std::string  pattern;
    std::string  hex_pattern; // YARA-like hex bytes

    // Tags for filtering, reporting, and Navigator exports.
    // e.g. "credential-access", "lateral-movement", "windows"
    std::vector<std::string> tags;
};

// ═══════════════════════════════════════════════════════════════════════
// SECTION 9 — DETECTION RESULT (EVIDENCE-BASED)
// Every result carries evidence explaining WHY it fired.
// confidence replaces binary bool matched.
// matched kept for backward compatibility — true if confidence > 0.
// ═══════════════════════════════════════════════════════════════════════

struct DetectionResult {
    RuleId                  rule_id;
    std::string             rule_name;
    TechniqueId             mitre_id;
    Severity                severity       = Severity::Medium;
    KillChainStage          kill_chain     = KillChainStage::Unknown;
    float                   confidence     = 0.0f; // 0.0-1.0
    float                   severity_score = 0.0f; // 0.0-10.0
    bool                    matched        = false;
    std::uint64_t           timestamp_us   = 0;    // set on match
    std::string             description;
    std::vector<Evidence>   evidence;   // WHY it matched
};

// ═══════════════════════════════════════════════════════════════════════
// SECTION 10 — RISK AND ATTRIBUTION
// Explainable risk scoring — analysts must understand why.
// Attribution always carries confidence — never return actor without it.
// ═══════════════════════════════════════════════════════════════════════

struct RiskAssessment {
    float                       score      = 0.0f; // 0.0-10.0
    float                       confidence = 0.0f; // 0.0-1.0
    std::vector<std::string>    reasons;   // Human-readable factors
    std::vector<DetectionResult> evidence; // Supporting detections
};

struct Attribution {
    ActorId                     actor;
    float                       confidence        = 0.0f; // 0.0-1.0
    std::vector<TechniqueId>    matched_techniques;
    std::vector<std::string>    reasons;
};

// ═══════════════════════════════════════════════════════════════════════
// SECTION 11 — CAMPAIGN PRIMITIVES
// ═══════════════════════════════════════════════════════════════════════

enum class CampaignState : std::uint8_t {
    Active,   // Activity within retention window
    Dormant,  // No activity but not yet expired
    Closed,   // Manually closed or expired
};

// A single event in the campaign attack timeline
struct TimelineEvent {
    std::uint64_t  timestamp_us = 0;
    KillChainStage stage        = KillChainStage::Unknown;
    TechniqueId    technique;
    std::string    description;
    IpAddress      src_ip;
    Severity       severity     = Severity::Medium;
};

// Correlation window config — for event stream correlation
struct EventCorrelation {
    std::uint64_t  window_sec   = 300;  // 5 minutes default
    std::uint32_t  min_events   = 2;    // Minimum to form campaign
    std::string    grouping_key;        // "src_ip", "mitre_id", etc.
};

// Unified threat assessment — everything in one object
struct ThreatAssessment {
    RiskAssessment              risk;
    Attribution                 attribution;
    KillChainProgress           kill_chain;
    AttackCoverage              coverage;
    std::vector<TimelineEvent>  timeline;
    std::vector<std::string>    recommendations;
};

// ═══════════════════════════════════════════════════════════════════════
// SECTION 12 — MITRE QUERY SYSTEM
// ═══════════════════════════════════════════════════════════════════════

// Forward declaration for TechniqueRef
struct MitreTechnique;

// Safe reference to a technique in the database
using TechniqueRef = std::reference_wrapper<const MitreTechnique>;

// Composable query — replaces individual by_actor/by_software functions
struct MitreQuery {
    std::optional<ActorId>    actor;
    std::optional<SoftwareId> software;
    std::optional<ServiceId>  service;
    std::optional<std::string> tactic;
    std::optional<Severity>   min_severity;
    std::optional<std::string> platform; // "Linux", "Windows", "ICS"
};

// ATT&CK Navigator export structures
struct NavigatorEntry {
    TechniqueId  technique_id;
    float        score     = 1.0f;
    std::string  color;    // hex color e.g. "#ff6666"
    std::string  comment;
};

struct NavigatorLayer {
    std::string                 name;
    std::string                 domain    = "enterprise-attack";
    std::string                 version   = "14";
    std::vector<NavigatorEntry> techniques;

    // Serialize to ATT&CK Navigator JSON string.
    [[nodiscard]] std::string to_json() const;
};

// ═══════════════════════════════════════════════════════════════════════
// SECTION 13 — ENGINE CONFIGURATION
// Never hardcode operational limits — always configurable.
// ═══════════════════════════════════════════════════════════════════════

struct DetectionEngineConfig {
    float         fp_threshold     = 0.80f; // FP score above this suppresses rule
    bool          enable_sigma     = true;
    bool          enable_suricata  = true;
    bool          enable_yara      = true;
    std::uint32_t max_rules        = 100000;
    std::uint32_t max_suppressed   = 10000;
};

struct CorrelationConfig {
    std::uint32_t max_campaigns      = 10000;
    std::uint32_t max_alerts         = 100000;
    std::uint32_t max_ueba_entities  = 50000;  // Max IP profiles tracked
    std::uint32_t retention_sec      = 604800; // 7 days
    std::uint32_t campaign_age_sec   = 86400;  // 1 day dormant threshold
    std::uint32_t ueba_window_sec    = 86400;  // 24h UEBA window
    float         anomaly_threshold  = 5.0f;   // UEBA anomaly score
};

// ═══════════════════════════════════════════════════════════════════════
// SECTION 14 — STATISTICS AND OBSERVABILITY
// ═══════════════════════════════════════════════════════════════════════

struct EngineStats {
    std::uint64_t signals_processed = 0;
    std::uint64_t alerts_fired      = 0;
    std::uint64_t alerts_suppressed = 0;
    std::uint64_t rules_matched     = 0;
    std::size_t   rules_loaded      = 0;
};

struct CorrelationStats {
    std::uint64_t alerts_ingested   = 0;
    std::uint64_t campaigns_created = 0;
    std::uint64_t campaigns_closed  = 0;
    std::uint64_t actors_attributed = 0;
};

// ═══════════════════════════════════════════════════════════════════════
// SECTION 15 — CALLBACKS
// ═══════════════════════════════════════════════════════════════════════

using AlertCallback  = std::function<void(const DetectionResult&)>;
using SignalCallback = std::function<void(const Signal&)>;

// ═══════════════════════════════════════════════════════════════════════
// SECTION 16 — IpAddress INLINE IMPLEMENTATION
// Kept inline to avoid a separate compilation unit for a simple type.
// ═══════════════════════════════════════════════════════════════════════

inline bool IpAddress::is_ipv4() const noexcept {
    if (value.empty()) return false;
    // Must have exactly 3 dots and only digits
    int dots = 0;
    int octet = 0;
    int octet_len = 0;
    for (const char c : value) {
        if (c == '.') {
            if (octet_len == 0 || octet > 255) return false;
            ++dots;
            octet = 0;
            octet_len = 0;
        } else if (c >= '0' && c <= '9') {
            octet = octet * 10 + (c - '0');
            ++octet_len;
            if (octet_len > 3) return false;
        } else {
            return false;
        }
    }
    return dots == 3 && octet_len > 0 && octet <= 255;
}

inline bool IpAddress::is_ipv6() const noexcept {
    if (value.empty()) return false;
    // Minimal check: contains ':' and only hex digits and colons
    bool has_colon = false;
    for (const char c : value) {
        if (c == ':') { has_colon = true; continue; }
        if ((c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F')) continue;
        return false;
    }
    return has_colon;
}

inline bool IpAddress::is_private() const noexcept {
    if (!is_ipv4()) return false;
    // RFC1918: 10.x, 172.16-31.x, 192.168.x
    if (value.rfind("10.", 0) == 0) return true;
    if (value.rfind("192.168.", 0) == 0) return true;
    if (value.rfind("172.", 0) == 0) {
        // Manual octet parse — no stoi() to avoid throw in noexcept
        const auto dot2 = value.find('.', 4);
        if (dot2 != std::string::npos) {
            int oct = 0;
            for (std::size_t i = 4; i < dot2; ++i) {
                const char c = value[i];
                if (c < '0' || c > '9') return false;
                oct = oct * 10 + (c - '0');
                if (oct > 255) return false;
            }
            if (oct >= 16 && oct <= 31) return true;
        }
    }
    return false;
}

inline bool IpAddress::is_loopback() const noexcept {
    if (value == "::1") return true;
    return value.rfind("127.", 0) == 0;
}

// ═══════════════════════════════════════════════════════════════════════
// SECTION 17 — NavigatorLayer::to_json INLINE IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════

inline std::string NavigatorLayer::to_json() const {
    std::string j;
    j += '{';
    j += "\"name\":\"" + name + "\",";
    j += "\"versions\":{\"attack\":\"" + version + "\",";
    j += "\"navigator\":\"4.9\"},";
    j += "\"domain\":\"" + domain + "\",";
    j += "\"techniques\":[";
    bool first = true;
    for (const auto& e : techniques) {
        if (!first) j += ',';
        first = false;
        j += "{\"techniqueID\":\"" + e.technique_id.value + "\"";
        j += ",\"score\":" + std::to_string(static_cast<int>(e.score));
        if (!e.color.empty())
            j += ",\"color\":\"" + e.color + "\"";
        if (!e.comment.empty())
            j += ",\"comment\":\"" + e.comment + "\"";
        j += '}';
    }
    j += "]}";
    return j;
}


// ═══════════════════════════════════════════════════════════════════════
// SECTION 18 — CONFIDENCE NORMALIZATION
// Combines confidence scores from multiple engines into a single
// normalized score. All engines use 0.0-1.0 range.
//
// Formula:
//   combined = (w_det × detection + w_ueba × ueba + w_kc × kill_chain)
//              / (w_det + w_ueba + w_kc)
//
// Default weights reflect typical SOC signal reliability:
//   Detection engine:  0.50  (rule match — strong signal)
//   UEBA anomaly:      0.30  (behavioral — context signal)
//   Kill chain:        0.20  (stage inference — supporting signal)
//
// Usage:
//   float combined = ConfidenceNormalizer::combine(det, ueba, kc);
//   float custom   = ConfidenceNormalizer::combine(det, ueba, kc,
//                       0.6f, 0.2f, 0.2f);
// ═══════════════════════════════════════════════════════════════════════

struct ConfidenceNormalizer {
    // Combine three confidence scores with default SOC weights.
    [[nodiscard]] static float
    combine(float detection_conf,
            float ueba_conf,
            float kill_chain_conf) noexcept {
        constexpr float w_det  = 0.50f;
        constexpr float w_ueba = 0.30f;
        constexpr float w_kc   = 0.20f;
        return combine(detection_conf, ueba_conf, kill_chain_conf,
                       w_det, w_ueba, w_kc);
    }

    // Combine with custom weights.
    // Weights are normalized internally — they do not need to sum to 1.
    [[nodiscard]] static float
    combine(float detection_conf,
            float ueba_conf,
            float kill_chain_conf,
            float w_detection,
            float w_ueba,
            float w_kill_chain) noexcept {
        const float total = w_detection + w_ueba + w_kill_chain;
        if (total <= 0.0f) return 0.0f;
        float result = (w_detection  * detection_conf  +
                        w_ueba       * ueba_conf        +
                        w_kill_chain * kill_chain_conf) / total;
        // Clamp to [0.0, 1.0]
        if (result < 0.0f) return 0.0f;
        if (result > 1.0f) return 1.0f;
        return result;
    }

    // Combine detection + kill chain only (no UEBA available).
    [[nodiscard]] static float
    combine_det_kc(float detection_conf,
                   float kill_chain_conf) noexcept {
        return combine(detection_conf, 0.0f, kill_chain_conf,
                       0.70f, 0.0f, 0.30f);
    }

    // Combine detection + UEBA only (no kill chain mapping).
    [[nodiscard]] static float
    combine_det_ueba(float detection_conf,
                     float ueba_conf) noexcept {
        return combine(detection_conf, ueba_conf, 0.0f,
                       0.60f, 0.40f, 0.0f);
    }
};

// Convenience: API version query.
// Prefer this over accessing ZOTE_VERSION directly.
[[nodiscard]] inline constexpr Version version() noexcept {
    return ZOTE_VERSION;
}

// ═══════════════════════════════════════════════════════════════════════
// SECTION 19 — CONFIDENCE MODEL VERSIONING
// Versioned confidence weights — prevents silent breaking changes
// when weights are tuned. Callers can check version to detect changes.
// ═══════════════════════════════════════════════════════════════════════

struct ConfidenceModel {
    float         w_detection  = 0.50f; // DetectionEngine weight
    float         w_ueba       = 0.30f; // UEBA anomaly weight
    float         w_kill_chain = 0.20f; // Kill chain inference weight
    std::uint32_t version      = 1;     // Increment when weights change

    // Apply this model to three confidence scores.
    [[nodiscard]] float apply(float detection_conf,
                              float ueba_conf,
                              float kill_chain_conf) const noexcept {
        return ConfidenceNormalizer::combine(
            detection_conf, ueba_conf, kill_chain_conf,
            w_detection, w_ueba, w_kill_chain);
    }
};

// Default confidence model — v1 weights.
inline constexpr ConfidenceModel DEFAULT_CONFIDENCE_MODEL{};

} // namespace zote
