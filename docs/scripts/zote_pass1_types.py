#!/usr/bin/env python3
# zote_pass1_types.py
# Run from ~/Desktop/ZOTE/
# Pass 1: types.hpp — SignalCategory, Protocol, Direction enums
#          ConfidenceModel versioning, Signal enum fields

import pathlib

p = pathlib.Path("include/zote/types.hpp")
content = p.read_text()

# ── Add SignalCategory, Protocol, Direction enums after Severity ──────────
content = content.replace(
"""// ═══════════════════════════════════════════════════════════════════════
// SECTION 6 — KILL CHAIN""",
"""// ═══════════════════════════════════════════════════════════════════════
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
// SECTION 6 — KILL CHAIN""")

# ── Update NetworkContext to use Protocol + Direction enums ───────────────
content = content.replace(
"""struct NetworkContext {
    IpAddress      src;
    IpAddress      dst;
    std::uint16_t  src_port  = 0;
    std::uint16_t  dst_port  = 0;
    std::string    protocol; // "tcp", "udp", "icmp"
    std::string    direction; // "inbound", "outbound", "internal"
};""",
"""struct NetworkContext {
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
};""")

# ── Update Signal to use SignalCategory enum ──────────────────────────────
content = content.replace(
"""struct Signal {
    NetworkContext net;
    ProcessContext proc;

    std::string    description;
    std::string    category;
    std::string    detection_rule; // Rule or signature that fired
    TechniqueId    mitre_id;       // Known technique if available
    std::string    raw;            // Raw log line or event

    Severity       severity     = Severity::Medium;
    std::uint64_t  timestamp_us = 0; // 0 = use current time
};""",
"""struct Signal {
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
};""")

# ── Add ConfidenceModel versioning after ConfidenceNormalizer ─────────────
content = content.replace(
"""// Convenience: API version query.
// Prefer this over accessing ZOTE_VERSION directly.
[[nodiscard]] inline constexpr Version version() noexcept {
    return ZOTE_VERSION;
}

} // namespace zote""",
"""// Convenience: API version query.
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

} // namespace zote""")

p.write_text(content)
print("OK -- types.hpp Pass 1 complete")
print("     + SignalCategory enum (16 values)")
print("     + Protocol enum (16 values)")
print("     + Direction enum (5 values)")
print("     + NetworkContext uses Protocol/Direction enums")
print("     + Signal uses SignalCategory enum")
print("     + ConfidenceModel versioning (Section 19)")
