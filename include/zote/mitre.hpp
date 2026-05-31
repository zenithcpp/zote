#pragma once
// include/zote/mitre.hpp
// ZOTE — zenithcpp Open Source Threat Engine
// ISO C++23 compliant — zero external dependencies
// Apache 2.0 License — https://github.com/zenithcpp/zote
//
// MITRE ATT&CK knowledge base.
//
// Coverage:
//   Enterprise v14: 89+ techniques + sub-techniques
//   ICS matrix:     87 techniques (T08xx)
//   Threat actors:  APT28/29/41, Lazarus, LockBit,
//                   FIN7, Cobalt, Sandworm, WizardSpider,
//                   Kimsuky, MuddyWater
//   Software:       Mimikatz, CobaltStrike, Metasploit,
//                   Impacket, BloodHound, Sliver, Empire,
//                   BruteRatel, Havoc, Meterpreter,
//                   PsExec, Nmap
//   Services:       ssh, rdp, smb, http/s, ftp, dns,
//                   ldap, mssql, mysql, winrm, snmp,
//                   nfs, vnc, telnet
//   D3FEND:         countermeasure mappings
//   Navigator:      ATT&CK Navigator 4.9 JSON export
//
// Thread-safety:
//   All query functions are read-only and thread-safe.
//   The database is compiled-in constexpr — no locking needed.
//
// v0.1 limitations (documented upgrade path):
//   - Techniques use string keys internally (v1.0: interning)
//   - Linear scan for lookups (v1.0: hash index)
//   - Static functions only (v0.2: instantiable engine)
//   - Mobile matrix returns empty (v0.2: full mobile)

#include <zote/types.hpp>
#include <functional>
#include <string>
#include <vector>

namespace zote {

// ─── MitreTechnique ──────────────────────────────────────────────────────
// Represents a single ATT&CK technique or sub-technique.
// All string fields are const char* (compiled-in data, no allocation).
struct MitreTechnique {
    const char* id;           // e.g. "T1566"
    const char* sub_id;       // e.g. "T1566.001" (empty string if none)
    const char* name;         // e.g. "Phishing"
    const char* tactic;       // Primary tactic ID e.g. "TA0001"
    const char* tactic_name;  // e.g. "Initial Access"
    const char* description;  // Brief description
    const char* platform;     // e.g. "Linux,Windows,macOS"
    Severity    severity;     // Default severity for this technique
};

// ─── MitreDb ─────────────────────────────────────────────────────────────
// Static knowledge base — no instantiation required.
// All functions are stateless and thread-safe.
//
// Query API (composable):
//   Use query(MitreQuery{}) to combine filters.
//   Convenience functions (by_actor, by_service, etc.) wrap query().
//
// Return type:
//   std::vector<TechniqueRef> — safe references into compiled-in DB.
//   References are valid for the lifetime of the process.
//   Raw const MitreTechnique* also available via lookup().
class MitreDb {
public:
    // ── Direct lookup ─────────────────────────────────────────────────

    // Look up technique by ID or sub-technique ID.
    // Returns nullptr if not found.
    // e.g. lookup("T1566") or lookup("T1566.001")
    [[nodiscard]] static const MitreTechnique*
    lookup(const std::string& id) noexcept;

    // Look up by TechniqueId strong type.
    [[nodiscard]] static const MitreTechnique*
    lookup(const TechniqueId& id) noexcept;

    // ── Composable query ──────────────────────────────────────────────

    // Query with optional filters — any combination.
    // All non-empty filters must match (AND semantics).
    // Returns TechniqueRef vector — safe references into compiled-in DB.
    [[nodiscard]] static std::vector<TechniqueRef>
    query(const MitreQuery& q);

    // ── Convenience queries (wrap query()) ────────────────────────────

    // All techniques for a tactic ID (e.g. "TA0001").
    [[nodiscard]] static std::vector<const MitreTechnique*>
    by_tactic(const std::string& tactic_id);

    // Techniques used by a known threat actor.
    // Case-insensitive. e.g. "APT28", "apt28", "Apt28"
    [[nodiscard]] static std::vector<const MitreTechnique*>
    by_actor(const std::string& actor);

    // Techniques used by a software/tool.
    // Case-insensitive. e.g. "Mimikatz", "CobaltStrike"
    [[nodiscard]] static std::vector<const MitreTechnique*>
    by_software(const std::string& software);

    // Techniques relevant to a service/port.
    // Case-insensitive. e.g. "ssh", "rdp", "smb"
    [[nodiscard]] static std::vector<const MitreTechnique*>
    by_service(const std::string& service);

    // ── D3FEND countermeasures ────────────────────────────────────────

    // Defensive countermeasures for a technique ID.
    // Returns empty vector if technique has no D3FEND mapping.
    [[nodiscard]] static std::vector<std::string>
    d3fend_for(const std::string& technique_id);

    // ── ATT&CK Navigator export ───────────────────────────────────────

    // Build a NavigatorLayer from technique IDs.
    // Call layer.to_json() for JSON string output.
    [[nodiscard]] static NavigatorLayer
    build_layer(
        const std::vector<std::string>& technique_ids,
        const std::string&              layer_name,
        const std::string&              color = "#ff6666") noexcept;

    // Convenience: build layer and return JSON string directly.
    [[nodiscard]] static std::string
    navigator_export(
        const std::vector<std::string>& technique_ids,
        const std::string&              layer_name) noexcept;

    // ── Matrix queries ────────────────────────────────────────────────

    // All ICS matrix techniques (T08xx range).
    [[nodiscard]] static std::vector<const MitreTechnique*>
    ics_techniques();

    // Mobile matrix techniques.
    // Note: returns empty in v0.1 — full mobile matrix in v0.2.
    [[nodiscard]] static std::vector<const MitreTechnique*>
    mobile_techniques();

    // ── Database metadata ─────────────────────────────────────────────

    // Enterprise technique count.
    [[nodiscard]] static std::size_t enterprise_size() noexcept;

    // Total database size (Enterprise + ICS).
    [[nodiscard]] static std::size_t total_size() noexcept;

    // ATT&CK version string.
    [[nodiscard]] static const char* attack_version() noexcept;
};

} // namespace zote
