// examples/threat_hunting.cpp
// ZOTE — zenithcpp Open Source Threat Engine
//
// Example: Threat hunting with MITRE ATT&CK
// Demonstrates:
//   - Querying techniques by actor, tactic, platform
//   - D3FEND countermeasure lookup
//   - Navigator layer export

#include <zote/mitre.hpp>
#include <zote/killchain.hpp>
#include <iostream>
#include <vector>

int main() {
    std::cout << "ZOTE Threat Hunting Example\n";
    std::cout << "MITRE ATT&CK v" << zote::MitreDb::attack_version()
              << " | " << zote::MitreDb::total_size()
              << " techniques\n\n";

    // ── Hunt: APT29 techniques on Windows ────────────────────────────────
    std::cout << "=== APT29 techniques (Windows) ===\n";
    zote::MitreQuery q;
    q.actor    = zote::ActorId{"APT29"};
    q.platform = "Windows";
    auto results = zote::MitreDb::query(q);
    for (const auto& ref : results) {
        const auto& t = ref.get();
        std::cout << "  " << t.id
                  << " [" << t.tactic << "] "
                  << t.name << "\n";
    }

    // ── Kill chain for key techniques ────────────────────────────────────
    std::cout << "\n=== Kill chain mapping ===\n";
    std::vector<std::string> hunt_ids = {
        "T1566", "T1059", "T1003", "T1071", "T1486"
    };
    for (const auto& tid : hunt_ids) {
        auto stage = zote::KillChainMapper::from_mitre_id(tid);
        auto* t    = zote::MitreDb::lookup(tid);
        if (t) {
            std::cout << "  " << tid << " " << t->name
                      << " → "
                      << zote::KillChainMapper::stage_name(stage)
                      << "\n";
        }
    }

    // ── D3FEND countermeasures ────────────────────────────────────────────
    std::cout << "\n=== D3FEND countermeasures for T1486 (Ransomware) ===\n";
    auto cms = zote::MitreDb::d3fend_for("T1486");
    for (const auto& cm : cms)
        std::cout << "  → " << cm << "\n";

    // ── Navigator export ──────────────────────────────────────────────────
    std::cout << "\n=== ATT&CK Navigator export ===\n";
    auto layer = zote::MitreDb::build_layer(
        hunt_ids, "APT29 Hunt");
    std::string json = layer.to_json();
    std::cout << "  Layer JSON (" << json.size()
              << " bytes) ready for navigator.attack.mitre.org\n";
    std::cout << "  " << json.substr(0, 80) << "...\n";

    return 0;
}
