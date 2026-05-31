// src/killchain.cpp
// ZOTE — zenithcpp Open Source Threat Engine
// ISO C++23 compliant — zero external dependencies
// Apache 2.0 License — https://github.com/zenithcpp/zote

#include <zote/killchain.hpp>
#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

namespace zote {

// ─── Keyword → stage mapping ─────────────────────────────────────────────
struct KcEntry {
    const char*    keyword;
    KillChainStage stage;
    float          weight;  // Base weight for this keyword
};

static constexpr KcEntry KC_KEYWORDS[] = {
    // Reconnaissance
    {"recon",           KillChainStage::Reconnaissance, 0.90f},
    {"scan",            KillChainStage::Reconnaissance, 0.80f},
    {"probe",           KillChainStage::Reconnaissance, 0.80f},
    {"enumerat",        KillChainStage::Reconnaissance, 0.85f},
    {"fingerprint",     KillChainStage::Reconnaissance, 0.85f},
    {"discovery",       KillChainStage::Reconnaissance, 0.80f},
    {"osint",           KillChainStage::Reconnaissance, 0.90f},
    // Weaponization
    {"weaponiz",        KillChainStage::Weaponization,  0.90f},
    {"obfuscat",        KillChainStage::Weaponization,  0.80f},
    // Delivery
    {"phish",           KillChainStage::Delivery,       0.90f},
    {"deliver",         KillChainStage::Delivery,       0.85f},
    {"payload",         KillChainStage::Delivery,       0.80f},
    {"dropper",         KillChainStage::Delivery,       0.85f},
    {"drive-by",        KillChainStage::Delivery,       0.85f},
    // Exploitation
    {"exploit",         KillChainStage::Exploitation,   0.90f},
    {"shellcode",       KillChainStage::Exploitation,   0.90f},
    {"overflow",        KillChainStage::Exploitation,   0.85f},
    {"injection",       KillChainStage::Exploitation,   0.85f},
    {"rce",             KillChainStage::Exploitation,   0.90f},
    {"remote code",     KillChainStage::Exploitation,   0.90f},
    {"cve-",            KillChainStage::Exploitation,   0.85f},
    {"lfi",             KillChainStage::Exploitation,   0.85f},
    {"sqli",            KillChainStage::Exploitation,   0.85f},
    // Installation
    {"backdoor",        KillChainStage::Installation,   0.90f},
    {"install",         KillChainStage::Installation,   0.80f},
    {"persist",         KillChainStage::Installation,   0.85f},
    {"rootkit",         KillChainStage::Installation,   0.90f},
    {"implant",         KillChainStage::Installation,   0.90f},
    {"cron",            KillChainStage::Installation,   0.80f},
    {"startup",         KillChainStage::Installation,   0.80f},
    {"autorun",         KillChainStage::Installation,   0.80f},
    {"service install", KillChainStage::Installation,   0.85f},
    // Command & Control
    {"beacon",          KillChainStage::CommandControl, 0.90f},
    {"c2",              KillChainStage::CommandControl, 0.85f},
    {"c&c",             KillChainStage::CommandControl, 0.85f},
    {"command and control", KillChainStage::CommandControl, 0.95f},
    {"tunnel",          KillChainStage::CommandControl, 0.80f},
    {"cobaltstrike",    KillChainStage::CommandControl, 0.95f},
    {"metasploit",      KillChainStage::CommandControl, 0.90f},
    {"meterpreter",     KillChainStage::CommandControl, 0.95f},
    {"reverse shell",   KillChainStage::CommandControl, 0.90f},
    {"dns tunnel",      KillChainStage::CommandControl, 0.90f},
    // Actions on Objectives
    {"exfil",           KillChainStage::ActionsOnObj,   0.90f},
    {"lateral",         KillChainStage::ActionsOnObj,   0.85f},
    {"ransomware",      KillChainStage::ActionsOnObj,   0.95f},
    {"encrypt",         KillChainStage::ActionsOnObj,   0.85f},
    {"data theft",      KillChainStage::ActionsOnObj,   0.90f},
    {"credential dump", KillChainStage::ActionsOnObj,   0.90f},
    {"privilege esc",   KillChainStage::ActionsOnObj,   0.85f},
    {"pass the hash",   KillChainStage::ActionsOnObj,   0.90f},
    {"kerberoast",      KillChainStage::ActionsOnObj,   0.90f},
    {"dcsync",          KillChainStage::ActionsOnObj,   0.95f},
    {"destroy",         KillChainStage::ActionsOnObj,   0.90f},
    {"wiper",           KillChainStage::ActionsOnObj,   0.90f},
};
static constexpr std::size_t KC_COUNT =
    sizeof(KC_KEYWORDS)/sizeof(KC_KEYWORDS[0]);

// ─── MITRE technique → stage mapping ─────────────────────────────────────
// Some techniques span multiple stages — all are listed.
struct MitreKcEntry {
    const char*    prefix;
    KillChainStage stage;
    float          confidence;
};

static constexpr MitreKcEntry MITRE_KC[] = {
    // Reconnaissance
    {"T1595", KillChainStage::Reconnaissance, 0.95f},
    {"T1592", KillChainStage::Reconnaissance, 0.90f},
    {"T1589", KillChainStage::Reconnaissance, 0.90f},
    {"T1590", KillChainStage::Reconnaissance, 0.90f},
    {"T1598", KillChainStage::Reconnaissance, 0.90f},
    // Weaponization
    {"T1583", KillChainStage::Weaponization,  0.85f},
    {"T1584", KillChainStage::Weaponization,  0.85f},
    {"T1587", KillChainStage::Weaponization,  0.85f},
    // Delivery
    {"T1566", KillChainStage::Delivery,       0.95f},
    {"T1199", KillChainStage::Delivery,       0.90f},
    {"T1195", KillChainStage::Delivery,       0.90f},
    {"T1189", KillChainStage::Delivery,       0.90f},
    // Exploitation — T1566 also spans here
    {"T1190", KillChainStage::Exploitation,   0.95f},
    {"T1203", KillChainStage::Exploitation,   0.95f},
    {"T1212", KillChainStage::Exploitation,   0.90f},
    {"T1068", KillChainStage::Exploitation,   0.95f},
    // Installation
    {"T1059", KillChainStage::Installation,   0.85f},
    {"T1053", KillChainStage::Installation,   0.90f},
    {"T1547", KillChainStage::Installation,   0.90f},
    {"T1543", KillChainStage::Installation,   0.90f},
    {"T1546", KillChainStage::Installation,   0.85f},
    // Command & Control
    {"T1071", KillChainStage::CommandControl, 0.95f},
    {"T1573", KillChainStage::CommandControl, 0.90f},
    {"T1572", KillChainStage::CommandControl, 0.90f},
    {"T1219", KillChainStage::CommandControl, 0.85f},
    {"T1095", KillChainStage::CommandControl, 0.90f},
    {"T1105", KillChainStage::CommandControl, 0.85f},
    // Actions on Objectives
    {"T1021", KillChainStage::ActionsOnObj,   0.85f},
    {"T1560", KillChainStage::ActionsOnObj,   0.90f},
    {"T1485", KillChainStage::ActionsOnObj,   0.95f},
    {"T1486", KillChainStage::ActionsOnObj,   0.95f},
    {"T1041", KillChainStage::ActionsOnObj,   0.90f},
    {"T1048", KillChainStage::ActionsOnObj,   0.90f},
    {"T1003", KillChainStage::ActionsOnObj,   0.90f},
    {"T1550", KillChainStage::ActionsOnObj,   0.90f},
};
static constexpr std::size_t MITRE_KC_COUNT =
    sizeof(MITRE_KC)/sizeof(MITRE_KC[0]);

static constexpr const char* STAGE_NAMES[] = {
    "Reconnaissance", "Weaponization", "Delivery",
    "Exploitation", "Installation", "Command & Control",
    "Actions on Objectives", "Unknown",
};

static constexpr const char* TACTIC_NAMES[] = {
    "TA0043","TA0001","TA0001",
    "TA0002","TA0003","TA0011",
    "TA0010","unknown",
};

static std::string lower(const std::string& s) noexcept {
    std::string r = s;
    for (auto& c : r)
        c = static_cast<char>(
            tolower(static_cast<unsigned char>(c)));
    return r;
}

// ─── Public API ───────────────────────────────────────────────────────────

KillChainAssessment KillChainMapper::assess(
    const Signal& signal) noexcept {
    KillChainAssessment result;

    // ── Phase 1: MITRE ID mapping (highest priority) ──────────────────
    if (!signal.mitre_id.empty()) {
        for (std::size_t i = 0; i < MITRE_KC_COUNT; ++i) {
            if (signal.mitre_id.value.rfind(
                    MITRE_KC[i].prefix, 0) != 0) continue;
            // Add to candidates — collect ALL matching stages
            bool found = false;
            for (auto& sc : result.candidates)
                if (sc.stage == MITRE_KC[i].stage) {
                    // Keep highest confidence for same stage
                    if (MITRE_KC[i].confidence > sc.confidence)
                        sc.confidence = MITRE_KC[i].confidence;
                    found = true; break;
                }
            if (!found)
                result.candidates.push_back({
                    MITRE_KC[i].stage,
                    MITRE_KC[i].confidence});
        }
        if (!result.candidates.empty()) {
            // Primary = highest confidence candidate
            auto best = std::max_element(
                result.candidates.begin(),
                result.candidates.end(),
                [](const StageConfidence& a,
                   const StageConfidence& b) {
                    return a.confidence < b.confidence;
                });
            result.stage      = best->stage;
            result.confidence = best->confidence;
            float contrib = best->confidence;
            result.reasons.push_back({
                "mitre_id",
                signal.mitre_id.value,
                best->confidence,
                contrib});
            return result;
        }
    }

    // ── Phase 2: Keyword search ───────────────────────────────────────
    std::string desc = lower(signal.description);
    std::string cat  = lower(signal.category_str);

    for (std::size_t i = 0; i < KC_COUNT; ++i) {
        const std::string kw(KC_KEYWORDS[i].keyword);
        std::string field;
        float base_w = 0.0f;

        if (desc.find(kw) != std::string::npos) {
            field   = "description";
            base_w  = KC_KEYWORDS[i].weight;
        } else if (cat.find(kw) != std::string::npos) {
            field   = "category";
            // Category match is slightly weaker than description
            base_w  = KC_KEYWORDS[i].weight * 0.90f;
        }

        if (field.empty()) continue;

        // Compute contribution relative to keyword weight
        float contrib = base_w;

        // Add to candidates
        bool found = false;
        for (auto& sc : result.candidates)
            if (sc.stage == KC_KEYWORDS[i].stage) {
                if (base_w > sc.confidence)
                    sc.confidence = base_w;
                found = true; break;
            }
        if (!found)
            result.candidates.push_back({
                KC_KEYWORDS[i].stage, base_w});

        // Add reason (for primary stage only — avoid noise)
        if (result.reasons.empty() ||
            base_w > result.confidence) {
            result.reasons.push_back({field, kw, base_w, contrib});
        }
    }

    // Select primary stage = highest confidence candidate
    if (!result.candidates.empty()) {
        auto best = std::max_element(
            result.candidates.begin(),
            result.candidates.end(),
            [](const StageConfidence& a,
               const StageConfidence& b) {
                return a.confidence < b.confidence;
            });
        result.stage      = best->stage;
        result.confidence = best->confidence;
    }

    return result;
}

KillChainStage KillChainMapper::map(
    const Signal& signal) noexcept {
    return assess(signal).stage;
}

KillChainStage KillChainMapper::from_mitre_id(
    const std::string& tid) noexcept {
    float best_conf = 0.0f;
    KillChainStage best = KillChainStage::Unknown;
    for (std::size_t i = 0; i < MITRE_KC_COUNT; ++i) {
        if (tid.rfind(MITRE_KC[i].prefix, 0) != 0) continue;
        if (MITRE_KC[i].confidence > best_conf) {
            best_conf = MITRE_KC[i].confidence;
            best      = MITRE_KC[i].stage;
        }
    }
    return best;
}

KillChainStage KillChainMapper::from_technique_id(
    const TechniqueId& tid) noexcept {
    return from_mitre_id(tid.value);
}

std::vector<StageConfidence>
KillChainMapper::stages_for_technique(
    const std::string& tid) {
    std::vector<StageConfidence> result;
    for (std::size_t i = 0; i < MITRE_KC_COUNT; ++i) {
        if (tid.rfind(MITRE_KC[i].prefix, 0) != 0) continue;
        bool found = false;
        for (auto& sc : result)
            if (sc.stage == MITRE_KC[i].stage) {
                if (MITRE_KC[i].confidence > sc.confidence)
                    sc.confidence = MITRE_KC[i].confidence;
                found = true; break;
            }
        if (!found)
            result.push_back({MITRE_KC[i].stage,
                              MITRE_KC[i].confidence});
    }
    return result;
}

const char* KillChainMapper::stage_name(
    KillChainStage stage) noexcept {
    return STAGE_NAMES[static_cast<std::uint8_t>(stage)];
}

const char* KillChainMapper::tactic(
    KillChainStage stage) noexcept {
    return TACTIC_NAMES[static_cast<std::uint8_t>(stage)];
}

} // namespace zote
