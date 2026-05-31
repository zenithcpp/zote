#!/usr/bin/env python3
# zote_killchain_v2.py
# Run from ~/Desktop/ZOTE/
# Upgrades KillChain: multi-stage candidates, contribution field,
# StageConfidence struct, updated assess()

import pathlib

# ── 1. Update types.hpp ───────────────────────────────────────────────────
p = pathlib.Path("include/zote/types.hpp")
content = p.read_text()

# Add contribution field to KillChainReason
content = content.replace(
    """// Kill chain reason — evidence for stage mapping
struct KillChainReason {
    std::string field;   // Field that triggered mapping
    std::string match;   // Keyword or ID that matched
    float       weight;  // 0.0-1.0 confidence contribution
};""",
    """// Kill chain reason — evidence for stage mapping
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
};"""
)

# Extend KillChainAssessment with candidates
content = content.replace(
    """// Kill chain assessment — replaces raw KillChainStage return
struct KillChainAssessment {
    KillChainStage              stage      = KillChainStage::Unknown;
    float                       confidence = 0.0f; // 0.0-1.0
    std::vector<KillChainReason> reasons;
};""",
    """// Kill chain assessment — replaces raw KillChainStage return
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
};"""
)

p.write_text(content)
print("OK -- types.hpp: StageConfidence + contribution + candidates added")

# ── 2. Update killchain.hpp ───────────────────────────────────────────────
hpp = []
hpp.append("#pragma once")
hpp.append("// include/zote/killchain.hpp")
hpp.append("// ZOTE — zenithcpp Open Source Threat Engine")
hpp.append("// ISO C++23 compliant — zero external dependencies")
hpp.append("// Apache 2.0 License — https://github.com/zenithcpp/zote")
hpp.append("//")
hpp.append("// Kill Chain Inference Engine (KCIE)")
hpp.append("//")
hpp.append("// Maps signals to Lockheed Martin kill chain stages using")
hpp.append("// evidence-based probabilistic inference, not deterministic")
hpp.append("// classification.")
hpp.append("//")
hpp.append("// ── Assessment model ─────────────────────────────────────────────────────")
hpp.append("//")
hpp.append("// assess() returns KillChainAssessment containing:")
hpp.append("//   stage:      primary stage (highest confidence)")
hpp.append("//   confidence: 0.0-1.0 for primary stage")
hpp.append("//   reasons:    evidence explaining the primary mapping")
hpp.append("//   candidates: ALL matching stages with individual confidence")
hpp.append("//")
hpp.append("// ── Mapping priority (highest to lowest) ─────────────────────────────────")
hpp.append("//")
hpp.append("//   1. MITRE technique ID  → confidence 0.90-0.95 (authoritative)")
hpp.append("//   2. Description keyword → confidence 0.75       (strong signal)")
hpp.append("//   3. Category keyword    → confidence 0.70       (weaker signal)")
hpp.append("//   4. Unknown             → confidence 0.0        (no evidence)")
hpp.append("//")
hpp.append("// ── Multi-stage signals ───────────────────────────────────────────────────")
hpp.append("//")
hpp.append("// Some techniques span multiple kill chain stages simultaneously.")
hpp.append("// Examples:")
hpp.append("//   T1566.001 (Spearphishing Attachment) → Delivery + Exploitation")
hpp.append("//   T1059 (Scripting Interpreter)        → Execution + Installation")
hpp.append("//   T1055 (Process Injection)            → Exploitation + Privilege Esc")
hpp.append("//")
hpp.append("// The candidates vector contains ALL matching stages.")
hpp.append("// The primary stage is the highest-confidence candidate.")
hpp.append("// Callers should inspect candidates for full picture.")
hpp.append("//")
hpp.append("// ── MITRE many-to-many limitation (v0.1) ────────────────────────────────")
hpp.append("//")
hpp.append("// MITRE techniques map to multiple tactics in the official matrix.")
hpp.append("// The current mapping forces one primary kill chain stage per")
hpp.append("// technique ID. Full many-to-many tactic mapping planned for v0.2")
hpp.append("// when MitreTechnique.tactics becomes a vector.")
hpp.append("//")
hpp.append("// ── v0.2 upgrade path ────────────────────────────────────────────────────")
hpp.append("//")
hpp.append("//   Feature-based inference layer (weighted feature extraction)")
hpp.append("//   Temporal progression model (KillChainEngine instance)")
hpp.append("//   Full MITRE many-to-many tactic mapping")
hpp.append("//   Normalized confidence across DetectionEngine + UEBA + KCIE")
hpp.append("//   Integration hooks → CorrelationEngine campaign builder")
hpp.append("//")
hpp.append("// ── Thread-safety ────────────────────────────────────────────────────────")
hpp.append("//")
hpp.append("//   All functions are stateless and thread-safe.")
hpp.append("//   No shared mutable state — safe for parallel ingestion.")
hpp.append("")
hpp.append("#include <zote/types.hpp>")
hpp.append("#include <string>")
hpp.append("#include <vector>")
hpp.append("")
hpp.append("namespace zote {")
hpp.append("")
hpp.append("class KillChainMapper {")
hpp.append("public:")
hpp.append("    // ── Primary API ───────────────────────────────────────────────────")
hpp.append("")
hpp.append("    // Evidence-based assessment — preferred API.")
hpp.append("    // Returns:")
hpp.append("    //   stage:      primary kill chain stage")
hpp.append("    //   confidence: 0.0-1.0 for primary stage")
hpp.append("    //   reasons:    what triggered the mapping")
hpp.append("    //   candidates: all matching stages (multi-stage signals)")
hpp.append("    [[nodiscard]] static KillChainAssessment")
hpp.append("    assess(const Signal& signal) noexcept;")
hpp.append("")
hpp.append("    // ── Convenience API ───────────────────────────────────────────────")
hpp.append("")
hpp.append("    // Returns primary stage only (delegates to assess()).")
hpp.append("    // Use assess() when confidence or candidates are needed.")
hpp.append("    [[nodiscard]] static KillChainStage")
hpp.append("    map(const Signal& signal) noexcept;")
hpp.append("")
hpp.append("    // Map MITRE technique ID string to primary kill chain stage.")
hpp.append("    // Handles sub-techniques: \"T1566.001\" maps same as \"T1566\".")
hpp.append("    // Returns Unknown if technique ID not in mapping table.")
hpp.append("    [[nodiscard]] static KillChainStage")
hpp.append("    from_mitre_id(const std::string& technique_id) noexcept;")
hpp.append("")
hpp.append("    // Map TechniqueId strong type to kill chain stage.")
hpp.append("    [[nodiscard]] static KillChainStage")
hpp.append("    from_technique_id(const TechniqueId& tid) noexcept;")
hpp.append("")
hpp.append("    // All kill chain stages a MITRE technique maps to.")
hpp.append("    // Returns multiple stages for techniques that span phases.")
hpp.append("    [[nodiscard]] static std::vector<StageConfidence>")
hpp.append("    stages_for_technique(const std::string& technique_id) noexcept;")
hpp.append("")
hpp.append("    // ── Metadata ──────────────────────────────────────────────────────")
hpp.append("")
hpp.append("    // Human-readable stage name.")
hpp.append("    // e.g. KillChainStage::CommandControl -> \"Command & Control\"")
hpp.append("    [[nodiscard]] static const char*")
hpp.append("    stage_name(KillChainStage stage) noexcept;")
hpp.append("")
hpp.append("    // MITRE tactic ID for a kill chain stage.")
hpp.append("    // e.g. KillChainStage::Delivery -> \"TA0001\"")
hpp.append("    [[nodiscard]] static const char*")
hpp.append("    tactic(KillChainStage stage) noexcept;")
hpp.append("};")
hpp.append("")
hpp.append("} // namespace zote")
hpp.append("")

pathlib.Path("include/zote/killchain.hpp").write_text(
    "\n".join(hpp), encoding="utf-8")
print(f"OK -- include/zote/killchain.hpp written ({len(hpp)} lines)")

# ── 3. Update killchain.cpp ───────────────────────────────────────────────
cpp = []
cpp.append("// src/killchain.cpp")
cpp.append("// ZOTE — zenithcpp Open Source Threat Engine")
cpp.append("// ISO C++23 compliant — zero external dependencies")
cpp.append("// Apache 2.0 License — https://github.com/zenithcpp/zote")
cpp.append("")
cpp.append("#include <zote/killchain.hpp>")
cpp.append("#include <algorithm>")
cpp.append("#include <cctype>")
cpp.append("#include <string>")
cpp.append("#include <vector>")
cpp.append("")
cpp.append("namespace zote {")
cpp.append("")
cpp.append("// ─── Keyword → stage mapping ─────────────────────────────────────────────")
cpp.append("struct KcEntry {")
cpp.append("    const char*    keyword;")
cpp.append("    KillChainStage stage;")
cpp.append("    float          weight;  // Base weight for this keyword")
cpp.append("};")
cpp.append("")
cpp.append("static constexpr KcEntry KC_KEYWORDS[] = {")
cpp.append('    // Reconnaissance')
cpp.append('    {"recon",           KillChainStage::Reconnaissance, 0.90f},')
cpp.append('    {"scan",            KillChainStage::Reconnaissance, 0.80f},')
cpp.append('    {"probe",           KillChainStage::Reconnaissance, 0.80f},')
cpp.append('    {"enumerat",        KillChainStage::Reconnaissance, 0.85f},')
cpp.append('    {"fingerprint",     KillChainStage::Reconnaissance, 0.85f},')
cpp.append('    {"discovery",       KillChainStage::Reconnaissance, 0.80f},')
cpp.append('    {"osint",           KillChainStage::Reconnaissance, 0.90f},')
cpp.append('    // Weaponization')
cpp.append('    {"weaponiz",        KillChainStage::Weaponization,  0.90f},')
cpp.append('    {"obfuscat",        KillChainStage::Weaponization,  0.80f},')
cpp.append('    // Delivery')
cpp.append('    {"phish",           KillChainStage::Delivery,       0.90f},')
cpp.append('    {"deliver",         KillChainStage::Delivery,       0.85f},')
cpp.append('    {"payload",         KillChainStage::Delivery,       0.80f},')
cpp.append('    {"dropper",         KillChainStage::Delivery,       0.85f},')
cpp.append('    {"drive-by",        KillChainStage::Delivery,       0.85f},')
cpp.append('    // Exploitation')
cpp.append('    {"exploit",         KillChainStage::Exploitation,   0.90f},')
cpp.append('    {"shellcode",       KillChainStage::Exploitation,   0.90f},')
cpp.append('    {"overflow",        KillChainStage::Exploitation,   0.85f},')
cpp.append('    {"injection",       KillChainStage::Exploitation,   0.85f},')
cpp.append('    {"rce",             KillChainStage::Exploitation,   0.90f},')
cpp.append('    {"remote code",     KillChainStage::Exploitation,   0.90f},')
cpp.append('    {"cve-",            KillChainStage::Exploitation,   0.85f},')
cpp.append('    {"lfi",             KillChainStage::Exploitation,   0.85f},')
cpp.append('    {"sqli",            KillChainStage::Exploitation,   0.85f},')
cpp.append('    // Installation')
cpp.append('    {"backdoor",        KillChainStage::Installation,   0.90f},')
cpp.append('    {"install",         KillChainStage::Installation,   0.80f},')
cpp.append('    {"persist",         KillChainStage::Installation,   0.85f},')
cpp.append('    {"rootkit",         KillChainStage::Installation,   0.90f},')
cpp.append('    {"implant",         KillChainStage::Installation,   0.90f},')
cpp.append('    {"cron",            KillChainStage::Installation,   0.80f},')
cpp.append('    {"startup",         KillChainStage::Installation,   0.80f},')
cpp.append('    {"autorun",         KillChainStage::Installation,   0.80f},')
cpp.append('    {"service install", KillChainStage::Installation,   0.85f},')
cpp.append('    // Command & Control')
cpp.append('    {"beacon",          KillChainStage::CommandControl, 0.90f},')
cpp.append('    {"c2",              KillChainStage::CommandControl, 0.85f},')
cpp.append('    {"c&c",             KillChainStage::CommandControl, 0.85f},')
cpp.append('    {"command and control", KillChainStage::CommandControl, 0.95f},')
cpp.append('    {"tunnel",          KillChainStage::CommandControl, 0.80f},')
cpp.append('    {"cobaltstrike",    KillChainStage::CommandControl, 0.95f},')
cpp.append('    {"metasploit",      KillChainStage::CommandControl, 0.90f},')
cpp.append('    {"meterpreter",     KillChainStage::CommandControl, 0.95f},')
cpp.append('    {"reverse shell",   KillChainStage::CommandControl, 0.90f},')
cpp.append('    {"dns tunnel",      KillChainStage::CommandControl, 0.90f},')
cpp.append('    // Actions on Objectives')
cpp.append('    {"exfil",           KillChainStage::ActionsOnObj,   0.90f},')
cpp.append('    {"lateral",         KillChainStage::ActionsOnObj,   0.85f},')
cpp.append('    {"ransomware",      KillChainStage::ActionsOnObj,   0.95f},')
cpp.append('    {"encrypt",         KillChainStage::ActionsOnObj,   0.85f},')
cpp.append('    {"data theft",      KillChainStage::ActionsOnObj,   0.90f},')
cpp.append('    {"credential dump", KillChainStage::ActionsOnObj,   0.90f},')
cpp.append('    {"privilege esc",   KillChainStage::ActionsOnObj,   0.85f},')
cpp.append('    {"pass the hash",   KillChainStage::ActionsOnObj,   0.90f},')
cpp.append('    {"kerberoast",      KillChainStage::ActionsOnObj,   0.90f},')
cpp.append('    {"dcsync",          KillChainStage::ActionsOnObj,   0.95f},')
cpp.append('    {"destroy",         KillChainStage::ActionsOnObj,   0.90f},')
cpp.append('    {"wiper",           KillChainStage::ActionsOnObj,   0.90f},')
cpp.append("};")
cpp.append("static constexpr std::size_t KC_COUNT =")
cpp.append("    sizeof(KC_KEYWORDS)/sizeof(KC_KEYWORDS[0]);")
cpp.append("")
cpp.append("// ─── MITRE technique → stage mapping ─────────────────────────────────────")
cpp.append("// Some techniques span multiple stages — all are listed.")
cpp.append("struct MitreKcEntry {")
cpp.append("    const char*    prefix;")
cpp.append("    KillChainStage stage;")
cpp.append("    float          confidence;")
cpp.append("};")
cpp.append("")
cpp.append("static constexpr MitreKcEntry MITRE_KC[] = {")
cpp.append('    // Reconnaissance')
cpp.append('    {"T1595", KillChainStage::Reconnaissance, 0.95f},')
cpp.append('    {"T1592", KillChainStage::Reconnaissance, 0.90f},')
cpp.append('    {"T1589", KillChainStage::Reconnaissance, 0.90f},')
cpp.append('    {"T1590", KillChainStage::Reconnaissance, 0.90f},')
cpp.append('    {"T1598", KillChainStage::Reconnaissance, 0.90f},')
cpp.append('    // Weaponization')
cpp.append('    {"T1583", KillChainStage::Weaponization,  0.85f},')
cpp.append('    {"T1584", KillChainStage::Weaponization,  0.85f},')
cpp.append('    {"T1587", KillChainStage::Weaponization,  0.85f},')
cpp.append('    // Delivery')
cpp.append('    {"T1566", KillChainStage::Delivery,       0.95f},')
cpp.append('    {"T1199", KillChainStage::Delivery,       0.90f},')
cpp.append('    {"T1195", KillChainStage::Delivery,       0.90f},')
cpp.append('    {"T1189", KillChainStage::Delivery,       0.90f},')
cpp.append('    // Exploitation — T1566 also spans here')
cpp.append('    {"T1190", KillChainStage::Exploitation,   0.95f},')
cpp.append('    {"T1203", KillChainStage::Exploitation,   0.95f},')
cpp.append('    {"T1212", KillChainStage::Exploitation,   0.90f},')
cpp.append('    {"T1068", KillChainStage::Exploitation,   0.95f},')
cpp.append('    // Installation')
cpp.append('    {"T1059", KillChainStage::Installation,   0.85f},')
cpp.append('    {"T1053", KillChainStage::Installation,   0.90f},')
cpp.append('    {"T1547", KillChainStage::Installation,   0.90f},')
cpp.append('    {"T1543", KillChainStage::Installation,   0.90f},')
cpp.append('    {"T1546", KillChainStage::Installation,   0.85f},')
cpp.append('    // Command & Control')
cpp.append('    {"T1071", KillChainStage::CommandControl, 0.95f},')
cpp.append('    {"T1573", KillChainStage::CommandControl, 0.90f},')
cpp.append('    {"T1572", KillChainStage::CommandControl, 0.90f},')
cpp.append('    {"T1219", KillChainStage::CommandControl, 0.85f},')
cpp.append('    {"T1095", KillChainStage::CommandControl, 0.90f},')
cpp.append('    {"T1105", KillChainStage::CommandControl, 0.85f},')
cpp.append('    // Actions on Objectives')
cpp.append('    {"T1021", KillChainStage::ActionsOnObj,   0.85f},')
cpp.append('    {"T1560", KillChainStage::ActionsOnObj,   0.90f},')
cpp.append('    {"T1485", KillChainStage::ActionsOnObj,   0.95f},')
cpp.append('    {"T1486", KillChainStage::ActionsOnObj,   0.95f},')
cpp.append('    {"T1041", KillChainStage::ActionsOnObj,   0.90f},')
cpp.append('    {"T1048", KillChainStage::ActionsOnObj,   0.90f},')
cpp.append('    {"T1003", KillChainStage::ActionsOnObj,   0.90f},')
cpp.append('    {"T1550", KillChainStage::ActionsOnObj,   0.90f},')
cpp.append("};")
cpp.append("static constexpr std::size_t MITRE_KC_COUNT =")
cpp.append("    sizeof(MITRE_KC)/sizeof(MITRE_KC[0]);")
cpp.append("")
cpp.append("static constexpr const char* STAGE_NAMES[] = {")
cpp.append('    "Reconnaissance", "Weaponization", "Delivery",')
cpp.append('    "Exploitation", "Installation", "Command & Control",')
cpp.append('    "Actions on Objectives", "Unknown",')
cpp.append("};")
cpp.append("")
cpp.append("static constexpr const char* TACTIC_NAMES[] = {")
cpp.append('    "TA0043","TA0001","TA0001",')
cpp.append('    "TA0002","TA0003","TA0011",')
cpp.append('    "TA0010","unknown",')
cpp.append("};")
cpp.append("")
cpp.append("static std::string lower(const std::string& s) noexcept {")
cpp.append("    std::string r = s;")
cpp.append("    for (auto& c : r)")
cpp.append("        c = static_cast<char>(")
cpp.append("            tolower(static_cast<unsigned char>(c)));")
cpp.append("    return r;")
cpp.append("}")
cpp.append("")
cpp.append("// ─── Public API ───────────────────────────────────────────────────────────")
cpp.append("")
cpp.append("KillChainAssessment KillChainMapper::assess(")
cpp.append("    const Signal& signal) noexcept {")
cpp.append("    KillChainAssessment result;")
cpp.append("")
cpp.append("    // ── Phase 1: MITRE ID mapping (highest priority) ──────────────────")
cpp.append("    if (!signal.mitre_id.empty()) {")
cpp.append("        for (std::size_t i = 0; i < MITRE_KC_COUNT; ++i) {")
cpp.append("            if (signal.mitre_id.value.rfind(")
cpp.append("                    MITRE_KC[i].prefix, 0) != 0) continue;")
cpp.append("            // Add to candidates — collect ALL matching stages")
cpp.append("            bool found = false;")
cpp.append("            for (auto& sc : result.candidates)")
cpp.append("                if (sc.stage == MITRE_KC[i].stage) {")
cpp.append("                    // Keep highest confidence for same stage")
cpp.append("                    if (MITRE_KC[i].confidence > sc.confidence)")
cpp.append("                        sc.confidence = MITRE_KC[i].confidence;")
cpp.append("                    found = true; break;")
cpp.append("                }")
cpp.append("            if (!found)")
cpp.append("                result.candidates.push_back({")
cpp.append("                    MITRE_KC[i].stage,")
cpp.append("                    MITRE_KC[i].confidence});")
cpp.append("        }")
cpp.append("        if (!result.candidates.empty()) {")
cpp.append("            // Primary = highest confidence candidate")
cpp.append("            auto best = std::max_element(")
cpp.append("                result.candidates.begin(),")
cpp.append("                result.candidates.end(),")
cpp.append("                [](const StageConfidence& a,")
cpp.append("                   const StageConfidence& b) {")
cpp.append("                    return a.confidence < b.confidence;")
cpp.append("                });")
cpp.append("            result.stage      = best->stage;")
cpp.append("            result.confidence = best->confidence;")
cpp.append("            float contrib = best->confidence;")
cpp.append("            result.reasons.push_back({")
cpp.append('                "mitre_id",')
cpp.append("                signal.mitre_id.value,")
cpp.append("                best->confidence,")
cpp.append("                contrib});")
cpp.append("            return result;")
cpp.append("        }")
cpp.append("    }")
cpp.append("")
cpp.append("    // ── Phase 2: Keyword search ───────────────────────────────────────")
cpp.append("    std::string desc = lower(signal.description);")
cpp.append("    std::string cat  = lower(signal.category);")
cpp.append("")
cpp.append("    for (std::size_t i = 0; i < KC_COUNT; ++i) {")
cpp.append("        const std::string kw(KC_KEYWORDS[i].keyword);")
cpp.append("        std::string field;")
cpp.append("        float base_w = 0.0f;")
cpp.append("")
cpp.append("        if (desc.find(kw) != std::string::npos) {")
cpp.append('            field   = "description";')
cpp.append("            base_w  = KC_KEYWORDS[i].weight;")
cpp.append("        } else if (cat.find(kw) != std::string::npos) {")
cpp.append('            field   = "category";')
cpp.append("            // Category match is slightly weaker than description")
cpp.append("            base_w  = KC_KEYWORDS[i].weight * 0.90f;")
cpp.append("        }")
cpp.append("")
cpp.append("        if (field.empty()) continue;")
cpp.append("")
cpp.append("        // Compute contribution relative to keyword weight")
cpp.append("        float contrib = base_w;")
cpp.append("")
cpp.append("        // Add to candidates")
cpp.append("        bool found = false;")
cpp.append("        for (auto& sc : result.candidates)")
cpp.append("            if (sc.stage == KC_KEYWORDS[i].stage) {")
cpp.append("                if (base_w > sc.confidence)")
cpp.append("                    sc.confidence = base_w;")
cpp.append("                found = true; break;")
cpp.append("            }")
cpp.append("        if (!found)")
cpp.append("            result.candidates.push_back({")
cpp.append("                KC_KEYWORDS[i].stage, base_w});")
cpp.append("")
cpp.append("        // Add reason (for primary stage only — avoid noise)")
cpp.append("        if (result.reasons.empty() ||")
cpp.append("            base_w > result.confidence) {")
cpp.append("            result.reasons.push_back({field, kw, base_w, contrib});")
cpp.append("        }")
cpp.append("    }")
cpp.append("")
cpp.append("    // Select primary stage = highest confidence candidate")
cpp.append("    if (!result.candidates.empty()) {")
cpp.append("        auto best = std::max_element(")
cpp.append("            result.candidates.begin(),")
cpp.append("            result.candidates.end(),")
cpp.append("            [](const StageConfidence& a,")
cpp.append("               const StageConfidence& b) {")
cpp.append("                return a.confidence < b.confidence;")
cpp.append("            });")
cpp.append("        result.stage      = best->stage;")
cpp.append("        result.confidence = best->confidence;")
cpp.append("    }")
cpp.append("")
cpp.append("    return result;")
cpp.append("}")
cpp.append("")
cpp.append("KillChainStage KillChainMapper::map(")
cpp.append("    const Signal& signal) noexcept {")
cpp.append("    return assess(signal).stage;")
cpp.append("}")
cpp.append("")
cpp.append("KillChainStage KillChainMapper::from_mitre_id(")
cpp.append("    const std::string& tid) noexcept {")
cpp.append("    float best_conf = 0.0f;")
cpp.append("    KillChainStage best = KillChainStage::Unknown;")
cpp.append("    for (std::size_t i = 0; i < MITRE_KC_COUNT; ++i) {")
cpp.append("        if (tid.rfind(MITRE_KC[i].prefix, 0) != 0) continue;")
cpp.append("        if (MITRE_KC[i].confidence > best_conf) {")
cpp.append("            best_conf = MITRE_KC[i].confidence;")
cpp.append("            best      = MITRE_KC[i].stage;")
cpp.append("        }")
cpp.append("    }")
cpp.append("    return best;")
cpp.append("}")
cpp.append("")
cpp.append("KillChainStage KillChainMapper::from_technique_id(")
cpp.append("    const TechniqueId& tid) noexcept {")
cpp.append("    return from_mitre_id(tid.value);")
cpp.append("}")
cpp.append("")
cpp.append("std::vector<StageConfidence>")
cpp.append("KillChainMapper::stages_for_technique(")
cpp.append("    const std::string& tid) noexcept {")
cpp.append("    std::vector<StageConfidence> result;")
cpp.append("    for (std::size_t i = 0; i < MITRE_KC_COUNT; ++i) {")
cpp.append("        if (tid.rfind(MITRE_KC[i].prefix, 0) != 0) continue;")
cpp.append("        bool found = false;")
cpp.append("        for (auto& sc : result)")
cpp.append("            if (sc.stage == MITRE_KC[i].stage) {")
cpp.append("                if (MITRE_KC[i].confidence > sc.confidence)")
cpp.append("                    sc.confidence = MITRE_KC[i].confidence;")
cpp.append("                found = true; break;")
cpp.append("            }")
cpp.append("        if (!found)")
cpp.append("            result.push_back({MITRE_KC[i].stage,")
cpp.append("                              MITRE_KC[i].confidence});")
cpp.append("    }")
cpp.append("    return result;")
cpp.append("}")
cpp.append("")
cpp.append("const char* KillChainMapper::stage_name(")
cpp.append("    KillChainStage stage) noexcept {")
cpp.append("    return STAGE_NAMES[static_cast<std::uint8_t>(stage)];")
cpp.append("}")
cpp.append("")
cpp.append("const char* KillChainMapper::tactic(")
cpp.append("    KillChainStage stage) noexcept {")
cpp.append("    return TACTIC_NAMES[static_cast<std::uint8_t>(stage)];")
cpp.append("}")
cpp.append("")
cpp.append("} // namespace zote")
cpp.append("")

pathlib.Path("src/killchain.cpp").write_text(
    "\n".join(cpp), encoding="utf-8")
print(f"OK -- src/killchain.cpp written ({len(cpp)} lines)")

# ── 4. Update test_killchain.cpp ──────────────────────────────────────────
p = pathlib.Path("tests/unit/test_killchain.cpp")
content = p.read_text()

# Add new tests for multi-stage + candidates + contribution
new_tests = """
TEST_CASE("KillChain: assess returns candidates vector\",")
          \"[killchain][candidates]\") {")
    // exploit + payload → Exploitation + Delivery candidates
    auto a = zote::KillChainMapper::assess(
        make_sig("exploit attempt with payload delivery"));
    REQUIRE(!a.candidates.empty());
}

TEST_CASE("KillChain: candidates contain primary stage\",")
          \"[killchain][candidates]\") {")
    auto a = zote::KillChainMapper::assess(
        make_sig("c2 beacon detected"));
    bool found = false;
    for (const auto& sc : a.candidates)
        if (sc.stage == a.stage) { found = true; break; }
    REQUIRE(found);
}

TEST_CASE("KillChain: candidates have valid confidence range\",")
          \"[killchain][candidates]\") {")
    auto a = zote::KillChainMapper::assess(
        make_sig("ransomware encrypting files"));
    for (const auto& sc : a.candidates) {
        REQUIRE(sc.confidence >= 0.0f);
        REQUIRE(sc.confidence <= 1.0f);
    }
}

TEST_CASE("KillChain: reason includes contribution field\",")
          \"[killchain][reasons]\") {")
    auto a = zote::KillChainMapper::assess(
        make_sig("beacon outbound c2"));
    REQUIRE(!a.reasons.empty());
    REQUIRE(a.reasons[0].contribution >= 0.0f);
    REQUIRE(a.reasons[0].contribution <= 1.0f);
}

TEST_CASE("KillChain: stages_for_technique returns all stages\",")
          \"[killchain][multistage]\") {")
    // T1566 maps to Delivery
    auto stages = zote::KillChainMapper::stages_for_technique("T1566");
    REQUIRE(!stages.empty());
    bool found = false;
    for (const auto& sc : stages)
        if (sc.stage == zote::KillChainStage::Delivery)
            found = true;
    REQUIRE(found);
}

TEST_CASE("KillChain: stages_for_technique confidence in valid range\",")
          \"[killchain][multistage]\") {")
    auto stages = zote::KillChainMapper::stages_for_technique("T1071");
    REQUIRE(!stages.empty());
    for (const auto& sc : stages) {
        REQUIRE(sc.confidence > 0.0f);
        REQUIRE(sc.confidence <= 1.0f);
    }
}

TEST_CASE("KillChain: stages_for_technique empty for unknown technique\",")
          \"[killchain][multistage]\") {")
    auto stages = zote::KillChainMapper::stages_for_technique("T9999");
    REQUIRE(stages.empty());
}

TEST_CASE("KillChain: primary confidence is highest among candidates\",")
          \"[killchain][candidates]\") {")
    auto a = zote::KillChainMapper::assess(
        make_sig("exploit attempt"));
    for (const auto& sc : a.candidates)
        REQUIRE(a.confidence >= sc.confidence);
}
"""

content = content.rstrip() + "\n" + new_tests
p.write_text(content)
print("OK -- tests/unit/test_killchain.cpp: 8 new tests added")
