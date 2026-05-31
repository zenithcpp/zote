#pragma once
// include/zote/killchain.hpp
// ZOTE — zenithcpp Open Source Threat Engine
// ISO C++23 compliant — zero external dependencies
// Apache 2.0 License — https://github.com/zenithcpp/zote
//
// Kill Chain Inference Engine (KCIE)
//
// Maps signals to Lockheed Martin kill chain stages using
// evidence-based probabilistic inference, not deterministic
// classification.
//
// ── Assessment model ─────────────────────────────────────────────────────
//
// assess() returns KillChainAssessment containing:
//   stage:      primary stage (highest confidence)
//   confidence: 0.0-1.0 for primary stage
//   reasons:    evidence explaining the primary mapping
//   candidates: ALL matching stages with individual confidence
//
// ── Mapping priority (highest to lowest) ─────────────────────────────────
//
//   1. MITRE technique ID  → confidence 0.90-0.95 (authoritative)
//   2. Description keyword → confidence 0.75       (strong signal)
//   3. Category keyword    → confidence 0.70       (weaker signal)
//   4. Unknown             → confidence 0.0        (no evidence)
//
// ── Multi-stage signals ───────────────────────────────────────────────────
//
// Some techniques span multiple kill chain stages simultaneously.
// Examples:
//   T1566.001 (Spearphishing Attachment) → Delivery + Exploitation
//   T1059 (Scripting Interpreter)        → Execution + Installation
//   T1055 (Process Injection)            → Exploitation + Privilege Esc
//
// The candidates vector contains ALL matching stages.
// The primary stage is the highest-confidence candidate.
// Callers should inspect candidates for full picture.
//
// ── MITRE many-to-many limitation (v0.1) ────────────────────────────────
//
// MITRE techniques map to multiple tactics in the official matrix.
// The current mapping forces one primary kill chain stage per
// technique ID. Full many-to-many tactic mapping planned for v0.2
// when MitreTechnique.tactics becomes a vector.
//
// ── Confidence normalization ─────────────────────────────────────────────
//
// Kill chain confidence must be combined with other engine scores
// before making autonomous decisions. Use ConfidenceNormalizer:
//
//   float combined = zote::ConfidenceNormalizer::combine(
//       detection_result.confidence,  // DetectionEngine
//       ueba_profile.anomaly_score / 10.0f, // UEBA (normalized)
//       assessment.confidence);       // KillChainMapper
//
// Default weights: detection=0.50, ueba=0.30, kill_chain=0.20
//
// ── v0.2 upgrade path ────────────────────────────────────────────────────
//
//   Feature-based inference layer (weighted feature extraction)
//   Temporal progression model (KillChainEngine instance)
//   Full MITRE many-to-many tactic mapping
//   Normalized confidence across DetectionEngine + UEBA + KCIE
//   Integration hooks → CorrelationEngine campaign builder
//
// ── Thread-safety ────────────────────────────────────────────────────────
//
//   All functions are stateless and thread-safe.
//   No shared mutable state — safe for parallel ingestion.

#include <zote/types.hpp>
#include <string>
#include <vector>

namespace zote {

class KillChainMapper {
public:
    // ── Primary API ───────────────────────────────────────────────────

    // Evidence-based assessment — preferred API.
    // Returns:
    //   stage:      primary kill chain stage
    //   confidence: 0.0-1.0 for primary stage
    //   reasons:    what triggered the mapping
    //   candidates: all matching stages (multi-stage signals)
    [[nodiscard]] static KillChainAssessment
    assess(const Signal& signal) noexcept;

    // ── Convenience API ───────────────────────────────────────────────

    // Returns primary stage only (delegates to assess()).
    // Use assess() when confidence or candidates are needed.
    [[nodiscard]] static KillChainStage
    map(const Signal& signal) noexcept;

    // Map MITRE technique ID string to primary kill chain stage.
    // Handles sub-techniques: "T1566.001" maps same as "T1566".
    // Returns Unknown if technique ID not in mapping table.
    [[nodiscard]] static KillChainStage
    from_mitre_id(const std::string& technique_id) noexcept;

    // Map TechniqueId strong type to kill chain stage.
    [[nodiscard]] static KillChainStage
    from_technique_id(const TechniqueId& tid) noexcept;

    // All kill chain stages a MITRE technique maps to.
    // Returns multiple stages for techniques that span phases.
    [[nodiscard]] static std::vector<StageConfidence>
    stages_for_technique(const std::string& technique_id);

    // ── Metadata ──────────────────────────────────────────────────────

    // Human-readable stage name.
    // e.g. KillChainStage::CommandControl -> "Command & Control"
    [[nodiscard]] static const char*
    stage_name(KillChainStage stage) noexcept;

    // MITRE tactic ID for a kill chain stage.
    // e.g. KillChainStage::Delivery -> "TA0001"
    [[nodiscard]] static const char*
    tactic(KillChainStage stage) noexcept;
};

} // namespace zote
