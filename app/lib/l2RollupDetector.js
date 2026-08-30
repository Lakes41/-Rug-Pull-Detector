/**
 * Layer 2 Rollup Centralization & Exit Risk Detector
 *
 * Evaluates target L2 token contracts for force-inclusion mechanisms and L1 escape hatch functions.
 * Tracks active sequencer status and computes finality risk ratings based on bridge withdrawal challenge delays.
 * Generates explicit L2 centralization parameters and sequencer dependency warnings for token reports.
 */

const FORCE_INCLUSION_SIGNATURES = [
  "forceinclusion",
  "forceincludetx",
  "deposittransaction",
  "enqueuetransaction",
  "enqueue",
  "forceinclusionenabled",
  "force_inclusion",
  "force_include",
  "l1tol2message",
];

const ESCAPE_HATCH_SIGNATURES = [
  "escapehatch",
  "withdrawtol1",
  "emergencyexit",
  "forcewithdraw",
  "exittol1",
  "emergencywithdrawal",
  "l1escapehatch",
  "withdrawtoparent",
  "directexit",
];

function normalizeString(value) {
  if (!value) return "";
  return String(value)
    .toLowerCase()
    .replace(/[\s_-]+/g, "");
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

/**
 * Extracts method names, ABI signatures, and bytecode text from chainData context.
 */
function extractContractMethods(chainData) {
  const methods = [];
  const fullText = [];

  const contractData =
    chainData?.tokenData?.contractData || chainData?.contractData || {};
  const metadata = contractData?.metadata || {};

  if (Array.isArray(contractData?.abi)) {
    for (const item of contractData.abi) {
      if (item?.name) methods.push(String(item.name));
    }
  }

  if (Array.isArray(metadata?.abiMethods)) {
    for (const m of metadata.abiMethods) {
      methods.push(String(m));
    }
  }

  if (Array.isArray(chainData?.abiMethods)) {
    for (const m of chainData.abiMethods) {
      methods.push(String(m));
    }
  }

  try {
    fullText.push(JSON.stringify(chainData || {}).toLowerCase());
  } catch {
    // Ignore circular reference errors
  }

  return {
    methods,
    combinedText: fullText.join(" "),
  };
}

/**
 * Evaluates target L2 token contracts for force-inclusion mechanisms and L1 escape hatch functions.
 */
export function evaluateContractExitMechanisms(chainData = {}, overrides = {}) {
  if (overrides.forceInclusionEnabled !== undefined && overrides.escapeHatchAvailable !== undefined) {
    return {
      forceInclusionSupported: Boolean(overrides.forceInclusionEnabled),
      escapeHatchSupported: Boolean(overrides.escapeHatchAvailable),
      detectedForceMethods: overrides.detectedForceMethods || [],
      detectedEscapeMethods: overrides.detectedEscapeMethods || [],
    };
  }

  const { methods, combinedText } = extractContractMethods(chainData);
  const detectedForceMethods = [];
  const detectedEscapeMethods = [];

  for (const m of methods) {
    const norm = normalizeString(m);
    if (FORCE_INCLUSION_SIGNATURES.some((sig) => norm.includes(sig))) {
      detectedForceMethods.push(m);
    }
    if (ESCAPE_HATCH_SIGNATURES.some((sig) => norm.includes(sig))) {
      detectedEscapeMethods.push(m);
    }
  }

  // Check combined text if methods were empty
  if (detectedForceMethods.length === 0) {
    for (const sig of FORCE_INCLUSION_SIGNATURES) {
      if (combinedText.includes(sig)) {
        detectedForceMethods.push(sig);
      }
    }
  }

  if (detectedEscapeMethods.length === 0) {
    for (const sig of ESCAPE_HATCH_SIGNATURES) {
      if (combinedText.includes(sig)) {
        detectedEscapeMethods.push(sig);
      }
    }
  }

  const forceInclusionSupported =
    overrides.forceInclusionEnabled !== undefined
      ? Boolean(overrides.forceInclusionEnabled)
      : detectedForceMethods.length > 0;

  const escapeHatchSupported =
    overrides.escapeHatchAvailable !== undefined
      ? Boolean(overrides.escapeHatchAvailable)
      : detectedEscapeMethods.length > 0;

  return {
    forceInclusionSupported,
    escapeHatchSupported,
    detectedForceMethods: Array.from(new Set(detectedForceMethods)),
    detectedEscapeMethods: Array.from(new Set(detectedEscapeMethods)),
  };
}

/**
 * Tracks active sequencer operating status.
 */
export function trackSequencerStatus(chainData = {}, overrides = {}) {
  if (overrides.sequencerStatus) {
    return String(overrides.sequencerStatus).toLowerCase();
  }

  const status =
    chainData?.sequencerStatus ||
    chainData?.l2Data?.sequencerStatus ||
    chainData?.rollupInfo?.sequencerStatus ||
    "active";

  return String(status).toLowerCase();
}

/**
 * Computes finality risk ratings based on bridge withdrawal challenge delays and L2 mechanisms.
 */
export function computeFinalityRisk(
  challengeWindowSeconds,
  sequencerStatus,
  escapeHatchSupported,
  forceInclusionSupported,
  rollupType = "optimistic",
) {
  let score = 0;

  // Bridge withdrawal delay component (7 days = 604800s => 0.35 max delay score)
  const delayRatio = Math.min(challengeWindowSeconds / 604800, 1.0);
  score += delayRatio * 0.35;

  // Sequencer status impact
  if (["halted", "down"].includes(sequencerStatus)) {
    if (!escapeHatchSupported) {
      score += 0.65;
    } else {
      score += 0.4;
    }
  } else if (sequencerStatus === "degraded") {
    if (!forceInclusionSupported) {
      score += 0.4;
    } else {
      score += 0.2;
    }
  } else {
    // active sequencer
    if (!forceInclusionSupported) {
      score += 0.2;
    }
    if (!escapeHatchSupported) {
      score += 0.15;
    }
  }

  // Rollup type modifier
  if (rollupType === "optimistic" && challengeWindowSeconds >= 604800 && !escapeHatchSupported) {
    score += 0.15;
  } else if (rollupType === "zk_rollup" && escapeHatchSupported) {
    score = Math.max(0, score - 0.1);
  }

  const normalizedScore = Math.min(Math.max(score, 0), 1.0);

  let rating;
  if (normalizedScore >= 0.8) {
    rating = "critical";
  } else if (normalizedScore >= 0.55) {
    rating = "high";
  } else if (normalizedScore >= 0.3) {
    rating = "medium";
  } else {
    rating = "low";
  }

  return {
    rating,
    score: Math.round(normalizedScore * 100) / 100,
  };
}

/**
 * Main entry point: Analyzes L2 rollup centralization and exit risks.
 *
 * @param {object} chainData - Chain and contract data
 * @param {object} [overrides] - Override parameters
 * @returns {object} Analysis result containing explicit L2 centralization parameters and warnings
 */
export function analyzeL2RollupRisk(chainData = {}, overrides = {}) {
  // 1. Evaluate force inclusion & escape hatches
  const exitMechanisms = evaluateContractExitMechanisms(chainData, overrides);

  // 2. Track active sequencer status
  const sequencerStatus = trackSequencerStatus(chainData, overrides);

  // 3. Extract rollup type and challenge window delay
  const rollupType = String(
    overrides.rollupType ||
      chainData?.rollupType ||
      chainData?.l2Data?.rollupType ||
      "optimistic",
  ).toLowerCase();

  const defaultDelay = rollupType === "optimistic" ? 604800 : 3600;
  const challengeWindowSeconds = Number(
    overrides.challengeWindowSeconds ??
      chainData?.challengeWindowSeconds ??
      chainData?.l2Data?.challengeWindowSeconds ??
      defaultDelay,
  );
  const challengeWindowDays = Math.round((challengeWindowSeconds / 86400) * 100) / 100;

  // 4. Compute finality risk rating
  const finalityRisk = computeFinalityRisk(
    challengeWindowSeconds,
    sequencerStatus,
    exitMechanisms.escapeHatchSupported,
    exitMechanisms.forceInclusionSupported,
    rollupType,
  );

  // 5. Build explicit L2 centralization parameters
  const centralizationParameters = {
    rollupType,
    sequencerStatus,
    challengeWindowSeconds,
    challengeWindowDays,
    forceInclusionEnabled: exitMechanisms.forceInclusionSupported,
    escapeHatchAvailable: exitMechanisms.escapeHatchSupported,
    sequencerAddress:
      overrides.sequencerAddress ||
      chainData?.sequencerAddress ||
      chainData?.l2Data?.sequencerAddress ||
      null,
    l1BridgeAddress:
      overrides.l1BridgeAddress ||
      chainData?.l1BridgeAddress ||
      chainData?.l2Data?.l1BridgeAddress ||
      null,
  };

  // 6. Generate sequencer dependency warnings
  const warnings = [];

  if (["halted", "down"].includes(sequencerStatus)) {
    if (!exitMechanisms.escapeHatchSupported) {
      warnings.push(
        "CRITICAL: Sequencer is HALTED and contract lacks L1 escape hatch. User funds locked until sequencer recovers.",
      );
    } else {
      warnings.push(
        "HIGH: Sequencer is HALTED. L1 escape hatch available, but bridge withdrawal delay applies.",
      );
    }
  } else if (sequencerStatus === "degraded") {
    warnings.push(
      "WARNING: Sequencer is operating in DEGRADED status. Transaction processing may be delayed.",
    );
  }

  if (!exitMechanisms.forceInclusionSupported) {
    warnings.push(
      "CENTRALIZATION RISK: No force-inclusion mechanism detected. Sequencer can censor user transactions.",
    );
  }

  if (!exitMechanisms.escapeHatchSupported) {
    warnings.push(
      "EXIT RISK: No explicit L1 escape hatch functions detected for emergency withdrawal if sequencer halts.",
    );
  }

  if (challengeWindowSeconds >= 604800) {
    warnings.push(
      `FINALITY DELAY: Bridge withdrawal challenge window is ${challengeWindowDays} days (${challengeWindowSeconds} seconds).`,
    );
  }

  const flagged = finalityRisk.score >= 0.35 || warnings.length > 0;

  return {
    score: finalityRisk.score,
    flagged,
    finalityRiskRating: finalityRisk.rating,
    forceInclusionSupported: exitMechanisms.forceInclusionSupported,
    escapeHatchSupported: exitMechanisms.escapeHatchSupported,
    detectedForceMethods: exitMechanisms.detectedForceMethods,
    detectedEscapeMethods: exitMechanisms.detectedEscapeMethods,
    sequencerStatus,
    rollupType,
    challengeWindowSeconds,
    challengeWindowDays,
    centralizationParameters,
    warnings,
  };
}
