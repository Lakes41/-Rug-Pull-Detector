/**
 * Oracle Manipulation Risk Detector
 *
 * Detects structural vulnerabilities in token contracts that are
 * susceptible to single-block price oracle manipulation via flash loans.
 *
 * Detection modules:
 *   1. Flash Loan Pattern Recognizer — Traces historical block transactions
 *      to detect same-block borrow → swap → repay loops
 *   2. Price Sensitivity Analyzer — Calculates token price sensitivity
 *      relative to spot pool reserves under simulated high-volume swaps
 *   3. TWAP Protection Checker — Warns if token relies on spot AMM reserves
 *      without time-weighted average price (TWAP) protections
 */

// ─── Constants ───────────────────────────────────────────────────────────────

const FLASH_LOAN_SIGNATURES = [
  "flashloan",
  "flash_loan",
  "flashLoan",
  "executeOperation",
  "makerdao",
  "dssflash",
  "balancerFlashLoan",
  "aave",
  "uniswapV2FlashSwap",
  "uniswapV3Flash",
];

const LENDING_PROTOCOLS = [
  "aave",
  "compound",
  "makerdao",
  "dydx",
  "euler",
  "radiant",
  "silicon",
  "spark",
];

const TWAP_ORACLE_KEYWORDS = [
  "twap",
  "timeweighted",
  "time_weighted",
  "chainlink",
  "pricefeed",
  "price_feed",
  "latestRoundData",
  "getRoundData",
  "accumulator",
  "observation",
  "consume",
  "liquiditycheck",
  "oracle",
];

const KNOWN_TWAP_CONTRACTS = [
  "uniswapv3twap",
  "chainlink",
  "tellorflex",
  "makerosm",
  "keep3r",
  "redstone",
];

const SWAP_OPERATIONS = [
  "swap",
  "swapExactTokensForETH",
  "swapExactTokensForTokens",
  "swapExactETHForTokens",
  "swapTokensForExactETH",
  "swapTokensForExactTokens",
  "swapexacttokensforeth",
  "swapexacttokensfortokens",
  "swapexactethfortokens",
  "swaptokensforexacteth",
  "swaptokensforexacttokens",
  "swaptokensforexacttokens",
  "swapExactOut",
  "swapExactIn",
  "exactInput",
  "exactOutput",
  "exactInputSingle",
  "exactOutputSingle",
  "multihop",
];

const TRANSFER_OPERATIONS = [
  "transfer",
  "transferFrom",
  "transferfrom",
  "mint",
  "burn",
  "deposit",
  "withdraw",
];

// ─── Helpers ─────────────────────────────────────────────────────────────────

function toNumber(value) {
  if (value === "" || value === null || value === undefined) {
    return null;
  }
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function normalizeString(value) {
  if (!value) return "";
  return String(value)
    .toLowerCase()
    .replace(/[\s_-]+/g, "");
}

function getOperation(trace) {
  const raw =
    trace?.operation ||
    trace?.method ||
    trace?.functionName ||
    trace?.name ||
    trace?.type ||
    "";
  return normalizeString(raw);
}

function getFrom(trace) {
  return (
    trace?.from ||
    trace?.caller ||
    trace?.sender ||
    trace?.transaction?.from ||
    null
  );
}

function getTo(trace) {
  return (
    trace?.to ||
    trace?.contract ||
    trace?.contractId ||
    trace?.transaction?.to ||
    null
  );
}

function getValue(trace) {
  return toNumber(
    trace?.value ||
      trace?.amount ||
      trace?.transaction?.value ||
      trace?.result?.value,
  );
}

function getStatus(trace) {
  const status =
    trace?.status ?? trace?.receipt?.status ?? trace?.result?.status;
  if (trace?.reverted === true || trace?.error || trace?.revertReason)
    return "reverted";
  if (status === false || status === 0) return "reverted";
  return "success";
}

function isReverted(trace) {
  return getStatus(trace) === "reverted";
}

// ─── 1. Flash Loan Pattern Recognition ──────────────────────────────────────

/**
 * Extracts all callable traces from chainData for analysis.
 * Supports multiple trace storage formats used across adapters.
 */
function extractTraces(chainData) {
  const traces = [];

  // From rawChainData.tokenData.contractData.transactions
  const contractData =
    chainData?.tokenData?.contractData || chainData?.contractData || {};

  // Normalized contract transactions
  if (Array.isArray(contractData?.transactions)) {
    traces.push(
      ...contractData.transactions.map((tx) => ({ ...tx, source: "contract" })),
    );
  }

  // From rawChainData directly
  if (Array.isArray(chainData?.transactions)) {
    traces.push(
      ...chainData.transactions.map((tx) => ({ ...tx, source: "direct" })),
    );
  }

  // From the trade simulation call sequence (used by honeypotDetector)
  const callSequence = [
    ...asArray(chainData?.tradeSimulation?.callSequence),
    ...asArray(chainData?.tradeSimulation?.traces),
    ...asArray(chainData?.simulationTraces),
    ...asArray(chainData?.callSequence),
  ];
  if (callSequence.length > 0) {
    traces.push(...callSequence.map((t) => ({ ...t, source: "simulation" })));
  }

  // From issuer transaction history (Stellar)
  const issuerData = chainData?.issuerData || {};
  if (Array.isArray(issuerData?.transactions)) {
    traces.push(
      ...issuerData.transactions.map((tx) => ({ ...tx, source: "issuer" })),
    );
  }

  // From normalized chain data events
  const events = chainData?.events || chainData?.normalizedEvents || [];
  if (Array.isArray(events)) {
    traces.push(...events.map((e) => ({ ...e, source: "events" })));
  }

  return traces;
}

/**
 * Checks if a trace or its metadata contains flash loan signatures.
 */
function isFlashLoanCall(trace) {
  const op = getOperation(trace);
  const rawOp = trace?.operation || trace?.method || trace?.type || "";
  const rawName = normalizeString(rawOp);

  // Direct flash loan operation match
  if (
    FLASH_LOAN_SIGNATURES.some((sig) => rawName.includes(normalizeString(sig)))
  ) {
    return true;
  }

  // Check function signature / selector
  const sig =
    trace?.functionSignature ||
    trace?.selector ||
    trace?.input?.slice(0, 10) ||
    "";
  // Common flash loan selectors: aave, balancer, uniswapV3
  if (sig) {
    const s = normalizeString(sig);
    if (FLASH_LOAN_SIGNATURES.some((sig) => s.includes(normalizeString(sig)))) {
      return true;
    }
  }

  // Check if any lending protocol is referenced in the trace
  const fullText = JSON.stringify(trace || {}).toLowerCase();
  if (
    LENDING_PROTOCOLS.some((proto) => fullText.includes(proto)) &&
    fullText.includes("loan")
  ) {
    return true;
  }

  return false;
}

/**
 * Detects flash loan patterns from extracted traces.
 *
 * Strategy:
 * 1. Scan traces for flash loan calls (borrow events)
 * 2. Within the same trace group, look for swap operations that
 *    could represent the price manipulation phase
 * 3. Cross-reference with repayment/transfer patterns
 * 4. Heuristically flag if borrow → multiple swaps → repay detected
 */
function detectFlashLoanPatterns(traces) {
  const findings = {
    detected: false,
    flashLoanCalls: [],
    swapCalls: [],
    transferCalls: [],
    patternType: null, // 'classic_triangle' | 'multi_pool' | 'sandwich' | null
    confidence: 0, // 0–1
    details: [],
  };

  if (traces.length === 0) {
    findings.details.push("No traces available for analysis");
    return findings;
  }

  // Classify traces
  for (const trace of traces) {
    const op = getOperation(trace);

    if (isFlashLoanCall(trace)) {
      findings.flashLoanCalls.push(trace);
    }

    if (SWAP_OPERATIONS.some((s) => op.includes(normalizeString(s)))) {
      if (!isReverted(trace)) {
        findings.swapCalls.push(trace);
      }
    }

    if (TRANSFER_OPERATIONS.some((t) => op.includes(normalizeString(t)))) {
      if (!isReverted(trace)) {
        findings.transferCalls.push(trace);
      }
    }
  }

  // Analyze pattern
  const hasFlashLoan = findings.flashLoanCalls.length > 0;
  const hasSwap = findings.swapCalls.length > 1; // Need at least 2 swaps for triangle
  const hasSignificantTransfer = findings.transferCalls.length > 2;

  if (hasFlashLoan && hasSwap) {
    findings.detected = true;
    findings.confidence = Math.min(
      0.5 +
        (hasSignificantTransfer ? 0.3 : 0) +
        (findings.flashLoanCalls.length >= 1 ? 0.1 : 0) +
        (findings.swapCalls.length >= 3 ? 0.1 : 0),
      1.0,
    );

    if (
      findings.flashLoanCalls.length === 1 &&
      findings.swapCalls.length >= 2
    ) {
      findings.patternType = "classic_triangle";
      findings.details.push(
        `Detected classic flash loan triangle: 1 borrow → ${findings.swapCalls.length} swap operations`,
      );
    } else {
      findings.patternType = "multi_pool";
      findings.details.push(
        `Detected multi-pool flash loan pattern: ${findings.flashLoanCalls.length} borrow(s), ${findings.swapCalls.length} swap(s)`,
      );
    }

    if (hasSignificantTransfer) {
      findings.details.push(
        "Large transfer/repayment activity detected post-swap sequence",
      );
    }
  } else if (hasSwap && findings.swapCalls.length >= 3) {
    // Even without explicit flash loan call, many swaps in same context is suspicious
    findings.detected = true;
    findings.confidence = 0.3;
    findings.patternType = "sandwich";
    findings.details.push(
      "No explicit flash loan calls but high swap density detected — possible sandwich/sniping pattern",
    );
  } else {
    findings.details.push(
      "No flash loan patterns detected in available traces",
    );
  }

  return findings;
}

// ─── 2. Price Sensitivity Analysis ──────────────────────────────────────────

/**
 * Attempts to extract pool reserve data from chainData.
 *
 * Looks in multiple locations:
 * - rawChainData.poolReserves
 * - rawChainData.tokenData.contractData.metadata
 * - rawChainData.tradeSimulation.storage
 * - Can use overrides if provided
 */
function extractPoolReserves(chainData, overrides = {}) {
  // Priority 1: Direct overrides
  if (overrides.reserve0 !== undefined && overrides.reserve1 !== undefined) {
    return {
      reserve0: toNumber(overrides.reserve0),
      reserve1: toNumber(overrides.reserve1),
      token0: overrides.token0 || "token0",
      token1: overrides.token1 || "token1",
    };
  }

  // Priority 2: Explicit poolReserves field in chainData
  const poolReserves =
    chainData?.poolReserves || chainData?.pool_reserves || {};

  if (
    poolReserves.reserve0 !== undefined &&
    poolReserves.reserve1 !== undefined
  ) {
    return {
      reserve0: toNumber(poolReserves.reserve0),
      reserve1: toNumber(poolReserves.reserve1),
      token0: poolReserves.token0 || "token0",
      token1: poolReserves.token1 || "token1",
    };
  }

  // Priority 3: From storage snapshots (used by honeypot detector)
  const storage =
    chainData?.tradeSimulation?.storage ||
    chainData?.storage ||
    chainData?.storageSnapshots?.afterTrade ||
    chainData?.storageSnapshots?.preTrade ||
    {};

  if (storage.reserve0 !== undefined && storage.reserve1 !== undefined) {
    return {
      reserve0: toNumber(storage.reserve0),
      reserve1: toNumber(storage.reserve1),
      token0: storage.token0 || "token0",
      token1: storage.token1 || "token1",
    };
  }

  // Priority 4: From contract metadata
  const metadata =
    chainData?.tokenData?.contractData?.metadata ||
    chainData?.contractData?.metadata ||
    {};
  if (metadata.reserve0 !== undefined && metadata.reserve1 !== undefined) {
    return {
      reserve0: toNumber(metadata.reserve0),
      reserve1: toNumber(metadata.reserve1),
      token0: metadata.token0 || "token0",
      token1: metadata.token1 || "token1",
    };
  }

  // Fallback: Unable to find reserves
  return null;
}

/**
 * Given pool reserves (reserve0, reserve1), simulates constant-product swaps
 * at various sizes and computes price impact.
 *
 * Uses the constant product formula: k = reserve0 * reserve1
 * Price impact = (executionPrice - spotPrice) / spotPrice
 *
 * @param {object} reserves - { reserve0, reserve1, token0, token1 }
 * @returns {object|null} Price sensitivity analysis
 */
function calculatePriceSensitivity(reserves) {
  if (!reserves) {
    return null;
  }

  const r0 = toNumber(reserves.reserve0);
  const r1 = toNumber(reserves.reserve1);

  if (r0 === null || r1 === null || r0 <= 0 || r1 <= 0) {
    return null;
  }

  // Constant product: k = r0 * r1
  const k = r0 * r1;

  // Spot price: how many token1 per token0
  const spotPrice = r1 / r0;

  // Swap sizes to simulate (percentage of pool)
  const swapSizes = [0.01, 0.05, 0.1, 0.25, 0.5];
  const impactLevels = [];

  for (const pct of swapSizes) {
    const amountIn = r0 * pct; // amount of token0 to swap in
    // amountOut = (amountIn * r1) / (r0 + amountIn)  (with fee abstracted)
    const amountOut = (amountIn * r1) / (r0 + amountIn);
    const executionPrice = amountOut / amountIn;
    const priceImpactBps =
      Math.abs((executionPrice - spotPrice) / spotPrice) * 10000;

    impactLevels.push({
      swapSizePct: pct * 100,
      amountIn,
      amountOut,
      executionPrice,
      priceImpactBps: Math.round(priceImpactBps),
    });
  }

  // Max single-block deviation: worst-case impact from the largest swap size
  const maxDeviation =
    impactLevels[impactLevels.length - 1]?.priceImpactBps || 0;

  return {
    spotPrice,
    reserve0: r0,
    reserve1: r1,
    k,
    impactLevels,
    maxSingleBlockDeviation: maxDeviation,
    sensitivityLevel:
      maxDeviation < 100
        ? "low"
        : maxDeviation < 500
        ? "medium"
        : maxDeviation < 2000
        ? "high"
        : "critical",
  };
}

// ─── 3. TWAP Protection Check ───────────────────────────────────────────────

/**
 * Analyzes chainData to determine if the token contract uses TWAP oracles.
 *
 * Strategy:
 * 1. Check if rawChainData contains explicit TWAP oracle references
 * 2. Look at contract bytecode / metadata for known TWAP implementations
 * 3. Check for Chainlink price feed integration
 * 4. Fall back to heuristic: if no oracle detected, assume vulnerable
 */
function checkTWAPProtection(chainData) {
  const findings = {
    hasTWAP: false,
    protectionLevel: "none", // 'none' | 'partial' | 'full'
    oracleReferences: [],
    details: [],
  };

  const fullContext = [
    chainData,
    chainData?.tokenData || {},
    chainData?.contractData || {},
    chainData?.issuerData || {},
    chainData?.tokenData?.contractData || {},
    chainData?.contractData?.metadata || {},
    chainData?.tokenData?.contractData?.metadata || {},
    chainData?.tradeSimulation || {},
  ];

  // Collect all text from the context for keyword matching
  const allTexts = [];

  for (const ctx of fullContext) {
    try {
      allTexts.push(JSON.stringify(ctx).toLowerCase());
    } catch {
      // Skip circular references
    }
  }

  const combinedText = allTexts.join(" ");

  // Check for explicit TWAP oracle references
  for (const keyword of TWAP_ORACLE_KEYWORDS) {
    if (combinedText.includes(keyword)) {
      findings.oracleReferences.push(keyword);
    }
  }

  // Check for known TWAP contract patterns
  for (const contract of KNOWN_TWAP_CONTRACTS) {
    if (combinedText.includes(contract)) {
      if (!findings.oracleReferences.includes(contract)) {
        findings.oracleReferences.push(contract);
      }
    }
  }

  // Analyze protection level
  if (findings.oracleReferences.length > 0) {
    const refs = new Set(findings.oracleReferences.map((r) => r.toLowerCase()));

    // Full TWAP protection: references Uniswap V3 TWAP or similar
    if (
      refs.has("twap") ||
      refs.has("timeweighted") ||
      refs.has("time_weighted") ||
      refs.has("accumulator") ||
      refs.has("observation")
    ) {
      findings.hasTWAP = true;
      findings.protectionLevel = "full";
      findings.details.push(
        "TWAP oracle detected — token is protected against single-block manipulation",
      );
    }
    // Partial: Chainlink or other price feeds (may still be manipulable if spot-based)
    else if (
      refs.has("chainlink") ||
      refs.has("pricefeed") ||
      refs.has("price_feed")
    ) {
      findings.hasTWAP = true;
      findings.protectionLevel = "partial";
      findings.details.push(
        "Chainlink-style price feed detected — provides decentralized price data, but TWAP is preferred",
      );
    }
    // Low confidence: some oracle references found but unclear
    else {
      findings.hasTWAP = false;
      findings.protectionLevel = "partial";
      findings.details.push(
        `Oracle references found (${findings.oracleReferences.join(
          ", ",
        )}) but no confirmed TWAP implementation`,
      );
    }
  } else {
    // No oracle references found — assume spot-price based
    findings.hasTWAP = false;
    findings.protectionLevel = "none";
    findings.details.push(
      "No TWAP oracle detected — token likely relies on spot AMM reserves, vulnerable to single-block manipulation",
    );
  }

  return findings;
}

// ─── 4. Main Entry Point ────────────────────────────────────────────────────

/**
 * Analyzes chain data for oracle manipulation vulnerabilities.
 *
 * @param {object} chainData - Raw chain data from adapters (rawChainData)
 * @param {object} [overrides] - Optional override parameters
 * @param {number} [overrides.reserve0] - Override pool reserve0
 * @param {number} [overrides.reserve1] - Override pool reserve1
 * @returns {object} OracleManipulationRisk analysis result
 */
export function analyzeOracleManipulationRisk(chainData = {}, overrides = {}) {
  // 1. Extract and analyze traces for flash loan patterns
  const traces = extractTraces(chainData);
  const flashLoanAnalysis = detectFlashLoanPatterns(traces);

  // 2. Calculate price sensitivity from pool reserves
  const reserves = extractPoolReserves(chainData, overrides);
  const priceSensitivity = calculatePriceSensitivity(reserves);

  // 3. Check for TWAP protection
  const twapProtection = checkTWAPProtection(chainData);

  // 4. Compute overall score
  let score = 0;
  const warnings = [];

  // Flash loan component (up to 0.35)
  if (flashLoanAnalysis.detected) {
    score += flashLoanAnalysis.confidence * 0.35;
    if (flashLoanAnalysis.patternType === "classic_triangle") {
      warnings.push(
        "Classic flash loan triangle pattern detected: borrow → swap(s) → repay in single-block context",
      );
    } else if (flashLoanAnalysis.patternType === "multi_pool") {
      warnings.push(
        "Multi-pool flash loan activity detected — potential cross-protocol manipulation",
      );
    } else {
      warnings.push(
        "Suspicious swap density detected — possible sandwich attack pattern",
      );
    }
  }

  // Price sensitivity component (up to 0.35)
  if (priceSensitivity) {
    if (priceSensitivity.sensitivityLevel === "critical") {
      score += 0.35;
      warnings.push(
        `Critical price sensitivity: ${priceSensitivity.maxSingleBlockDeviation.toLocaleString()} bps deviation from a single block swap`,
      );
    } else if (priceSensitivity.sensitivityLevel === "high") {
      score += 0.25;
      warnings.push(
        `High price sensitivity: ${priceSensitivity.maxSingleBlockDeviation.toLocaleString()} bps potential deviation`,
      );
    } else if (priceSensitivity.sensitivityLevel === "medium") {
      score += 0.15;
      warnings.push(
        `Moderate price sensitivity: ${priceSensitivity.maxSingleBlockDeviation.toLocaleString()} bps deviation`,
      );
    }
  } else {
    // If we can't calculate, assume worst case + flag
    score += 0.2;
    warnings.push(
      "Unable to calculate pool reserves — assuming vulnerable spot-price oracle",
    );
  }

  // TWAP protection component (up to 0.30)
  if (twapProtection.protectionLevel === "none") {
    score += 0.3;
    warnings.push(
      "Token relies on spot AMM reserves without TWAP protection — highly vulnerable to single-block price manipulation",
    );
  } else if (twapProtection.protectionLevel === "partial") {
    score += 0.15;
    warnings.push(
      "Partial oracle protection detected — consider migrating to TWAP-based oracle",
    );
  }

  // 5. Determine severity level
  const flagged = score >= 0.35;
  let severity;
  if (score >= 0.75) {
    severity = "critical";
  } else if (score >= 0.55) {
    severity = "high";
  } else if (score >= 0.35) {
    severity = "medium";
  } else {
    severity = "low";
  }

  return {
    score: Math.min(Math.round(score * 100) / 100, 1),
    flagged,
    severity,
    flashLoanAnalysis,
    priceSensitivity,
    twapProtection,
    warnings,
  };
}
