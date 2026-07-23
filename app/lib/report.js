import { analyzeDynamicHoneypotSignals } from "./honeypotDetector";
import { analyzeOracleManipulationRisk } from "./oracleManipulationDetector";

const BACKEND_API_BASE_URL =
  process.env.BACKEND_API_BASE_URL || "http://127.0.0.1:8080";

function toNumber(value) {
  if (value === "" || value === null || value === undefined) {
    return null;
  }

  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

export function buildAnalyzePayload(input) {
  return {
    token_address: input.tokenAddress,
    total_supply: toNumber(input.totalSupply),
    creator_balance: toNumber(input.creatorBalance),
    locked_liquidity: toNumber(input.lockedLiquidity),
    total_liquidity: toNumber(input.totalLiquidity),
    is_potential_honeypot:
      input.isPotentialHoneypot === true ||
      input.isPotentialHoneypot === "true",
    chain_id: input.chainId || null,
    normalized_chain_data: input.normalizedChainData || null,
  };
}

export function isValidAnalyzePayload(payload) {
  return Boolean(
    payload.token_address &&
      payload.total_supply !== null &&
      payload.creator_balance !== null &&
      payload.locked_liquidity !== null &&
      payload.total_liquidity !== null,
  );
}

export function normalizeAnalysisResult(payload, apiData) {
  const chainData = payload.normalized_chain_data || {};
  const detector = analyzeDynamicHoneypotSignals(chainData);
  const oracleManipulation = analyzeOracleManipulationRisk(chainData);
  const backendScore = typeof apiData?.score === "number" ? apiData.score : 0;
  const score = Math.max(
    backendScore,
    detector.score,
    oracleManipulation.score,
  );
  const backendRiskLevel = apiData?.riskLevel || apiData?.risk_level || null;

  // Determine risk level incorporating oracle manipulation findings
  let riskLevel;
  if (detector.flagged && score >= 0.8) {
    riskLevel = "Critical";
  } else if (detector.flagged) {
    riskLevel = "High";
  } else if (
    oracleManipulation.flagged &&
    oracleManipulation.severity === "critical"
  ) {
    riskLevel = "Critical";
  } else if (
    oracleManipulation.flagged &&
    oracleManipulation.severity === "high"
  ) {
    riskLevel = "High";
  } else {
    riskLevel = backendRiskLevel || "Low";
  }

  return {
    ...apiData,
    tokenAddress: payload.token_address,
    chainId: payload.chain_id,
    detector,
    oracleManipulation,
    components: {
      creatorOwnership: apiData?.components?.creatorOwnership ?? 0,
      liquidityLock: apiData?.components?.liquidityLock ?? 0,
      honeypot: apiData?.components?.honeypot ?? 0,
      gasDelta: detector.score,
      dynamicTax: detector.dynamicTax.flagged ? 1 : 0,
      conditionalReverts: detector.conditionalReverts.flagged ? 1 : 0,
      oracleManipulation: oracleManipulation.score,
    },
    riskLevel,
    score,
    reportHref: buildReportHref({
      tokenAddress: payload.token_address,
      totalSupply: payload.total_supply,
      creatorBalance: payload.creator_balance,
      lockedLiquidity: payload.locked_liquidity,
      totalLiquidity: payload.total_liquidity,
      isPotentialHoneypot: payload.is_potential_honeypot,
      chainId: payload.chain_id,
    }),
  };
}

export function buildReportHref(input) {
  const params = new URLSearchParams({
    totalSupply: String(input.totalSupply),
    creatorBalance: String(input.creatorBalance),
    lockedLiquidity: String(input.lockedLiquidity),
    totalLiquidity: String(input.totalLiquidity),
    isPotentialHoneypot: String(Boolean(input.isPotentialHoneypot)),
    ...(input.chainId ? { chainId: String(input.chainId) } : {}),
  });

  return `/reports/${encodeURIComponent(
    input.tokenAddress,
  )}?${params.toString()}`;
}

export async function fetchTokenAnalysis(payload) {
  const response = await fetch(`${BACKEND_API_BASE_URL}/api/analyze`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Backend request failed with status ${response.status}`);
  }

  return response.json();
}
