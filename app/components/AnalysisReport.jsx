import Link from "next/link";
import {
  AlertTriangle,
  CheckCircle,
  Clock,
  Database,
  Shield,
  XCircle,
} from "lucide-react";

function getRiskLevelColor(level) {
  switch (level) {
    case "Low":
      return "text-success-400 bg-success-500/20 border-success-500/50";
    case "Medium":
      return "text-yellow-400 bg-yellow-500/20 border-yellow-500/50";
    case "High":
      return "text-orange-400 bg-orange-500/20 border-orange-500/50";
    case "Critical":
      return "text-danger-400 bg-danger-500/20 border-danger-500/50";
    default:
      return "text-gray-400 bg-gray-500/20 border-gray-500/50";
  }
}

function getRiskIcon(level) {
  switch (level) {
    case "Low":
      return <CheckCircle className="h-5 w-5" />;
    case "Medium":
      return <AlertTriangle className="h-5 w-5" />;
    case "High":
      return <AlertTriangle className="h-5 w-5" />;
    case "Critical":
      return <XCircle className="h-5 w-5" />;
    default:
      return <Shield className="h-5 w-5" />;
  }
}

function formatPercent(value) {
  return `${(value * 100).toFixed(1)}%`;
}

function formatBps(value) {
  if (value === null || value === undefined) {
    return "n/a";
  }

  return `${value.toFixed(0)} bps`;
}

export default function AnalysisReport({
  tokenAddress,
  analysis,
  generatedAt,
  chainId,
}) {
  const detector = analysis.detector || {};
  const gasByOperation = detector.gas?.gasByOperation || {};
  const gasDeltas = detector.gas?.deltas || {};
  const storageChanges = detector.dynamicTax?.changedSlots || [];
  const reverts = detector.conditionalReverts || {};
  const oracle = analysis.oracleManipulation || {};
  const priceSensitivity = oracle.priceSensitivity || {};
  const flashLoan = oracle.flashLoanAnalysis || {};

  return (
    <div className="min-h-screen text-white">
      <header className="glass-card m-4 p-6">
        <div className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="rounded-xl bg-primary-500 p-3">
              <Shield className="h-8 w-8" />
            </div>
            <div>
              <p className="text-sm uppercase tracking-[0.25em] text-primary-300">
                Public Token Report
              </p>
              <h1 className="text-2xl font-bold">{tokenAddress}</h1>
            </div>
          </div>
          <div
            className={`flex items-center gap-2 rounded-full border px-4 py-2 text-sm font-medium ${getRiskLevelColor(
              analysis.riskLevel,
            )}`}
          >
            {getRiskIcon(analysis.riskLevel)}
            <span>{analysis.riskLevel} Risk</span>
          </div>
        </div>
      </header>

      <main className="container mx-auto grid gap-8 px-4 py-8 lg:grid-cols-[1.35fr_0.85fr]">
        <section className="glass-card p-6">
          <div className="flex items-center justify-between gap-4">
            <div>
              <h2 className="text-xl font-bold">Risk Summary</h2>
              <p className="mt-2 text-gray-300">
                Server-rendered report for SEO, social previews, and direct
                linking.
              </p>
            </div>
            <div className="text-right text-sm text-gray-400">
              <div className="flex items-center justify-end gap-2">
                <Clock className="h-4 w-4" />
                <span>{generatedAt}</span>
              </div>
            </div>
          </div>

          <div className="mt-8 rounded-2xl border border-white/10 bg-white/5 p-6">
            <p className="text-sm uppercase tracking-[0.25em] text-gray-400">
              Model Score
            </p>
            <p className="mt-2 text-5xl font-bold">
              {formatPercent(analysis.score)}
            </p>
            <p className="mt-3 max-w-2xl text-gray-300">
              Higher scores indicate stronger rug-pull signals based on creator
              ownership, liquidity protection, honeypot behavior, oracle
              manipulation vulnerabilities, and execution-path anomalies.
            </p>
          </div>

          <div className="mt-8 grid gap-4 md:grid-cols-4">
            <div className="rounded-xl border border-white/10 bg-white/5 p-4">
              <p className="text-sm text-gray-400">Creator Ownership</p>
              <p className="mt-2 text-2xl font-semibold">
                {formatPercent(analysis.components.creatorOwnership)}
              </p>
            </div>
            <div className="rounded-xl border border-white/10 bg-white/5 p-4">
              <p className="text-sm text-gray-400">Liquidity Lock</p>
              <p className="mt-2 text-2xl font-semibold">
                {formatPercent(analysis.components.liquidityLock)}
              </p>
            </div>
            <div className="rounded-xl border border-white/10 bg-white/5 p-4">
              <p className="text-sm text-gray-400">Honeypot Signal</p>
              <p className="mt-2 text-2xl font-semibold">
                {formatPercent(analysis.components.honeypot)}
              </p>
            </div>
            <div className="rounded-xl border border-white/10 bg-white/5 p-4">
              <p className="text-sm text-gray-400">Oracle Manipulation</p>
              <p className="mt-2 text-2xl font-semibold">
                {formatPercent(analysis.components.oracleManipulation || 0)}
              </p>
            </div>
          </div>

          {analysis.detector ? (
            <section className="mt-8 rounded-2xl border border-white/10 bg-white/5 p-6">
              <h3 className="text-lg font-semibold">
                Dynamic Honeypot Signals
              </h3>
              <div className="mt-4 grid gap-4 md:grid-cols-3">
                <div className="rounded-xl border border-white/10 bg-black/10 p-4">
                  <p className="text-sm text-gray-400">Gas Delta Score</p>
                  <p className="mt-2 text-2xl font-semibold">
                    {formatPercent(detector.score || 0)}
                  </p>
                </div>
                <div className="rounded-xl border border-white/10 bg-black/10 p-4">
                  <p className="text-sm text-gray-400">Dynamic Tax</p>
                  <p className="mt-2 text-2xl font-semibold">
                    {detector.dynamicTax?.flagged ? "Flagged" : "Clear"}
                  </p>
                </div>
                <div className="rounded-xl border border-white/10 bg-black/10 p-4">
                  <p className="text-sm text-gray-400">Conditional Reverts</p>
                  <p className="mt-2 text-2xl font-semibold">
                    {reverts.flagged ? "Flagged" : "Clear"}
                  </p>
                </div>
              </div>

              <div className="mt-6 grid gap-4 md:grid-cols-2">
                <div>
                  <h4 className="text-sm uppercase tracking-[0.2em] text-gray-400">
                    Gas Usage
                  </h4>
                  <div className="mt-3 space-y-2 text-sm text-gray-300">
                    {Object.entries(gasByOperation).length > 0 ? (
                      Object.entries(gasByOperation).map(
                        ([operation, value]) => (
                          <div
                            key={operation}
                            className="flex items-center justify-between rounded-lg border border-white/10 bg-black/10 px-3 py-2"
                          >
                            <span>{operation}</span>
                            <span>{value.toFixed(0)} gas</span>
                          </div>
                        ),
                      )
                    ) : (
                      <p>No trade trace data supplied.</p>
                    )}
                  </div>
                </div>

                <div>
                  <h4 className="text-sm uppercase tracking-[0.2em] text-gray-400">
                    Storage and Reverts
                  </h4>
                  <div className="mt-3 space-y-2 text-sm text-gray-300">
                    <div className="rounded-lg border border-white/10 bg-black/10 px-3 py-2">
                      Max tax before trade:{" "}
                      {formatBps(detector.dynamicTax?.maxBeforeTaxBps)}
                    </div>
                    <div className="rounded-lg border border-white/10 bg-black/10 px-3 py-2">
                      Max tax after trade:{" "}
                      {formatBps(detector.dynamicTax?.maxAfterTaxBps)}
                    </div>
                    <div className="rounded-lg border border-white/10 bg-black/10 px-3 py-2">
                      Storage changes: {storageChanges.length}
                    </div>
                    <div className="rounded-lg border border-white/10 bg-black/10 px-3 py-2">
                      Gas-limit findings:{" "}
                      {reverts.gasLimitFindings?.length || 0}
                    </div>
                    <div className="rounded-lg border border-white/10 bg-black/10 px-3 py-2">
                      Caller blacklist findings:{" "}
                      {reverts.callerFindings?.length || 0}
                    </div>
                  </div>
                </div>
              </div>

              {Object.keys(gasDeltas).length > 0 ? (
                <div className="mt-6 rounded-xl border border-white/10 bg-black/10 p-4">
                  <h4 className="text-sm uppercase tracking-[0.2em] text-gray-400">
                    Gas Deltas
                  </h4>
                  <div className="mt-3 grid gap-2 md:grid-cols-2">
                    {Object.entries(gasDeltas).map(([key, value]) => (
                      <div
                        key={key}
                        className="rounded-lg border border-white/10 px-3 py-2 text-sm text-gray-300"
                      >
                        <span className="block text-gray-400">{key}</span>
                        <span>{value.toFixed(0)} gas</span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}
            </section>
          ) : null}

          {/* Oracle Manipulation Risk Section - Always rendered */}
          <section className="mt-8 rounded-2xl border border-white/10 bg-white/5 p-6">
            <h3 className="text-lg font-semibold flex items-center gap-2">
              <Database className="w-5 h-5 text-purple-400" />
              Oracle Manipulation Risk
            </h3>

            <div className="mt-4 grid gap-4 md:grid-cols-3">
              <div className="rounded-xl border border-white/10 bg-black/10 p-4">
                <p className="text-sm text-gray-400">Flash Loan Pattern</p>
                <p className="mt-2 text-2xl font-semibold">
                  {flashLoan.detected ? (
                    <span className="text-danger-400">Detected</span>
                  ) : (
                    <span className="text-success-400">Clear</span>
                  )}
                </p>
                {flashLoan.patternType && (
                  <p className="mt-1 text-xs text-gray-500">
                    {flashLoan.patternType.replace(/_/g, " ")}
                  </p>
                )}
              </div>
              <div className="rounded-xl border border-white/10 bg-black/10 p-4">
                <p className="text-sm text-gray-400">Price Sensitivity</p>
                <p className="mt-2 text-2xl font-semibold">
                  {priceSensitivity.sensitivityLevel ? (
                    <span
                      className={
                        priceSensitivity.sensitivityLevel === "critical"
                          ? "text-danger-400"
                          : priceSensitivity.sensitivityLevel === "high"
                          ? "text-orange-400"
                          : priceSensitivity.sensitivityLevel === "medium"
                          ? "text-yellow-400"
                          : "text-success-400"
                      }
                    >
                      {priceSensitivity.sensitivityLevel
                        .charAt(0)
                        .toUpperCase() +
                        priceSensitivity.sensitivityLevel.slice(1)}
                    </span>
                  ) : (
                    <span className="text-gray-400">Unknown</span>
                  )}
                </p>
                {priceSensitivity.maxSingleBlockDeviation > 0 && (
                  <p className="mt-1 text-xs text-gray-500">
                    Max {formatBps(priceSensitivity.maxSingleBlockDeviation)}{" "}
                    deviation
                  </p>
                )}
              </div>
              <div className="rounded-xl border border-white/10 bg-black/10 p-4">
                <p className="text-sm text-gray-400">TWAP Protection</p>
                <p className="mt-2 text-2xl font-semibold">
                  {oracle.twapProtection?.hasTWAP ? (
                    <span className="text-success-400">Protected</span>
                  ) : (
                    <span className="text-danger-400">None</span>
                  )}
                </p>
                <p className="mt-1 text-xs text-gray-500">
                  Level: {oracle.twapProtection?.protectionLevel || "none"}
                </p>
              </div>
            </div>

            {/* Price Impact Levels */}
            {priceSensitivity.impactLevels &&
              priceSensitivity.impactLevels.length > 0 && (
                <div className="mt-6">
                  <h4 className="text-sm uppercase tracking-[0.2em] text-gray-400">
                    Simulated Price Impact by Swap Size
                  </h4>
                  <div className="mt-3 space-y-2">
                    {priceSensitivity.impactLevels.map((level, i) => (
                      <div key={i} className="flex items-center gap-3 text-sm">
                        <span className="w-24 text-gray-400">
                          {level.swapSizePct.toFixed(0)}% of pool
                        </span>
                        <div className="flex-1 h-4 bg-white/10 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full transition-all ${
                              level.priceImpactBps < 100
                                ? "bg-success-500"
                                : level.priceImpactBps < 500
                                ? "bg-yellow-500"
                                : level.priceImpactBps < 2000
                                ? "bg-orange-500"
                                : "bg-danger-500"
                            }`}
                            style={{
                              width: `${Math.min(
                                level.priceImpactBps / 50,
                                100,
                              )}%`,
                            }}
                          />
                        </div>
                        <span className="w-28 text-right text-gray-300">
                          {formatBps(level.priceImpactBps)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

            {/* Warnings */}
            {oracle.warnings && oracle.warnings.length > 0 && (
              <div className="mt-6">
                <h4 className="text-sm uppercase tracking-[0.2em] text-gray-400 mb-3">
                  Oracle Manipulation Warnings
                </h4>
                <div className="space-y-2">
                  {oracle.warnings.map((warning, i) => (
                    <div
                      key={i}
                      className="flex items-start gap-2 rounded-lg border border-danger-500/30 bg-danger-500/10 px-3 py-2 text-sm text-danger-300"
                    >
                      <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
                      <span>{warning}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {!oracle.score &&
              !flashLoan.detected &&
              !priceSensitivity.sensitivityLevel && (
                <div className="mt-4 text-sm text-gray-500">
                  No on-chain trace data available for oracle manipulation
                  analysis. Provide transaction or simulation data to enable
                  detection.
                </div>
              )}
          </section>
        </section>

        <aside className="glass-card p-6">
          <h2 className="text-xl font-bold">Next Steps</h2>
          <p className="mt-3 text-gray-300">
            Re-run the analysis from the main analyzer to generate a fresh
            report or compare this result with another token profile.
          </p>
          <div className="mt-6 space-y-3 text-sm text-gray-300">
            <p>Token address: {tokenAddress}</p>
            <p>Chain: {chainId || analysis.chainId || "unknown"}</p>
            <p>Risk level: {analysis.riskLevel}</p>
            <p>Score: {formatPercent(analysis.score)}</p>
          </div>
          <Link
            href="/"
            className="mt-8 inline-flex rounded-lg bg-primary-600 px-4 py-3 font-medium text-white transition-colors hover:bg-primary-700"
          >
            Back to Analyzer
          </Link>
        </aside>
      </main>
    </div>
  );
}
