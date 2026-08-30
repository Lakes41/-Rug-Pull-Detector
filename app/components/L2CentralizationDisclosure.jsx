import React from "react";
import { AlertTriangle, CheckCircle, Clock, ShieldAlert, Cpu, Lock } from "lucide-react";

export default function L2CentralizationDisclosure({ l2Analysis = {} }) {
  const params = l2Analysis.centralizationParameters || {};
  const warnings = l2Analysis.warnings || [];
  const sequencerStatus = (params.sequencerStatus || l2Analysis.sequencerStatus || "active").toUpperCase();
  const rollupType = (params.rollupType || l2Analysis.rollupType || "optimistic").toUpperCase();

  const getStatusColor = (status) => {
    switch (status) {
      case "ACTIVE":
        return "text-success-400 bg-success-500/20 border-success-500/50";
      case "DEGRADED":
        return "text-yellow-400 bg-yellow-500/20 border-yellow-500/50";
      case "HALTED":
      case "DOWN":
        return "text-danger-400 bg-danger-500/20 border-danger-500/50";
      default:
        return "text-gray-400 bg-gray-500/20 border-gray-500/50";
    }
  };

  const getRiskColor = (rating) => {
    switch (rating) {
      case "low":
        return "text-success-400";
      case "medium":
        return "text-yellow-400";
      case "high":
        return "text-orange-400";
      case "critical":
        return "text-danger-400";
      default:
        return "text-gray-400";
    }
  };

  return (
    <section className="mt-8 rounded-2xl border border-white/10 bg-white/5 p-6">
      <div className="flex items-center justify-between gap-4">
        <h3 className="text-lg font-semibold flex items-center gap-2">
          <Cpu className="w-5 h-5 text-blue-400" />
          Layer 2 Rollup Centralization & Exit Risk
        </h3>
        <div className={`flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-semibold ${getStatusColor(sequencerStatus)}`}>
          <span>Sequencer: {sequencerStatus}</span>
        </div>
      </div>

      <div className="mt-4 grid gap-4 md:grid-cols-4">
        <div className="rounded-xl border border-white/10 bg-black/10 p-4">
          <p className="text-sm text-gray-400">Rollup Architecture</p>
          <p className="mt-2 text-xl font-semibold">{rollupType}</p>
        </div>

        <div className="rounded-xl border border-white/10 bg-black/10 p-4">
          <p className="text-sm text-gray-400">Withdrawal Challenge Delay</p>
          <p className="mt-2 text-xl font-semibold flex items-center gap-1.5">
            <Clock className="w-4 h-4 text-gray-400" />
            {params.challengeWindowDays !== undefined ? `${params.challengeWindowDays} days` : "7 days"}
          </p>
          <p className="mt-1 text-xs text-gray-500">
            {params.challengeWindowSeconds ? `${params.challengeWindowSeconds.toLocaleString()}s` : "604,800s"}
          </p>
        </div>

        <div className="rounded-xl border border-white/10 bg-black/10 p-4">
          <p className="text-sm text-gray-400">Force Inclusion</p>
          <p className="mt-2 text-xl font-semibold flex items-center gap-1">
            {l2Analysis.forceInclusionSupported ? (
              <>
                <CheckCircle className="w-5 h-5 text-success-400" />
                <span className="text-success-400">Enabled</span>
              </>
            ) : (
              <>
                <AlertTriangle className="w-5 h-5 text-danger-400" />
                <span className="text-danger-400">Disabled</span>
              </>
            )}
          </p>
        </div>

        <div className="rounded-xl border border-white/10 bg-black/10 p-4">
          <p className="text-sm text-gray-400">L1 Escape Hatch</p>
          <p className="mt-2 text-xl font-semibold flex items-center gap-1">
            {l2Analysis.escapeHatchSupported ? (
              <>
                <CheckCircle className="w-5 h-5 text-success-400" />
                <span className="text-success-400">Available</span>
              </>
            ) : (
              <>
                <Lock className="w-5 h-5 text-danger-400" />
                <span className="text-danger-400">Missing</span>
              </>
            )}
          </p>
        </div>
      </div>

      <div className="mt-4 rounded-xl border border-white/10 bg-black/10 p-4">
        <div className="flex items-center justify-between text-sm text-gray-300">
          <span>Finality Risk Rating:</span>
          <span className={`font-semibold capitalize ${getRiskColor(l2Analysis.finalityRiskRating)}`}>
            {l2Analysis.finalityRiskRating || "low"} Risk (Score: {(l2Analysis.score ?? 0).toFixed(2)})
          </span>
        </div>
      </div>

      {warnings.length > 0 && (
        <div className="mt-6">
          <h4 className="text-sm uppercase tracking-[0.2em] text-gray-400 mb-3 flex items-center gap-1.5">
            <ShieldAlert className="w-4 h-4 text-orange-400" />
            Sequencer Dependency & Exit Warnings
          </h4>
          <div className="space-y-2">
            {warnings.map((warning, i) => (
              <div
                key={i}
                className="flex items-start gap-2 rounded-lg border border-danger-500/30 bg-danger-500/10 px-3 py-2 text-sm text-danger-300"
              >
                <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0 text-danger-400" />
                <span>{warning}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
