import React from "react";
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  Eye,
} from "lucide-react";
import ZKPrivacyDisclosure from "./ZKPrivacyDisclosure";

function RiskDashboard({ analyzedTokens }) {
  const getRiskLevelColor = (level) => {
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
  };

  const getRiskIcon = (level) => {
    switch (level) {
      case "Low":
        return <CheckCircle className="w-5 h-5" />;
      case "Medium":
        return <AlertTriangle className="w-5 h-5" />;
      case "High":
        return <AlertTriangle className="w-5 h-5" />;
      case "Critical":
        return <XCircle className="w-5 h-5" />;
      default:
        return <Shield className="w-5 h-5" />;
    }
  };

  const getScoreColor = (score) => {
    if (score < 0.3) return "from-success-500 to-success-400";
    if (score < 0.6) return "from-yellow-500 to-yellow-400";
    if (score < 0.8) return "from-orange-500 to-orange-400";
    return "from-danger-500 to-danger-400";
  };

  const stats = {
    total: analyzedTokens.length,
    safe: analyzedTokens.filter((t) => t.riskLevel === "Low").length,
    risky: analyzedTokens.filter((t) =>
      ["High", "Critical"].includes(t.riskLevel),
    ).length,
  };

  return (
    <div className="glass-card p-6">
      <h2 className="text-xl font-bold mb-6 flex items-center gap-2">
        <Shield className="w-5 h-5 text-primary-400" />
        Risk Dashboard
      </h2>

      {/* Stats Overview */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        <div className="bg-white/5 rounded-lg p-4 text-center">
          <div className="text-2xl font-bold text-white">{stats.total}</div>
          <div className="text-sm text-gray-400">Total Analyzed</div>
        </div>
        <div className="bg-success-500/20 rounded-lg p-4 text-center border border-success-500/50">
          <div className="text-2xl font-bold text-success-400">
            {stats.safe}
          </div>
          <div className="text-sm text-success-300">Safe Tokens</div>
        </div>
        <div className="bg-danger-500/20 rounded-lg p-4 text-center border border-danger-500/50">
          <div className="text-2xl font-bold text-danger-400">
            {stats.risky}
          </div>
          <div className="text-sm text-danger-300">Risky Tokens</div>
        </div>
      </div>

      {/* Token List */}
      <div className="space-y-3">
        {analyzedTokens.length === 0 ? (
          <div className="text-center py-12 text-gray-400">
            <Shield className="w-12 h-12 mx-auto mb-4 opacity-50" />
            <p>No tokens analyzed yet</p>
            <p className="text-sm">Use the analyzer to check token risks</p>
          </div>
        ) : (
          analyzedTokens.map((token, index) => (
            <div
              key={index}
              className="bg-white/5 rounded-lg p-4 border border-white/10 hover:border-white/20 transition-colors"
            >
              <div className="flex items-start justify-between mb-3">
                <div className="flex-1">
                  <div className="font-mono text-sm text-primary-400 mb-1">
                    {token.tokenAddress}
                  </div>
                  <div className="flex items-center gap-2 text-xs text-gray-400">
                    <Clock className="w-3 h-3" />
                    {new Date(token.timestamp).toLocaleTimeString()}
                  </div>
                </div>
                <div
                  className={`px-3 py-1 rounded-full text-xs font-medium border ${getRiskLevelColor(
                    token.riskLevel,
                  )} flex items-center gap-1`}
                >
                  {getRiskIcon(token.riskLevel)}
                  {token.riskLevel}
                </div>
              </div>

              {/* Risk Score Bar */}
              <div className="mb-3">
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-gray-400">Risk Score</span>
                  <span className="text-white font-medium">
                    {(token.score * 100).toFixed(1)}%
                  </span>
                </div>
                <div className="h-2 bg-white/10 rounded-full overflow-hidden">
                  <div
                    className={`h-full bg-gradient-to-r ${getScoreColor(
                      token.score,
                    )} transition-all duration-500`}
                    style={{ width: `${token.score * 100}%` }}
                  />
                </div>
              </div>

              {token.reportHref ? (
                <div className="mb-3">
                  <a
                    href={token.reportHref}
                    className="text-sm font-medium text-primary-300 transition-colors hover:text-primary-200"
                  >
                    Open public report
                  </a>
                </div>
              ) : null}

              {/* Component Breakdown */}
              <div className="grid grid-cols-4 gap-2 text-xs">
                <div className="bg-white/5 rounded p-2">
                  <div className="text-gray-400 mb-1">Creator</div>
                  <div className="text-white font-medium">
                    {(token.components.creatorOwnership * 100).toFixed(0)}%
                  </div>
                </div>
                <div className="bg-white/5 rounded p-2">
                  <div className="text-gray-400 mb-1">Liquidity</div>
                  <div className="text-white font-medium">
                    {(token.components.liquidityLock * 100).toFixed(0)}%
                  </div>
                </div>
                <div className="bg-white/5 rounded p-2">
                  <div className="text-gray-400 mb-1">Honeypot</div>
                  <div className="text-white font-medium">
                    {(token.components.honeypot * 100).toFixed(0)}%
                  </div>
                </div>
                <div className="bg-white/5 rounded p-2">
                  <div className="text-gray-400 mb-1">Oracle</div>
                  <div className="text-white font-medium">
                    {((token.components.oracleManipulation || 0) * 100).toFixed(
                      0,
                    )}
                    %
                  </div>
                </div>
              </div>

              {/* ZK Privacy Risk Indicator */}
              {token.hasZKPrivacy && (
                <div className="mt-3 p-2 bg-primary-500/10 border border-primary-500/30 rounded-lg flex items-center gap-2">
                  <Eye className="w-4 h-4 text-primary-400" />
                  <span className="text-xs text-primary-300">
                    Zero-Knowledge Privacy Layer Detected
                  </span>
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

export default RiskDashboard;
