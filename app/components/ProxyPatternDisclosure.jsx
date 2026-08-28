import React, { useState } from "react";
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  ChevronDown,
  ChevronUp,
  Settings,
  User,
  Lock,
  Unlock,
  Info,
} from "lucide-react";

function ProxyPatternDisclosure({ contractAddress, proxyAnalysisResult, onRefresh }) {
  const [isExpanded, setIsExpanded] = useState(false);
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);

  const getSeverityColor = (severity) => {
    switch (severity) {
      case "critical":
        return "text-danger-400 bg-danger-500/20 border-danger-500/50";
      case "high":
        return "text-orange-400 bg-orange-500/20 border-orange-500/50";
      case "medium":
        return "text-yellow-400 bg-yellow-500/20 border-yellow-500/50";
      case "low":
        return "text-success-400 bg-success-500/20 border-success-500/50";
      default:
        return "text-gray-400 bg-gray-500/20 border-gray-500/50";
    }
  };

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case "critical":
        return <XCircle className="w-4 h-4 text-danger-400" />;
      case "high":
        return <AlertTriangle className="w-4 h-4 text-orange-400" />;
      case "medium":
        return <AlertTriangle className="w-4 h-4 text-yellow-400" />;
      case "low":
        return <CheckCircle className="w-4 h-4 text-success-400" />;
      default:
        return <Info className="w-4 h-4 text-gray-400" />;
    }
  };

  const getProxyTypeBadge = (proxyType) => {
    const typeColors = {
      eip_1967: "bg-blue-500/20 text-blue-400 border-blue-500/50",
      eip_897: "bg-purple-500/20 text-purple-400 border-purple-500/50",
      beacon: "bg-green-500/20 text-green-400 border-green-500/50",
      uups: "bg-orange-500/20 text-orange-400 border-orange-500/50",
      unknown: "bg-gray-500/20 text-gray-400 border-gray-500/50",
    };
    return typeColors[proxyType] || typeColors.unknown;
  };

  const formatAddress = (address) => {
    if (!address) return "N/A";
    return `${address.slice(0, 6)}...${address.slice(-4)}`;
  };

  const formatDelay = (seconds) => {
    if (!seconds) return "N/A";
    const hours = seconds / 3600;
    if (hours >= 24) {
      const days = Math.floor(hours / 24);
      return `${days} day${days > 1 ? 's' : ''}`;
    }
    return `${hours.toFixed(1)}h`;
  };

  if (!proxyAnalysisResult) {
    return (
      <div className="glass-card p-6">
        <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
          <Settings className="w-5 h-5 text-primary-400" />
          Proxy Pattern Analysis
        </h2>
        <div className="text-center py-8 text-gray-400">
          <Shield className="w-12 h-12 mx-auto mb-4 opacity-50" />
          <p>No proxy pattern data available</p>
          <p className="text-sm mt-2">Provide contract address to analyze proxy risks</p>
        </div>
      </div>
    );
  }

  const hasRisks = proxyAnalysisResult.risks && proxyAnalysisResult.risks.length > 0;
  const hasTimelock = proxyAnalysisResult.timelock_info?.has_timelock;
  const isDelaySufficient = proxyAnalysisResult.timelock_info?.is_governance_delay_sufficient;

  return (
    <div className="glass-card p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold flex items-center gap-2">
          <Settings className="w-5 h-5 text-primary-400" />
          Proxy Pattern Analysis
        </h2>
        <button
          onClick={() => setIsExpanded(!isExpanded)}
          className="text-gray-400 hover:text-white transition-colors"
        >
          {isExpanded ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
        </button>
      </div>

      {/* Proxy Status */}
      <div className="mb-4">
        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-400">Proxy Type</span>
          {proxyAnalysisResult.is_proxy ? (
            <div
              className={`px-3 py-1 rounded-full text-xs font-medium border ${getProxyTypeBadge(
                proxyAnalysisResult.proxy_type,
              )} flex items-center gap-1`}
            >
              <Settings className="w-3 h-3" />
              {proxyAnalysisResult.proxy_type.toUpperCase()}
            </div>
          ) : (
            <div className="px-3 py-1 rounded-full text-xs font-medium border border-gray-500/50 text-gray-400">
              Not a Proxy
            </div>
          )}
        </div>
      </div>

      {/* Risk Multiplier */}
      {proxyAnalysisResult.is_proxy && (
        <div className="mb-4">
          <div className="flex items-center justify-between">
            <span className="text-sm text-gray-400">Risk Multiplier</span>
            <div className="flex items-center gap-2">
              <div className="text-lg font-bold text-white">
                {proxyAnalysisResult.risk_multiplier.toFixed(1)}x
              </div>
              {proxyAnalysisResult.risk_multiplier >= 3.0 && (
                <AlertTriangle className="w-4 h-4 text-danger-400" />
              )}
            </div>
          </div>
          <div className="h-2 bg-white/10 rounded-full overflow-hidden mt-2">
            <div
              className={`h-full bg-gradient-to-r ${
                proxyAnalysisResult.risk_multiplier >= 3.0
                  ? "from-danger-500 to-danger-400"
                  : proxyAnalysisResult.risk_multiplier >= 2.0
                  ? "from-orange-500 to-orange-400"
                  : "from-yellow-500 to-yellow-400"
              } transition-all duration-500`}
              style={{ width: `${Math.min(proxyAnalysisResult.risk_multiplier * 20, 100)}%` }}
            />
          </div>
        </div>
      )}

      {/* Implementation Details */}
      {proxyAnalysisResult.is_proxy && (
        <div className="mb-4 space-y-2">
          <div className="flex items-center justify-between text-sm">
            <span className="text-gray-400">Implementation</span>
            <span className="text-white font-mono">{formatAddress(proxyAnalysisResult.implementation_address)}</span>
          </div>
          {proxyAnalysisResult.admin_address && (
            <div className="flex items-center justify-between text-sm">
              <span className="text-gray-400 flex items-center gap-1">
                <User className="w-3 h-3" />
                Admin
              </span>
              <span className="text-white font-mono">{formatAddress(proxyAnalysisResult.admin_address)}</span>
            </div>
          )}
        </div>
      )}

      {/* Timelock Status */}
      {proxyAnalysisResult.is_proxy && (
        <div className="mb-4">
          <div className="flex items-center justify-between">
            <span className="text-sm text-gray-400 flex items-center gap-1">
              {hasTimelock ? <Lock className="w-3 h-3 text-success-400" /> : <Unlock className="w-3 h-3 text-danger-400" />}
              Timelock Governance
            </span>
            <div
              className={`px-2 py-1 rounded text-xs font-medium ${
                hasTimelock && isDelaySufficient
                  ? "bg-success-500/20 text-success-400"
                  : hasTimelock
                  ? "bg-yellow-500/20 text-yellow-400"
                  : "bg-danger-500/20 text-danger-400"
              }`}
            >
              {hasTimelock ? (isDelaySufficient ? "Secure" : "Insufficient Delay") : "No Timelock"}
            </div>
          </div>
          {hasTimelock && (
            <div className="flex items-center justify-between text-sm mt-2">
              <span className="text-gray-400 flex items-center gap-1">
                <Clock className="w-3 h-3" />
                Minimum Delay
              </span>
              <span className="text-white">{formatDelay(proxyAnalysisResult.timelock_info.minimum_delay)}</span>
            </div>
          )}
        </div>
      )}

      {/* Risks Section */}
      {hasRisks && (
        <div className="mb-4">
          <div className="text-sm text-gray-400 mb-2 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4" />
            Detected Proxy Risks ({proxyAnalysisResult.risks.length})
          </div>
          <div className="space-y-2">
            {proxyAnalysisResult.risks.map((risk, index) => (
              <div
                key={index}
                className="bg-white/5 rounded-lg p-3 border border-white/10"
              >
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center gap-2">
                    {getSeverityIcon(risk.severity)}
                    <span className="text-sm font-medium text-white">
                      {risk.risk_type.replace(/_/g, ' ').toUpperCase()}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span
                      className={`px-2 py-0.5 rounded text-xs font-medium ${getSeverityColor(risk.severity)}`}
                    >
                      {risk.severity.toUpperCase()}
                    </span>
                    {risk.risk_multiplier > 1.0 && (
                      <span className="text-xs text-orange-400 font-medium">
                        {risk.risk_multiplier.toFixed(1)}x
                      </span>
                    )}
                  </div>
                </div>
                <p className="text-xs text-gray-300 mb-2">{risk.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Expanded Details */}
      {isExpanded && (
        <div className="border-t border-white/10 pt-4 space-y-4">
          {/* Recommendations */}
          {proxyAnalysisResult.recommendations && proxyAnalysisResult.recommendations.length > 0 && (
            <div>
              <div className="text-sm text-gray-400 mb-2 flex items-center gap-2">
                <Info className="w-4 h-4" />
                Security Recommendations
              </div>
              <ul className="space-y-1">
                {proxyAnalysisResult.recommendations.map((rec, index) => (
                  <li key={index} className="text-xs text-gray-300 flex items-start gap-2">
                    <span className="text-primary-400 mt-0.5">•</span>
                    {rec}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Technical Details Toggle */}
          <button
            onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
            className="text-xs text-primary-400 hover:text-primary-300 transition-colors flex items-center gap-1"
          >
            {showTechnicalDetails ? <Unlock className="w-3 h-3" /> : <Lock className="w-3 h-3" />}
            {showTechnicalDetails ? 'Hide' : 'Show'} Technical Details
          </button>

          {/* Technical Details */}
          {showTechnicalDetails && (
            <div className="bg-black/30 rounded-lg p-3 text-xs font-mono max-h-48 overflow-y-auto">
              <pre className="text-gray-300 whitespace-pre-wrap">
                {JSON.stringify(proxyAnalysisResult, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}

      {/* Action Buttons */}
      <div className="mt-4 flex gap-2">
        {onRefresh && (
          <button
            onClick={onRefresh}
            className="flex-1 px-4 py-2 bg-primary-500/20 hover:bg-primary-500/30 text-primary-300 rounded-lg text-sm font-medium transition-colors flex items-center justify-center gap-2"
          >
            <Settings className="w-4 h-4" />
            Refresh Analysis
          </button>
        )}
      </div>
    </div>
  );
}

export default ProxyPatternDisclosure;