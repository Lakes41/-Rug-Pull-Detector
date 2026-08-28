import React, { useState, useEffect } from "react";
import {
  Shield,
  AlertTriangle,
  Eye,
  EyeOff,
  Lock,
  Unlock,
  ChevronDown,
  ChevronUp,
  CheckCircle,
  XCircle,
  Info,
} from "lucide-react";

function ZKPrivacyDisclosure({ contractId, zkAnalysisResult, onRefresh }) {
  const [isExpanded, setIsExpanded] = useState(false);
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);

  const getPrivacyRiskColor = (level) => {
    switch (level) {
      case "LOW":
        return "text-success-400 bg-success-500/20 border-success-500/50";
      case "MEDIUM":
        return "text-yellow-400 bg-yellow-500/20 border-yellow-500/50";
      case "HIGH":
        return "text-orange-400 bg-orange-500/20 border-orange-500/50";
      case "CRITICAL":
        return "text-danger-400 bg-danger-500/20 border-danger-500/50";
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

  const getCurveBadge = (curve) => {
    const curveColors = {
      bn254: "bg-blue-500/20 text-blue-400 border-blue-500/50",
      alt_bn128: "bg-purple-500/20 text-purple-400 border-purple-500/50",
      bls12_381: "bg-green-500/20 text-green-400 border-green-500/50",
      unknown: "bg-gray-500/20 text-gray-400 border-gray-500/50",
    };
    return curveColors[curve] || curveColors.unknown;
  };

  if (!zkAnalysisResult) {
    return (
      <div className="glass-card p-6">
        <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
          <Shield className="w-5 h-5 text-primary-400" />
          Zero-Knowledge Privacy Analysis
        </h2>
        <div className="text-center py-8 text-gray-400">
          <EyeOff className="w-12 h-12 mx-auto mb-4 opacity-50" />
          <p>No ZK verification data available</p>
          <p className="text-sm mt-2">Provide contract bytecode to analyze privacy risks</p>
        </div>
      </div>
    );
  }

  const hasRisks = zkAnalysisResult.risks && zkAnalysisResult.risks.length > 0;
  const hasShieldedPoolRisks = zkAnalysisResult.shielded_pool_risks && zkAnalysisResult.shielded_pool_risks.length > 0;

  return (
    <div className="glass-card p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold flex items-center gap-2">
          <Shield className="w-5 h-5 text-primary-400" />
          Zero-Knowledge Privacy Analysis
        </h2>
        <button
          onClick={() => setIsExpanded(!isExpanded)}
          className="text-gray-400 hover:text-white transition-colors"
        >
          {isExpanded ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
        </button>
      </div>

      {/* Privacy Risk Level Badge */}
      <div className="mb-4">
        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-400">Privacy Risk Level</span>
          <div
            className={`px-3 py-1 rounded-full text-xs font-medium border ${getPrivacyRiskColor(
              zkAnalysisResult.privacy_risk_level,
            )} flex items-center gap-1`}
          >
            {zkAnalysisResult.privacy_risk_level === "CRITICAL" && <XCircle className="w-4 h-4" />}
            {zkAnalysisResult.privacy_risk_level === "HIGH" && <AlertTriangle className="w-4 h-4" />}
            {zkAnalysisResult.privacy_risk_level === "MEDIUM" && <AlertTriangle className="w-4 h-4" />}
            {zkAnalysisResult.privacy_risk_level === "LOW" && <CheckCircle className="w-4 h-4" />}
            {zkAnalysisResult.privacy_risk_level}
          </div>
        </div>
      </div>

      {/* Cryptographic Pairings */}
      {zkAnalysisResult.bytecode_analysis && (
        <div className="mb-4">
          <div className="text-sm text-gray-400 mb-2">Detected Cryptographic Pairings</div>
          <div className="flex flex-wrap gap-2">
            {zkAnalysisResult.bytecode_analysis.detected_curves.map((curve, index) => (
              <span
                key={index}
                className={`px-2 py-1 rounded text-xs font-medium border ${getCurveBadge(curve)}`}
              >
                {curve.toUpperCase()}
              </span>
            ))}
            {zkAnalysisResult.bytecode_analysis.pairing_count > 0 && (
              <span className="text-xs text-gray-400">
                ({zkAnalysisResult.bytecode_analysis.pairing_count} pairing{zkAnalysisResult.bytecode_analysis.pairing_count > 1 ? 's' : ''} detected)
              </span>
            )}
          </div>
        </div>
      )}

      {/* Risks Section */}
      {hasRisks && (
        <div className="mb-4">
          <div className="text-sm text-gray-400 mb-2 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4" />
            Detected Privacy Risks ({zkAnalysisResult.risks.length})
          </div>
          <div className="space-y-2">
            {zkAnalysisResult.risks.map((risk, index) => (
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
                  <span
                    className={`px-2 py-0.5 rounded text-xs font-medium ${getPrivacyRiskColor(risk.severity)}`}
                  >
                    {risk.severity.toUpperCase()}
                  </span>
                </div>
                <p className="text-xs text-gray-300 mb-2">{risk.description}</p>
                {risk.affected_functions && risk.affected_functions.length > 0 && (
                  <div className="text-xs text-gray-400">
                    <span className="font-medium">Affected Functions:</span>{' '}
                    {risk.affected_functions.join(', ')}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Shielded Pool Risks */}
      {hasShieldedPoolRisks && (
        <div className="mb-4">
          <div className="text-sm text-gray-400 mb-2 flex items-center gap-2">
            <Unlock className="w-4 h-4" />
            Shielded Pool Risks ({zkAnalysisResult.shielded_pool_risks.length})
          </div>
          <div className="space-y-2">
            {zkAnalysisResult.shielded_pool_risks.map((risk, index) => (
              <div
                key={index}
                className="bg-danger-500/10 rounded-lg p-3 border border-danger-500/30"
              >
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center gap-2">
                    {getSeverityIcon(risk.severity)}
                    <span className="text-sm font-medium text-danger-300">
                      {risk.risk_type.replace(/_/g, ' ').toUpperCase()}
                    </span>
                  </div>
                </div>
                <p className="text-xs text-gray-300">{risk.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Expanded Details */}
      {isExpanded && (
        <div className="border-t border-white/10 pt-4 space-y-4">
          {/* Recommendations */}
          {zkAnalysisResult.recommendations && zkAnalysisResult.recommendations.length > 0 && (
            <div>
              <div className="text-sm text-gray-400 mb-2 flex items-center gap-2">
                <Info className="w-4 h-4" />
                Security Recommendations
              </div>
              <ul className="space-y-1">
                {zkAnalysisResult.recommendations.map((rec, index) => (
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
            {showTechnicalDetails ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
            {showTechnicalDetails ? 'Hide' : 'Show'} Technical Details
          </button>

          {/* Technical Details */}
          {showTechnicalDetails && (
            <div className="bg-black/30 rounded-lg p-3 text-xs font-mono">
              <pre className="text-gray-300 whitespace-pre-wrap overflow-x-auto">
                {JSON.stringify(zkAnalysisResult.bytecode_analysis, null, 2)}
              </pre>
            </div>
          )}

          {/* Full Disclosure Text */}
          {zkAnalysisResult.disclosure && (
            <div>
              <div className="text-sm text-gray-400 mb-2">Full Disclosure Report</div>
              <div className="bg-black/30 rounded-lg p-3 text-xs font-mono max-h-48 overflow-y-auto">
                <pre className="text-gray-300 whitespace-pre-wrap">
                  {zkAnalysisResult.disclosure}
                </pre>
              </div>
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
            <Shield className="w-4 h-4" />
            Refresh Analysis
          </button>
        )}
      </div>
    </div>
  );
}

export default ZKPrivacyDisclosure;