import {
  evaluateContractExitMechanisms,
  trackSequencerStatus,
  computeFinalityRisk,
  analyzeL2RollupRisk,
} from "../l2RollupDetector";

describe("Layer 2 Rollup Risk Detector", () => {
  describe("evaluateContractExitMechanisms", () => {
    it("detects force inclusion and escape hatch methods from contract ABI", () => {
      const chainData = {
        abiMethods: ["depositTransaction", "escapeHatch", "transfer"],
      };
      const result = evaluateContractExitMechanisms(chainData);

      expect(result.forceInclusionSupported).toBe(true);
      expect(result.escapeHatchSupported).toBe(true);
      expect(result.detectedForceMethods).toContain("depositTransaction");
      expect(result.detectedEscapeMethods).toContain("escapeHatch");
    });

    it("returns false when no exit mechanisms are found", () => {
      const chainData = {
        abiMethods: ["transfer", "approve", "balanceOf"],
      };
      const result = evaluateContractExitMechanisms(chainData);

      expect(result.forceInclusionSupported).toBe(false);
      expect(result.escapeHatchSupported).toBe(false);
    });

    it("respects override parameters", () => {
      const overrides = {
        forceInclusionEnabled: true,
        escapeHatchAvailable: true,
      };
      const result = evaluateContractExitMechanisms({}, overrides);

      expect(result.forceInclusionSupported).toBe(true);
      expect(result.escapeHatchSupported).toBe(true);
    });
  });

  describe("trackSequencerStatus", () => {
    it("returns default active status when none provided", () => {
      expect(trackSequencerStatus({})).toBe("active");
    });

    it("extracts sequencer status from chainData or overrides", () => {
      expect(trackSequencerStatus({ sequencerStatus: "halted" })).toBe("halted");
      expect(trackSequencerStatus({}, { sequencerStatus: "degraded" })).toBe(
        "degraded",
      );
    });
  });

  describe("computeFinalityRisk", () => {
    it("computes critical finality risk rating when sequencer is halted without escape hatch", () => {
      const result = computeFinalityRisk(604800, "halted", false, false, "optimistic");
      expect(result.rating).toBe("critical");
      expect(result.score).toBeGreaterThanOrEqual(0.8);
    });

    it("computes low finality risk rating for ZK rollup with escape hatch and active sequencer", () => {
      const result = computeFinalityRisk(3600, "active", true, true, "zk_rollup");
      expect(result.rating).toBe("low");
      expect(result.score).toBeLessThan(0.3);
    });
  });

  describe("analyzeL2RollupRisk", () => {
    it("performs full L2 rollup analysis and returns explicit centralization parameters", () => {
      const chainData = {
        abiMethods: ["enqueueTransaction", "withdrawToL1"],
        sequencerStatus: "active",
        challengeWindowSeconds: 604800,
      };
      const result = analyzeL2RollupRisk(chainData);

      expect(result.forceInclusionSupported).toBe(true);
      expect(result.escapeHatchSupported).toBe(true);
      expect(result.sequencerStatus).toBe("active");
      expect(result.centralizationParameters).toBeDefined();
      expect(result.centralizationParameters.challengeWindowDays).toBe(7);
      expect(result.centralizationParameters.forceInclusionEnabled).toBe(true);
      expect(result.centralizationParameters.escapeHatchAvailable).toBe(true);
    });

    it("generates explicit sequencer dependency warnings when sequencer is halted and escape hatch is missing", () => {
      const chainData = {
        abiMethods: ["transfer"],
        sequencerStatus: "halted",
      };
      const result = analyzeL2RollupRisk(chainData);

      expect(result.flagged).toBe(true);
      expect(result.warnings.some((w) => w.includes("CRITICAL: Sequencer is HALTED"))).toBe(true);
      expect(result.warnings.some((w) => w.includes("CENTRALIZATION RISK"))).toBe(true);
      expect(result.warnings.some((w) => w.includes("EXIT RISK"))).toBe(true);
    });
  });
});
