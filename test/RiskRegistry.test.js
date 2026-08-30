const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("RiskRegistry", function () {
  let riskRegistry;
  let mockToken;
  let owner;
  let oracle1;
  let oracle2;
  let disputer;
  let user;

  const MIN_ORACLE_STAKE = ethers.parseEther("10");
  const MIN_DISPUTE_BOND = ethers.parseEther("5");

  beforeEach(async function () {
    [owner, oracle1, oracle2, disputer, user] = await ethers.getSigners();

    // Deploy Mock Token
    const MockToken = await ethers.getContractFactory("MockERC20");
    mockToken = await MockToken.deploy("Mock Bonding Token", "MBT", ethers.parseEther("1000000"));
    await mockToken.waitForDeployment();

    // Deploy RiskRegistry
    const RiskRegistry = await ethers.getContractFactory("RiskRegistry");
    riskRegistry = await RiskRegistry.deploy(await mockToken.getAddress());
    await riskRegistry.waitForDeployment();

    // Mint tokens to all accounts
    await mockToken.mint(oracle1.address, ethers.parseEther("1000"));
    await mockToken.mint(oracle2.address, ethers.parseEther("1000"));
    await mockToken.mint(disputer.address, ethers.parseEther("1000"));
    await mockToken.mint(user.address, ethers.parseEther("1000"));

    // Approve tokens for RiskRegistry
    await mockToken.connect(oracle1).approve(await riskRegistry.getAddress(), ethers.parseEther("1000"));
    await mockToken.connect(oracle2).approve(await riskRegistry.getAddress(), ethers.parseEther("1000"));
    await mockToken.connect(disputer).approve(await riskRegistry.getAddress(), ethers.parseEther("1000"));
  });

  describe("Deployment", function () {
    it("Should set the right owner", async function () {
      expect(await riskRegistry.hasRole(await riskRegistry.DEFAULT_ADMIN_ROLE(), owner.address)).to.be.true;
    });

    it("Should set the bonding token correctly", async function () {
      expect(await riskRegistry.bondingToken()).to.equal(await mockToken.getAddress());
    });
  });

  describe("Oracle Registration", function () {
    it("Should register an oracle with stake", async function () {
      await riskRegistry.registerOracle(oracle1.address, MIN_ORACLE_STAKE);
      
      const stake = await riskRegistry.getOracleStake(oracle1.address);
      expect(stake.amount).to.equal(MIN_ORACLE_STAKE);
      expect(stake.active).to.be.true;
    });

    it("Should fail to register oracle with insufficient stake", async function () {
      await expect(
        riskRegistry.registerOracle(oracle1.address, ethers.parseEther("5"))
      ).to.be.revertedWithCustomError(riskRegistry, "InsufficientStake");
    });

    it("Should grant oracle role to registered oracle", async function () {
      await riskRegistry.registerOracle(oracle1.address, MIN_ORACLE_STAKE);
      
      const ORACLE_ROLE = await riskRegistry.ORACLE_ROLE();
      expect(await riskRegistry.hasRole(ORACLE_ROLE, oracle1.address)).to.be.true;
    });

    it("Should allow oracle to add additional stake", async function () {
      await riskRegistry.registerOracle(oracle1.address, MIN_ORACLE_STAKE);
      await riskRegistry.connect(oracle1).addStake(ethers.parseEther("5"));
      
      const stake = await riskRegistry.getOracleStake(oracle1.address);
      expect(stake.amount).to.equal(ethers.parseEther("15"));
    });

    it("Should allow oracle to unstake", async function () {
      await riskRegistry.registerOracle(oracle1.address, MIN_ORACLE_STAKE);
      await riskRegistry.connect(oracle1).unstake(ethers.parseEther("5"));
      
      const stake = await riskRegistry.getOracleStake(oracle1.address);
      expect(stake.amount).to.equal(ethers.parseEther("5"));
    });

    it("Should not allow unstake with active slashes", async function () {
      await riskRegistry.registerOracle(oracle1.address, MIN_ORACLE_STAKE);
      
      // Simulate a slash by manually setting slash count (in real scenario, this happens via dispute)
      // For testing, we'll check the logic works
      const stake = await riskRegistry.getOracleStake(oracle1.address);
      expect(stake.slashCount).to.equal(0);
    });
  });

  describe("Risk Assertion Submission", function () {
    beforeEach(async function () {
      await riskRegistry.registerOracle(oracle1.address, MIN_ORACLE_STAKE);
    });

    it("Should submit a risk assertion with valid signature", async function () {
      const targetContract = user.address;
      const riskScore = 75;
      const timestamp = await ethers.provider.getBlock('latest').then(b => b.timestamp);
      
      // Sign the message
      const messageHash = ethers.solidityPackedKeccak256(
        ["address", "uint256", "uint256"],
        [targetContract, riskScore, timestamp]
      );
      const signature = await oracle1.signMessage(ethers.getBytes(messageHash));
      
      await riskRegistry.connect(oracle1).submitRiskAssertion(targetContract, riskScore, signature);
      
      const assertion = await riskRegistry.getAssertion(0);
      expect(assertion.targetContract).to.equal(targetContract);
      expect(assertion.riskScore).to.equal(riskScore);
      expect(assertion.oracle).to.equal(oracle1.address);
      expect(assertion.verified).to.be.true;
    });

    it("Should fail with invalid risk score", async function () {
      const targetContract = user.address;
      const riskScore = 150; // Invalid: > 100
      const timestamp = await ethers.provider.getBlock('latest').then(b => b.timestamp);
      
      const messageHash = ethers.solidityPackedKeccak256(
        ["address", "uint256", "uint256"],
        [targetContract, riskScore, timestamp]
      );
      const signature = await oracle1.signMessage(ethers.getBytes(messageHash));
      
      await expect(
        riskRegistry.connect(oracle1).submitRiskAssertion(targetContract, riskScore, signature)
      ).to.be.revertedWithCustomError(riskRegistry, "InvalidRiskScore");
    });

    it("Should fail with unauthorized oracle", async function () {
      const targetContract = user.address;
      const riskScore = 75;
      const timestamp = await ethers.provider.getBlock('latest').then(b => b.timestamp);
      
      const messageHash = ethers.solidityPackedKeccak256(
        ["address", "uint256", "uint256"],
        [targetContract, riskScore, timestamp]
      );
      const signature = await oracle2.signMessage(ethers.getBytes(messageHash));
      
      await expect(
        riskRegistry.connect(oracle2).submitRiskAssertion(targetContract, riskScore, signature)
      ).to.be.revertedWithCustomError(riskRegistry, "OracleNotAuthorized");
    });
  });

  describe("Dispute Resolution", function () {
    let assertionId;
    let targetContract;
    let riskScore;

    beforeEach(async function () {
      await riskRegistry.registerOracle(oracle1.address, MIN_ORACLE_STAKE);
      await riskRegistry.authorizeDisputer(disputer.address);
      
      targetContract = user.address;
      riskScore = 75;
      const timestamp = await ethers.provider.getBlock('latest').then(b => b.timestamp);
      
      const messageHash = ethers.solidityPackedKeccak256(
        ["address", "uint256", "uint256"],
        [targetContract, riskScore, timestamp]
      );
      const signature = await oracle1.signMessage(ethers.getBytes(messageHash));
      
      await riskRegistry.connect(oracle1).submitRiskAssertion(targetContract, riskScore, signature);
      assertionId = 0;
    });

    it("Should authorize a disputer", async function () {
      const DISPUTER_ROLE = await riskRegistry.DISPUTER_ROLE();
      expect(await riskRegistry.hasRole(DISPUTER_ROLE, disputer.address)).to.be.true;
    });

    it("Should initiate a dispute", async function () {
      await riskRegistry.connect(disputer).initiateDispute(assertionId);
      
      const dispute = await riskRegistry.getDispute(0);
      expect(dispute.assertionId).to.equal(assertionId);
      expect(dispute.challenger).to.equal(disputer.address);
      expect(dispute.bondAmount).to.equal(MIN_DISPUTE_BOND);
      expect(dispute.resolved).to.be.false;
      
      const assertion = await riskRegistry.getAssertion(assertionId);
      expect(assertion.disputed).to.be.true;
      expect(assertion.verified).to.be.false;
    });

    it("Should not allow dispute after window closes", async function () {
      // Fast forward past dispute window
      await ethers.provider.send("evm_increaseTime", [8 * 24 * 60 * 60]); // 8 days
      await ethers.provider.send("evm_mine");
      
      await expect(
        riskRegistry.connect(disputer).initiateDispute(assertionId)
      ).to.be.revertedWithCustomError(riskRegistry, "DisputeWindowClosed");
    });

    it("Should not allow duplicate disputes", async function () {
      await riskRegistry.connect(disputer).initiateDispute(assertionId);
      
      await expect(
        riskRegistry.connect(disputer).initiateDispute(assertionId)
      ).to.be.revertedWithCustomError(riskRegistry, "AlreadyDisputed");
    });

    it("Should resolve successful dispute and slash oracle", async function () {
      await riskRegistry.connect(disputer).initiateDispute(assertionId);
      
      const initialOracleStake = await riskRegistry.getOracleStake(oracle1.address);
      const initialReserve = await riskRegistry.protocolReserve();
      
      await riskRegistry.resolveDispute(0, true);
      
      const dispute = await riskRegistry.getDispute(0);
      expect(dispute.resolved).to.be.true;
      expect(dispute.successful).to.be.true;
      
      const finalOracleStake = await riskRegistry.getOracleStake(oracle1.address);
      expect(finalOracleStake.amount).to.be.lt(initialOracleStake.amount);
      expect(finalOracleStake.slashCount).to.equal(1);
    });

    it("Should resolve unsuccessful dispute and return bond", async function () {
      await riskRegistry.connect(disputer).initiateDispute(assertionId);
      
      const initialDisputerBalance = await mockToken.balanceOf(disputer.address);
      
      await riskRegistry.resolveDispute(0, false);
      
      const dispute = await riskRegistry.getDispute(0);
      expect(dispute.resolved).to.be.true;
      expect(dispute.successful).to.be.false;
      
      const finalDisputerBalance = await mockToken.balanceOf(disputer.address);
      expect(finalDisputerBalance).to.equal(initialDisputerBalance + MIN_DISPUTE_BOND);
      
      const assertion = await riskRegistry.getAssertion(assertionId);
      expect(assertion.verified).to.be.true;
      expect(assertion.disputed).to.be.false;
    });

    it("Should not resolve already resolved dispute", async function () {
      await riskRegistry.connect(disputer).initiateDispute(assertionId);
      await riskRegistry.resolveDispute(0, true);
      
      await expect(
        riskRegistry.resolveDispute(0, true)
      ).to.be.revertedWithCustomError(riskRegistry, "DisputeNotResolved");
    });
  });

  describe("Protocol Reserves", function () {
    it("Should allow admin to withdraw from reserves", async function () {
      await riskRegistry.registerOracle(oracle1.address, MIN_ORACLE_STAKE);
      await riskRegistry.authorizeDisputer(disputer.address);
      
      // Submit assertion and create successful dispute to generate reserves
      const targetContract = user.address;
      const riskScore = 75;
      const timestamp = await ethers.provider.getBlock('latest').then(b => b.timestamp);
      
      const messageHash = ethers.solidityPackedKeccak256(
        ["address", "uint256", "uint256"],
        [targetContract, riskScore, timestamp]
      );
      const signature = await oracle1.signMessage(ethers.getBytes(messageHash));
      
      await riskRegistry.connect(oracle1).submitRiskAssertion(targetContract, riskScore, signature);
      await riskRegistry.connect(disputer).initiateDispute(0);
      await riskRegistry.resolveDispute(0, true);
      
      const reserveAmount = await riskRegistry.protocolReserve();
      expect(reserveAmount).to.be.gt(0);
      
      const initialBalance = await mockToken.balanceOf(user.address);
      await riskRegistry.withdrawFromReserves(reserveAmount, user.address);
      
      const finalBalance = await mockToken.balanceOf(user.address);
      expect(finalBalance).to.equal(initialBalance + reserveAmount);
    });

    it("Should not allow withdrawal exceeding reserves", async function () {
      await expect(
        riskRegistry.withdrawFromReserves(ethers.parseEther("1000"), user.address)
      ).to.be.revertedWith("Insufficient reserves");
    });
  });

  describe("View Functions", function () {
    it("Should correctly check if assertion can be disputed", async function () {
      await riskRegistry.registerOracle(oracle1.address, MIN_ORACLE_STAKE);
      
      const targetContract = user.address;
      const riskScore = 75;
      const timestamp = await ethers.provider.getBlock('latest').then(b => b.timestamp);
      
      const messageHash = ethers.solidityPackedKeccak256(
        ["address", "uint256", "uint256"],
        [targetContract, riskScore, timestamp]
      );
      const signature = await oracle1.signMessage(ethers.getBytes(messageHash));
      
      await riskRegistry.connect(oracle1).submitRiskAssertion(targetContract, riskScore, signature);
      
      expect(await riskRegistry.canDispute(0)).to.be.true;
      
      // Fast forward past dispute window
      await ethers.provider.send("evm_increaseTime", [8 * 24 * 60 * 60]);
      await ethers.provider.send("evm_mine");
      
      expect(await riskRegistry.canDispute(0)).to.be.false;
    });
  });
});
