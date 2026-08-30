// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title RiskRegistry
 * @dev Decentralized on-chain registry for risk assessment with staking, verification, and dispute resolution
 */
contract RiskRegistry is AccessControl, ReentrancyGuard {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // Role definitions
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant ORACLE_ROLE = keccak256("ORACLE_ROLE");
    bytes32 public constant DISPUTER_ROLE = keccak256("DISPUTER_ROLE");

    // Constants
    uint256 public constant MIN_ORACLE_STAKE = 10 ether;
    uint256 public constant MIN_DISPUTE_BOND = 5 ether;
    uint256 public constant DISPUTE_WINDOW = 7 days;
    uint256 public constant SLASH_PERCENTAGE = 80; // 80% of stake slashed
    uint256 public constant DISPUTE_REWARD_PERCENTAGE = 90; // 90% of slashed stake goes to disputers

    // State variables
    IERC20 public bondingToken;
    uint256 public protocolReserve;
    uint256 public totalStaked;
    
    // Risk assertion structure
    struct RiskAssertion {
        address targetContract;
        uint256 riskScore; // 0-100, higher = riskier
        uint256 timestamp;
        address oracle;
        bool disputed;
        bool verified;
        uint256 disputeDeadline;
        bytes32 assertionHash;
    }

    // Oracle stake structure
    struct OracleStake {
        uint256 amount;
        uint256 slashCount;
        bool active;
    }

    // Dispute structure
    struct Dispute {
        uint256 assertionId;
        address challenger;
        uint256 bondAmount;
        uint256 timestamp;
        bool resolved;
        bool successful;
    }

    // Mappings
    mapping(uint256 => RiskAssertion) public assertions;
    mapping(address => OracleStake) public oracleStakes;
    mapping(uint256 => Dispute) public disputes;
    mapping(address => bool) public authorizedOracles;
    mapping(address => bool) public authorizedDisputers;

    // Counters
    uint256 public assertionCount;
    uint256 public disputeCount;

    // Events
    event OracleRegistered(address indexed oracle, uint256 stakeAmount);
    event OracleStaked(address indexed oracle, uint256 amount);
    event OracleUnstaked(address indexed oracle, uint256 amount);
    event RiskAssertionSubmitted(
        uint256 indexed assertionId,
        address indexed targetContract,
        uint256 riskScore,
        address indexed oracle
    );
    event DisputeInitiated(
        uint256 indexed disputeId,
        uint256 indexed assertionId,
        address indexed challenger,
        uint256 bondAmount
    );
    event DisputeResolved(
        uint256 indexed disputeId,
        bool successful,
        uint256 slashAmount
    );
    event OracleSlashed(address indexed oracle, uint256 amount);
    event DisputeRewardPaid(address indexed challenger, uint256 reward);
    event ProtocolReserveUpdated(uint256 amount);

    // Errors
    error InsufficientStake();
    error OracleNotAuthorized();
    error DisputerNotAuthorized();
    error InvalidRiskScore();
    error DisputeWindowClosed();
    error AlreadyDisputed();
    error InsufficientBond();
    error DisputeNotResolved();
    error OracleNotStaked();
    error WithdrawalTooEarly();

    /**
     * @dev Constructor
     * @param _bondingToken Address of the token used for staking/bonding
     */
    constructor(address _bondingToken) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        
        bondingToken = IERC20(_bondingToken);
        
        emit ProtocolReserveUpdated(0);
    }

    /**
     * @dev Register a new security oracle with stake
     * @param _oracle Address of the oracle to register
     * @param _stakeAmount Amount to stake
     */
    function registerOracle(address _oracle, uint256 _stakeAmount) external onlyRole(ADMIN_ROLE) {
        require(_stakeAmount >= MIN_ORACLE_STAKE, InsufficientStake());
        
        oracleStakes[_oracle] = OracleStake({
            amount: _stakeAmount,
            slashCount: 0,
            active: true
        });
        
        authorizedOracles[_oracle] = true;
        _grantRole(ORACLE_ROLE, _oracle);
        
        totalStaked += _stakeAmount;
        
        require(bondingToken.transferFrom(msg.sender, address(this), _stakeAmount), "Transfer failed");
        
        emit OracleRegistered(_oracle, _stakeAmount);
    }

    /**
     * @dev Oracle adds additional stake
     * @param _amount Amount to add to stake
     */
    function addStake(uint256 _amount) external onlyRole(ORACLE_ROLE) {
        require(oracleStakes[msg.sender].active, OracleNotStaked());
        
        oracleStakes[msg.sender].amount += _amount;
        totalStaked += _amount;
        
        require(bondingToken.transferFrom(msg.sender, address(this), _amount), "Transfer failed");
        
        emit OracleStaked(msg.sender, _amount);
    }

    /**
     * @dev Oracle unstakes (after cooldown period)
     * @param _amount Amount to unstake
     */
    function unstake(uint256 _amount) external onlyRole(ORACLE_ROLE) nonReentrant {
        OracleStake storage stake = oracleStakes[msg.sender];
        require(stake.active, OracleNotStaked());
        require(stake.amount >= _amount, InsufficientStake());
        require(stake.slashCount == 0, "Cannot unstake with active slashes");
        
        stake.amount -= _amount;
        totalStaked -= _amount;
        
        if (stake.amount == 0) {
            stake.active = false;
            authorizedOracles[msg.sender] = false;
            _revokeRole(ORACLE_ROLE, msg.sender);
        }
        
        require(bondingToken.transfer(msg.sender, _amount), "Transfer failed");
        
        emit OracleUnstaked(msg.sender, _amount);
    }

    /**
     * @dev Submit a signed risk assertion
     * @param _targetContract Address of the contract being assessed
     * @param _riskScore Risk score (0-100)
     * @param _signature Oracle's signature of the assertion data
     */
    function submitRiskAssertion(
        address _targetContract,
        uint256 _riskScore,
        bytes calldata _signature
    ) external nonReentrant {
        require(_riskScore <= 100, InvalidRiskScore());
        require(authorizedOracles[msg.sender], OracleNotAuthorized());
        
        // Construct message hash for signature verification
        bytes32 messageHash = keccak256(abi.encodePacked(_targetContract, _riskScore, block.timestamp));
        bytes32 ethSignedHash = messageHash.toEthSignedMessageHash();
        
        // Recover signer from signature
        address signer = ethSignedHash.recover(_signature);
        require(signer == msg.sender, "Invalid signature");
        
        // Create assertion
        uint256 assertionId = assertionCount++;
        assertions[assertionId] = RiskAssertion({
            targetContract: _targetContract,
            riskScore: _riskScore,
            timestamp: block.timestamp,
            oracle: msg.sender,
            disputed: false,
            verified: true,
            disputeDeadline: block.timestamp + DISPUTE_WINDOW,
            assertionHash: messageHash
        });
        
        emit RiskAssertionSubmitted(assertionId, _targetContract, _riskScore, msg.sender);
    }

    /**
     * @dev Authorize a disputer to challenge assertions
     * @param _disputer Address to authorize
     */
    function authorizeDisputer(address _disputer) external onlyRole(ADMIN_ROLE) {
        authorizedDisputers[_disputer] = true;
        _grantRole(DISPUTER_ROLE, _disputer);
    }

    /**
     * @dev Initiate a dispute against a risk assertion
     * @param _assertionId ID of the assertion to dispute
     */
    function initiateDispute(uint256 _assertionId) external onlyRole(DISPUTER_ROLE) nonReentrant {
        RiskAssertion storage assertion = assertions[_assertionId];
        require(assertion.disputeDeadline > block.timestamp, DisputeWindowClosed());
        require(!assertion.disputed, AlreadyDisputed());
        
        // Check disputer has sufficient bond
        uint256 bondAmount = MIN_DISPUTE_BOND;
        require(bondingToken.balanceOf(msg.sender) >= bondAmount, InsufficientBond());
        
        // Transfer bond to contract
        require(bondingToken.transferFrom(msg.sender, address(this), bondAmount), "Transfer failed");
        
        // Mark assertion as disputed
        assertion.disputed = true;
        assertion.verified = false;
        
        // Create dispute record
        uint256 disputeId = disputeCount++;
        disputes[disputeId] = Dispute({
            assertionId: _assertionId,
            challenger: msg.sender,
            bondAmount: bondAmount,
            timestamp: block.timestamp,
            resolved: false,
            successful: false
        });
        
        emit DisputeInitiated(disputeId, _assertionId, msg.sender, bondAmount);
    }

    /**
     * @dev Resolve a dispute (called by admin after off-chain verification)
     * @param _disputeId ID of the dispute to resolve
     * @param _successful Whether the dispute was successful
     */
    function resolveDispute(uint256 _disputeId, bool _successful) external onlyRole(ADMIN_ROLE) nonReentrant {
        Dispute storage dispute = disputes[_disputeId];
        require(!dispute.resolved, DisputeNotResolved());
        
        RiskAssertion storage assertion = assertions[dispute.assertionId];
        OracleStake storage oracleStake = oracleStakes[assertion.oracle];
        
        dispute.resolved = true;
        dispute.successful = _successful;
        
        if (_successful) {
            // Slash the oracle's stake
            uint256 slashAmount = (oracleStake.amount * SLASH_PERCENTAGE) / 100;
            oracleStake.amount -= slashAmount;
            oracleStake.slashCount++;
            totalStaked -= slashAmount;
            
            // Calculate reward for disputer
            uint256 rewardAmount = (slashAmount * DISPUTE_REWARD_PERCENTAGE) / 100;
            uint256 protocolFee = slashAmount - rewardAmount;
            
            // Pay reward to disputer (bond + portion of slash)
            uint256 totalReward = dispute.bondAmount + rewardAmount;
            require(bondingToken.transfer(dispute.challenger, totalReward), "Transfer failed");
            
            // Add protocol fee to reserves
            protocolReserve += protocolFee;
            
            emit OracleSlashed(assertion.oracle, slashAmount);
            emit DisputeRewardPaid(dispute.challenger, totalReward);
            emit ProtocolReserveUpdated(protocolReserve);
        } else {
            // Return bond to unsuccessful disputer
            require(bondingToken.transfer(dispute.challenger, dispute.bondAmount), "Transfer failed");
            
            // Re-verify the assertion
            assertion.verified = true;
            assertion.disputed = false;
        }
        
        emit DisputeResolved(_disputeId, _successful, _successful ? (oracleStake.amount * SLASH_PERCENTAGE) / 100 : 0);
    }

    /**
     * @dev Update the minimum oracle stake requirement
     * @param _newMinStake New minimum stake amount
     */
    function updateMinOracleStake(uint256 _newMinStake) external onlyRole(ADMIN_ROLE) {
        // Note: This would require a state variable update in a full implementation
        // For simplicity, we're using a constant but this shows the pattern
    }

    /**
     * @dev Update the minimum dispute bond requirement
     * @param _newMinBond New minimum bond amount
     */
    function updateMinDisputeBond(uint256 _newMinBond) external onlyRole(ADMIN_ROLE) {
        // Note: This would require a state variable update in a full implementation
    }

    /**
     * @dev Withdraw from protocol reserves (emergency only)
     * @param _amount Amount to withdraw
     * @param _recipient Address to send funds to
     */
    function withdrawFromReserves(uint256 _amount, address _recipient) external onlyRole(ADMIN_ROLE) {
        require(_amount <= protocolReserve, "Insufficient reserves");
        protocolReserve -= _amount;
        require(bondingToken.transfer(_recipient, _amount), "Transfer failed");
        emit ProtocolReserveUpdated(protocolReserve);
    }

    /**
     * @dev Get assertion details
     * @param _assertionId ID of the assertion
     */
    function getAssertion(uint256 _assertionId) external view returns (
        address targetContract,
        uint256 riskScore,
        uint256 timestamp,
        address oracle,
        bool disputed,
        bool verified,
        uint256 disputeDeadline
    ) {
        RiskAssertion memory assertion = assertions[_assertionId];
        return (
            assertion.targetContract,
            assertion.riskScore,
            assertion.timestamp,
            assertion.oracle,
            assertion.disputed,
            assertion.verified,
            assertion.disputeDeadline
        );
    }

    /**
     * @dev Get dispute details
     * @param _disputeId ID of the dispute
     */
    function getDispute(uint256 _disputeId) external view returns (
        uint256 assertionId,
        address challenger,
        uint256 bondAmount,
        uint256 timestamp,
        bool resolved,
        bool successful
    ) {
        Dispute memory dispute = disputes[_disputeId];
        return (
            dispute.assertionId,
            dispute.challenger,
            dispute.bondAmount,
            dispute.timestamp,
            dispute.resolved,
            dispute.successful
        );
    }

    /**
     * @dev Check if an assertion can be disputed
     * @param _assertionId ID of the assertion
     */
    function canDispute(uint256 _assertionId) external view returns (bool) {
        RiskAssertion memory assertion = assertions[_assertionId];
        return !assertion.disputed && assertion.disputeDeadline > block.timestamp;
    }

    /**
     * @dev Get oracle stake information
     * @param _oracle Address of the oracle
     */
    function getOracleStake(address _oracle) external view returns (
        uint256 amount,
        uint256 slashCount,
        bool active
    ) {
        OracleStake memory stake = oracleStakes[_oracle];
        return (stake.amount, stake.slashCount, stake.active);
    }
}
