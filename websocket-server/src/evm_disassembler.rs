//! EVM Disassembler and Bytecode Analyzer
//! 
//! This module provides functionality to disassemble EVM bytecode, generate control flow graphs,
//! detect dangerous opcode patterns, and generate pseudo-Solidity signatures for contracts
//! without verified source code.

use std::collections::{HashMap, HashSet};
use std::fmt;

/// Risk patterns detected in bytecode
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskPattern {
    SelfDestruct {
        pc: usize,
        target_address: Option<String>,
    },
    DelegateCall {
        pc: usize,
        target_address: Option<String>,
    },
    HiddenMint {
        pc: usize,
        storage_slot: Option<String>,
    },
    RestrictedTransfer {
        pc: usize,
        restriction_type: String,
    },
    ArbitraryCall {
        pc: usize,
        call_type: String,
    },
    StorageManipulation {
        pc: usize,
        pattern: String,
    },
    ReentrancyRisk {
        pc: usize,
        external_call_pc: usize,
    },
}

impl RiskPattern {
    pub fn severity(&self) -> &str {
        match self {
            RiskPattern::SelfDestruct { .. } => "CRITICAL",
            RiskPattern::DelegateCall { .. } => "HIGH",
            RiskPattern::HiddenMint { .. } => "HIGH",
            RiskPattern::RestrictedTransfer { .. } => "MEDIUM",
            RiskPattern::ArbitraryCall { .. } => "HIGH",
            RiskPattern::StorageManipulation { .. } => "MEDIUM",
            RiskPattern::ReentrancyRisk { .. } => "HIGH",
        }
    }
    
    pub fn description(&self) -> &str {
        match self {
            RiskPattern::SelfDestruct { .. } => "Contract can self-destruct, potentially allowing fund drainage",
            RiskPattern::DelegateCall { .. } => "Uses delegatecall which can execute arbitrary code in contract context",
            RiskPattern::HiddenMint { .. } => "Hidden minting functionality detected via direct storage manipulation",
            RiskPattern::RestrictedTransfer { .. } => "Transfer restrictions may prevent users from selling tokens",
            RiskPattern::ArbitraryCall { .. } => "Arbitrary external calls detected, potential for malicious behavior",
            RiskPattern::StorageManipulation { .. } => "Direct storage manipulation detected, may bypass access controls",
            RiskPattern::ReentrancyRisk { .. } => "Potential reentrancy vulnerability detected",
        }
    }
}

/// Function signature extracted from bytecode
#[derive(Debug, Clone)]
pub struct FunctionSignature {
    pub selector: String,
    pub name: String,
    pub parameters: Vec<String>,
    pub returns: Vec<String>,
    pub visibility: String,
    pub mutability: String,
    pub start_pc: usize,
    pub end_pc: usize,
}

impl FunctionSignature {
    pub fn to_solidity(&self) -> String {
        let params = self.parameters.join(", ");
        let returns = if self.returns.is_empty() {
            String::new()
        } else {
            format!(" returns ({})", self.returns.join(", "))
        };
        
        format!(
            "{} {} {}({}){}",
            self.visibility, self.mutability, self.name, params, returns
        )
    }
}

/// Decompiler to generate pseudo-Solidity signatures
pub struct Decompiler {
    disassembler: Disassembler,
    function_selectors: HashMap<[u8; 4], String>, // Common function selector database
}

impl Decompiler {
    pub fn new(disassembler: Disassembler) -> Self {
        let mut decompiler = Self {
            disassembler,
            function_selectors: Self::build_selector_database(),
        };
        decompiler
    }
    
    /// Build a database of common function selectors
    fn build_selector_database() -> HashMap<[u8; 4], String> {
        let mut db = HashMap::new();
        
        // ERC20 standard functions
        db.insert([0xa9, 0x05, 0x9c, 0xbb], "balanceOf".to_string());
        db.insert([0x70, 0xa0, 0x82, 0x31], "transfer".to_string());
        db.insert([0x18, 0x16, 0xcf, 0xdd], "approve".to_string());
        db.insert([0x09, 0x5e, 0xa7, 0xb3], "transferFrom".to_string());
        db.insert([0x18, 0x1d, 0xc0, 0xde], "totalSupply".to_string());
        db.insert([0x31, 0x3c, 0xe5, 0x67], "name".to_string());
        db.insert([0x06, 0xfd, 0xde, 0x03], "symbol".to_string());
        db.insert([0x3f, 0x43, 0xa6, 0x82], "decimals".to_string());
        
        // Common ownership functions
        db.insert([0xf2, 0xf4, 0xeb, 0x38], "owner".to_string());
        db.insert([0x85, 0x82, 0x88, 0x6b], "renounceOwnership".to_string());
        db.insert([0x8f, 0x28, 0xf9, 0x18], "transferOwnership".to_string());
        
        // Mint/burn functions
        db.insert([0x40, 0xc1, 0x0f, 0x19], "mint".to_string());
        db.insert([0x79, 0xcc, 0x67, 0x9e], "burn".to_string());
        
        // Pause/unpause
        db.insert([0x845, 0x6c, 0xb6, 0xc4], "pause".to_string());
        db.insert([0x3f, 0x4b, 0xa3, 0x1a], "unpause".to_string());
        
        // Common proxy functions
        db.insert([0x7d, 0x64, 0xb8, 0x32], "implementation".to_string());
        db.insert([0x52, 0xef, 0x6b, 0x2c], "admin".to_string());
        db.insert([0xc1, 0x6a, 0x7d, 0x33], "changeAdmin".to_string());
        db.insert([0xbc, 0x19, 0x7c, 0x81], "upgradeTo".to_string());
        
        db
    }
    
    /// Generate pseudo-Solidity signatures from bytecode
    pub fn generate_signatures(&self) -> Vec<FunctionSignature> {
        let mut signatures = Vec::new();
        let cfg = self.disassembler.generate_cfg();
        
        // Find function dispatch patterns
        let dispatch_block = self.find_dispatch_block(&cfg);
        
        if let Some(dispatch_idx) = dispatch_block {
            signatures.extend(self.extract_functions_from_dispatch(&cfg, dispatch_idx));
        } else {
            // Fallback: analyze each basic block as potential function
            signatures.extend(self.analyze_blocks_as_functions(&cfg));
        }
        
        signatures
    }
    
    /// Find the dispatcher block (entry point with function selector logic)
    fn find_dispatch_block(&self, cfg: &ControlFlowGraph) -> Option<usize> {
        // Look for block with CALLDATALOAD pattern (typical dispatcher)
        for (idx, block) in cfg.blocks.iter().enumerate() {
            let has_calldataload = block.instructions.iter()
                .any(|instr| instr.opcode == Opcode::CALLDATALOAD);
            
            let has_jumpi = block.instructions.iter()
                .any(|instr| instr.opcode == Opcode::JUMPI);
            
            if has_calldataload && has_jumpi {
                return Some(idx);
            }
        }
        
        cfg.entry_block
    }
    
    /// Extract functions from dispatcher block
    fn extract_functions_from_dispatch(&self, cfg: &ControlFlowGraph, dispatch_idx: usize) -> Vec<FunctionSignature> {
        let mut signatures = Vec::new();
        
        if let Some(dispatch_block) = cfg.get_block(dispatch_idx) {
            // Analyze CALLDATALOAD patterns to extract function selectors
            for instr in &dispatch_block.instructions {
                if instr.opcode == Opcode::CALLDATALOAD {
                    if let Some(selector) = self.extract_function_selector(instr) {
                        // Find the target block for this selector
                        if let Some(target_pc) = self.find_jump_target(instr) {
                            let signature = self.create_signature_from_selector(selector, target_pc);
                            signatures.push(signature);
                        }
                    }
                }
            }
        }
        
        signatures
    }
    
    /// Fallback: analyze blocks as individual functions
    fn analyze_blocks_as_functions(&self, cfg: &ControlFlowGraph) -> Vec<FunctionSignature> {
        let mut signatures = Vec::new();
        
        for (idx, block) in cfg.blocks.iter().enumerate() {
            if block.instructions.is_empty() {
                continue;
            }
            
            // Create a generic signature for each block
            let signature = FunctionSignature {
                selector: format!("unknown_{:04x}", block.start_pc),
                name: format!("function_{:04x}", block.start_pc),
                parameters: self.infer_parameters(block),
                returns: self.infer_returns(block),
                visibility: "public".to_string(),
                mutability: self.infer_mutability(block),
                start_pc: block.start_pc,
                end_pc: block.end_pc,
            };
            
            signatures.push(signature);
        }
        
        signatures
    }
    
    /// Extract function selector from instruction context
    fn extract_function_selector(&self, instr: &Instruction) -> Option<[u8; 4]> {
        // Look for PUSH4 before CALLDATALOAD
        let preceding = self.disassembler.instructions_in_range(
            instr.pc.saturating_sub(5),
            instr.pc
        );
        
        for prev_instr in preceding {
            if matches!(prev_instr.opcode, Opcode::PUSH4) {
                if let Some(operand) = &prev_instr.operand {
                    if operand.len() >= 4 {
                        let mut selector = [0u8; 4];
                        selector.copy_from_slice(&operand[..4]);
                        return Some(selector);
                    }
                }
            }
        }
        
        None
    }
    
    /// Find jump target for a given instruction
    fn find_jump_target(&self, instr: &Instruction) -> Option<usize> {
        // Look for JUMPI that might jump to function implementation
        let following = self.disassembler.instructions_in_range(
            instr.pc,
            instr.pc + 10
        );
        
        for follow_instr in following {
            if follow_instr.opcode == Opcode::JUMPI {
                if let Some(operand) = &follow_instr.operand {
                    if operand.len() >= 4 {
                        let target_pc = usize::from_be_bytes([0, 0, 0, operand[0]]);
                        return Some(target_pc);
                    }
                }
            }
        }
        
        None
    }
    
    /// Create signature from known function selector
    fn create_signature_from_selector(&self, selector: [u8; 4], target_pc: usize) -> FunctionSignature {
        let name = self.function_selectors.get(&selector)
            .cloned()
            .unwrap_or_else(|| format!("unknown_{:02x}{:02x}{:02x}{:02x}", selector[0], selector[1], selector[2], selector[3]));
        
        // Find the target block to infer signature details
        let cfg = self.disassembler.generate_cfg();
        let target_block = cfg.blocks.iter()
            .find(|b| b.start_pc == target_pc);
        
        let (parameters, returns, mutability) = if let Some(block) = target_block {
            (
                self.infer_parameters(block),
                self.infer_returns(block),
                self.infer_mutability(block),
            )
        } else {
            (vec!["address".to_string(), "uint256".to_string()], vec!["bool".to_string()], "nonpayable".to_string())
        };
        
        FunctionSignature {
            selector: format!("0x{:02x}{:02x}{:02x}{:02x}", selector[0], selector[1], selector[2], selector[3]),
            name,
            parameters,
            returns,
            visibility: "public".to_string(),
            mutability,
            start_pc: target_pc,
            end_pc: target_pc + 100, // Rough estimate
        }
    }
    
    /// Infer function parameters from block analysis
    fn infer_parameters(&self, block: &BasicBlock) -> Vec<String> {
        let mut params = Vec::new();
        
        // Look for stack operations that might indicate parameters
        for instr in &block.instructions {
            match instr.opcode {
                Opcode::CALLDATALOAD => params.push("uint256".to_string()),
                Opcode::CALLDATASIZE => params.push("bytes".to_string()),
                Opcode::CALLVALUE => params.push("uint256".to_string()),
                _ => {}
            }
        }
        
        // Default to common ERC20 parameters if none found
        if params.is_empty() {
            params.push("address".to_string());
            params.push("uint256".to_string());
        }
        
        params
    }
    
    /// Infer return types from block analysis
    fn infer_returns(&self, block: &BasicBlock) -> Vec<String> {
        let mut returns = Vec::new();
        
        // Look for RETURN instructions to infer return types
        for instr in &block.instructions {
            if instr.opcode == Opcode::RETURN {
                returns.push("bool".to_string());
                break;
            }
        }
        
        returns
    }
    
    /// Infer function mutability
    fn infer_mutability(&self, block: &BasicBlock) -> String {
        // Check for state-changing operations
        let has_sstore = block.instructions.iter().any(|i| i.opcode == Opcode::SSTORE);
        let has_call = block.instructions.iter().any(|i| matches!(i.opcode, Opcode::CALL | Opcode::DELEGATECALL));
        let has_callvalue = block.instructions.iter().any(|i| i.opcode == Opcode::CALLVALUE);
        
        if has_callvalue {
            "payable".to_string()
        } else if has_sstore || has_call {
            "nonpayable".to_string()
        } else {
            "view".to_string()
        }
    }
    
    /// Generate complete pseudo-Solidity code
    pub fn generate_pseudo_solidity(&self) -> String {
        let signatures = self.generate_signatures();
        let risk_patterns = PatternMatcher::new(self.disassembler.clone()).detect_patterns();
        
        let mut code = String::new();
        
        // Add header comment
        code.push_str("// Generated pseudo-Solidity from bytecode analysis\n");
        code.push_str("// WARNING: This is approximate reconstruction and may not reflect actual source\n");
        code.push_str("// Generated by Rug Pull Detector EVM Disassembler\n\n");
        
        // Add SPDX identifier
        code.push_str("// SPDX-License-Identifier: UNDETERMINED\n");
        
        // Add pragma
        code.push_str("pragma solidity ^0.8.0;\n\n");
        
        // Add contract declaration
        code.push_str("contract DecompiledContract {\n");
        
        // Add detected risk patterns as comments
        if !risk_patterns.is_empty() {
            code.push_str("    // Risk Patterns Detected:\n");
            for risk in &risk_patterns {
                code.push_str(&format!("    // [{}] {} at PC 0x{:04x}: {}\n", 
                    risk.severity(), 
                    format!("{:?}", risk).split('{').next().unwrap_or("Unknown"),
                    self.get_risk_pc(risk),
                    risk.description()
                ));
            }
            code.push_str("\n");
        }
        
        // Add state variables (heuristic)
        code.push_str("    // State variables (inferred)\n");
        code.push_str("    mapping(address => uint256) public balanceOf;\n");
        code.push_str("    mapping(address => mapping(address => uint256)) public allowance;\n");
        code.push_str("    uint256 public totalSupply;\n");
        code.push_str("    string public name;\n");
        code.push_str("    string public symbol;\n");
        code.push_str("    uint8 public decimals;\n");
        code.push_str("\n");
        
        // Add events (heuristic)
        code.push_str("    // Events (inferred)\n");
        code.push_str("    event Transfer(address indexed from, address indexed to, uint256 value);\n");
        code.push_str("    event Approval(address indexed owner, address indexed spender, uint256 value);\n");
        code.push_str("\n");
        
        // Add function signatures
        code.push_str("    // Functions (extracted from bytecode)\n");
        for signature in &signatures {
            code.push_str(&format!("    {}\n", signature.to_solidity()));
        }
        
        code.push_str("}\n");
        
        code
    }
    
    /// Helper to get PC from risk pattern
    fn get_risk_pc(&self, risk: &RiskPattern) -> usize {
        match risk {
            RiskPattern::SelfDestruct { pc, .. } => *pc,
            RiskPattern::DelegateCall { pc, .. } => *pc,
            RiskPattern::HiddenMint { pc, .. } => *pc,
            RiskPattern::RestrictedTransfer { pc, .. } => *pc,
            RiskPattern::ArbitraryCall { pc, .. } => *pc,
            RiskPattern::StorageManipulation { pc, .. } => *pc,
            RiskPattern::ReentrancyRisk { pc, .. } => *pc,
        }
    }
}

/// Pattern matcher for detecting dangerous opcode sequences
pub struct PatternMatcher {
    disassembler: Disassembler,
}

impl PatternMatcher {
    pub fn new(disassembler: Disassembler) -> Self {
        Self { disassembler }
    }
    
    /// Detect all risk patterns in the bytecode
    pub fn detect_patterns(&self) -> Vec<RiskPattern> {
        let mut patterns = Vec::new();
        let cfg = self.disassembler.generate_cfg();
        
        // Detect SELFDESTRUCT patterns
        patterns.extend(self.detect_selfdestruct());
        
        // Detect DELEGATECALL patterns
        patterns.extend(self.detect_delegatecall());
        
        // Detect hidden mint patterns
        patterns.extend(self.detect_hidden_mint());
        
        // Detect restricted transfer patterns
        patterns.extend(self.detect_restricted_transfer());
        
        // Detect arbitrary call patterns
        patterns.extend(self.detect_arbitrary_calls());
        
        // Detect storage manipulation patterns
        patterns.extend(self.detect_storage_manipulation());
        
        // Detect reentrancy risks
        patterns.extend(self.detect_reentrancy(&cfg));
        
        patterns
    }
    
    /// Detect SELFDESTRUCT instructions
    fn detect_selfdestruct(&self) -> Vec<RiskPattern> {
        let mut patterns = Vec::new();
        
        for instr in &self.disassembler.instructions {
            if instr.opcode == Opcode::SELFDESTRUCT {
                patterns.push(RiskPattern::SelfDestruct {
                    pc: instr.pc,
                    target_address: self.extract_address_from_stack(instr),
                });
            }
        }
        
        patterns
    }
    
    /// Detect DELEGATECALL patterns
    fn detect_delegatecall(&self) -> Vec<RiskPattern> {
        let mut patterns = Vec::new();
        
        for instr in &self.disassembler.instructions {
            if instr.opcode == Opcode::DELEGATECALL {
                patterns.push(RiskPattern::DelegateCall {
                    pc: instr.pc,
                    target_address: self.extract_address_from_stack(instr),
                });
            }
        }
        
        patterns
    }
    
    /// Detect hidden mint patterns (SSTORE with specific storage slots)
    fn detect_hidden_mint(&self) -> Vec<RiskPattern> {
        let mut patterns = Vec::new();
        
        for instr in &self.disassembler.instructions {
            if instr.opcode == Opcode::SSTORE {
                // Check if this is in a suspicious context
                if self.is_suspicious_storage_access(instr) {
                    patterns.push(RiskPattern::HiddenMint {
                        pc: instr.pc,
                        storage_slot: self.extract_storage_slot(instr),
                    });
                }
            }
        }
        
        patterns
    }
    
    /// Detect restricted transfer patterns
    fn detect_restricted_transfer(&self) -> Vec<RiskPattern> {
        let mut patterns = Vec::new();
        
        // Look for transfer function patterns with restrictions
        let transfer_blocks = self.find_function_blocks("transfer");
        
        for block_idx in transfer_blocks {
            if let Some(block) = self.disassembler.generate_cfg().get_block(block_idx) {
                for instr in &block.instructions {
                    // Check for require/revert patterns that might restrict transfers
                    if instr.opcode == Opcode::REVERT || instr.opcode == Opcode::INVALID {
                        patterns.push(RiskPattern::RestrictedTransfer {
                            pc: instr.pc,
                            restriction_type: "Conditional revert in transfer function".to_string(),
                        });
                    }
                }
            }
        }
        
        patterns
    }
    
    /// Detect arbitrary call patterns
    fn detect_arbitrary_calls(&self) -> Vec<RiskPattern> {
        let mut patterns = Vec::new();
        
        for instr in &self.disassembler.instructions {
            match instr.opcode {
                Opcode::CALL | Opcode::CALLCODE | Opcode::DELEGATECALL | Opcode::STATICCALL => {
                    // Check if call target is dynamically computed
                    if self.is_dynamic_call_target(instr) {
                        patterns.push(RiskPattern::ArbitraryCall {
                            pc: instr.pc,
                            call_type: format!("{:?}", instr.opcode),
                        });
                    }
                }
                _ => {}
            }
        }
        
        patterns
    }
    
    /// Detect storage manipulation patterns
    fn detect_storage_manipulation(&self) -> Vec<RiskPattern> {
        let mut patterns = Vec::new();
        
        for instr in &self.disassembler.instructions {
            if instr.opcode == Opcode::SSTORE {
                // Check for suspicious storage patterns
                if let Some(pattern) = self.analyze_storage_pattern(instr) {
                    patterns.push(RiskPattern::StorageManipulation {
                        pc: instr.pc,
                        pattern,
                    });
                }
            }
        }
        
        patterns
    }
    
    /// Detect reentrancy risks
    fn detect_reentrancy(&self, cfg: &ControlFlowGraph) -> Vec<RiskPattern> {
        let mut patterns = Vec::new();
        
        for block in &cfg.blocks {
            let mut external_call_pc = None;
            
            for instr in &block.instructions {
                // Find external calls
                if matches!(instr.opcode, Opcode::CALL | Opcode::DELEGATECALL | Opcode::STATICCALL) {
                    external_call_pc = Some(instr.pc);
                }
                
                // Check for state changes after external call
                if external_call_pc.is_some() && instr.opcode == Opcode::SSTORE {
                    patterns.push(RiskPattern::ReentrancyRisk {
                        pc: instr.pc,
                        external_call_pc: external_call_pc.unwrap(),
                    });
                }
            }
        }
        
        patterns
    }
    
    /// Helper: Extract address from stack context
    fn extract_address_from_stack(&self, instr: &Instruction) -> Option<String> {
        // Simplified address extraction - in reality this would require stack simulation
        if let Some(operand) = &instr.operand {
            if operand.len() >= 20 {
                Some(format!("0x{}", hex::encode(&operand[..20])))
            } else {
                Some(format!("0x{}", hex::encode(operand)))
            }
        } else {
            None
        }
    }
    
    /// Helper: Extract storage slot from instruction context
    fn extract_storage_slot(&self, instr: &Instruction) -> Option<String> {
        // Simplified storage slot extraction
        if let Some(operand) = &instr.operand {
            Some(format!("0x{}", hex::encode(operand)))
        } else {
            None
        }
    }
    
    /// Helper: Check if storage access is suspicious
    fn is_suspicious_storage_access(&self, instr: &Instruction) -> bool {
        // Check if SSTORE is in a suspicious context
        // This is a simplified check - real implementation would analyze stack
        
        // Look for patterns like direct SSTORE without proper access control
        let preceding_instructions = self.disassembler.instructions_in_range(
            instr.pc.saturating_sub(10),
            instr.pc
        );
        
        // Check if there's no CALLER check before SSTORE
        let has_caller_check = preceding_instructions.iter()
            .any(|i| i.opcode == Opcode::CALLER);
        
        !has_caller_check && instr.opcode == Opcode::SSTORE
    }
    
    /// Helper: Find function blocks by name (heuristic)
    fn find_function_blocks(&self, _function_name: &str) -> Vec<usize> {
        // Simplified function detection - in reality would use ABI or hash matching
        // For now, return all blocks that could be functions
        let cfg = self.disassembler.generate_cfg();
        cfg.reachable_blocks()
    }
    
    /// Helper: Check if call target is dynamically computed
    fn is_dynamic_call_target(&self, instr: &Instruction) -> bool {
        // Simplified check - dynamic targets typically come from memory or storage
        let preceding_instructions = self.disassembler.instructions_in_range(
            instr.pc.saturating_sub(5),
            instr.pc
        );
        
        let has_dynamic_load = preceding_instructions.iter()
            .any(|i| matches!(i.opcode, Opcode::MLOAD | Opcode::SLOAD));
        
        has_dynamic_load
    }
    
    /// Helper: Analyze storage access pattern
    fn analyze_storage_pattern(&self, instr: &Instruction) -> Option<String> {
        // Analyze the pattern of storage access
        let preceding_instructions = self.disassembler.instructions_in_range(
            instr.pc.saturating_sub(10),
            instr.pc
        );
        
        // Check for specific patterns
        if preceding_instructions.iter().any(|i| i.opcode == Opcode::CALLVALUE) {
            return Some("Storage modification based on call value".to_string());
        }
        
        if preceding_instructions.iter().any(|i| i.opcode == Opcode::CALLER) {
            return Some("Storage modification based on caller".to_string());
        }
        
        Some("Direct storage manipulation".to_string())
    }
}

/// EVM Opcodes as defined in the Ethereum Yellow Paper
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Opcode {
    // Stop and Arithmetic Operations
    STOP,
    ADD,
    MUL,
    SUB,
    DIV,
    SDIV,
    MOD,
    SMOD,
    ADDMOD,
    MULMOD,
    EXP,
    SIGNEXTEND,
    
    // Comparison & Bitwise Logic Operations
    LT,
    GT,
    SLT,
    SGT,
    EQ,
    ISZERO,
    AND,
    OR,
    XOR,
    NOT,
    BYTE,
    SHL,
    SHR,
    SAR,
    
    // SHA3
    SHA3,
    
    // Environmental Information
    ADDRESS,
    BALANCE,
    ORIGIN,
    CALLER,
    CALLVALUE,
    CALLDATALOAD,
    CALLDATASIZE,
    CALLDATACOPY,
    CODESIZE,
    CODECOPY,
    GASPRICE,
    EXTCODESIZE,
    EXTCODECOPY,
    RETURNDATASIZE,
    RETURNDATACOPY,
    EXTCODEHASH,
    
    // Block Information
    BLOCKHASH,
    COINBASE,
    TIMESTAMP,
    NUMBER,
    DIFFICULTY,
    GASLIMIT,
    CHAINID,
    SELFBALANCE,
    BASEFEE,
    
    // Stack, Memory, Storage and Flow Operations
    POP,
    MLOAD,
    MSTORE,
    MSTORE8,
    SLOAD,
    SSTORE,
    JUMP,
    JUMPI,
    PC,
    MSIZE,
    GAS,
    JUMPDEST,
    
    // Push Operations
    PUSH1,
    PUSH2,
    PUSH3,
    PUSH4,
    PUSH5,
    PUSH6,
    PUSH7,
    PUSH8,
    PUSH9,
    PUSH10,
    PUSH11,
    PUSH12,
    PUSH13,
    PUSH14,
    PUSH15,
    PUSH16,
    PUSH17,
    PUSH18,
    PUSH19,
    PUSH20,
    PUSH21,
    PUSH22,
    PUSH23,
    PUSH24,
    PUSH25,
    PUSH26,
    PUSH27,
    PUSH28,
    PUSH29,
    PUSH30,
    PUSH31,
    PUSH32,
    
    // Duplication Operations
    DUP1,
    DUP2,
    DUP3,
    DUP4,
    DUP5,
    DUP6,
    DUP7,
    DUP8,
    DUP9,
    DUP10,
    DUP11,
    DUP12,
    DUP13,
    DUP14,
    DUP15,
    DUP16,
    
    // Exchange Operations
    SWAP1,
    SWAP2,
    SWAP3,
    SWAP4,
    SWAP5,
    SWAP6,
    SWAP7,
    SWAP8,
    SWAP9,
    SWAP10,
    SWAP11,
    SWAP12,
    SWAP13,
    SWAP14,
    SWAP15,
    SWAP16,
    
    // Logging Operations
    LOG0,
    LOG1,
    LOG2,
    LOG3,
    LOG4,
    
    // System Operations
    CREATE,
    CALL,
    CALLCODE,
    RETURN,
    DELEGATECALL,
    CREATE2,
    STATICCALL,
    REVERT,
    INVALID,
    SELFDESTRUCT,
    
    // Unknown opcode
    UNKNOWN(u8),
}

impl Opcode {
    /// Parse a byte into an Opcode
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0x00 => Opcode::STOP,
            0x01 => Opcode::ADD,
            0x02 => Opcode::MUL,
            0x03 => Opcode::SUB,
            0x04 => Opcode::DIV,
            0x05 => Opcode::SDIV,
            0x06 => Opcode::MOD,
            0x07 => Opcode::SMOD,
            0x08 => Opcode::ADDMOD,
            0x09 => Opcode::MULMOD,
            0x0a => Opcode::EXP,
            0x0b => Opcode::SIGNEXTEND,
            0x10 => Opcode::LT,
            0x11 => Opcode::GT,
            0x12 => Opcode::SLT,
            0x13 => Opcode::SGT,
            0x14 => Opcode::EQ,
            0x15 => Opcode::ISZERO,
            0x16 => Opcode::AND,
            0x17 => Opcode::OR,
            0x18 => Opcode::XOR,
            0x19 => Opcode::NOT,
            0x1a => Opcode::BYTE,
            0x1b => Opcode::SHL,
            0x1c => Opcode::SHR,
            0x1d => Opcode::SAR,
            0x20 => Opcode::SHA3,
            0x30 => Opcode::ADDRESS,
            0x31 => Opcode::BALANCE,
            0x32 => Opcode::ORIGIN,
            0x33 => Opcode::CALLER,
            0x34 => Opcode::CALLVALUE,
            0x35 => Opcode::CALLDATALOAD,
            0x36 => Opcode::CALLDATASIZE,
            0x37 => Opcode::CALLDATACOPY,
            0x38 => Opcode::CODESIZE,
            0x39 => Opcode::CODECOPY,
            0x3a => Opcode::GASPRICE,
            0x3b => Opcode::EXTCODESIZE,
            0x3c => Opcode::EXTCODECOPY,
            0x3d => Opcode::RETURNDATASIZE,
            0x3e => Opcode::RETURNDATACOPY,
            0x3f => Opcode::EXTCODEHASH,
            0x40 => Opcode::BLOCKHASH,
            0x41 => Opcode::COINBASE,
            0x42 => Opcode::TIMESTAMP,
            0x43 => Opcode::NUMBER,
            0x44 => Opcode::DIFFICULTY,
            0x45 => Opcode::GASLIMIT,
            0x46 => Opcode::CHAINID,
            0x47 => Opcode::SELFBALANCE,
            0x48 => Opcode::BASEFEE,
            0x50 => Opcode::POP,
            0x51 => Opcode::MLOAD,
            0x52 => Opcode::MSTORE,
            0x53 => Opcode::MSTORE8,
            0x54 => Opcode::SLOAD,
            0x55 => Opcode::SSTORE,
            0x56 => Opcode::JUMP,
            0x57 => Opcode::JUMPI,
            0x58 => Opcode::PC,
            0x59 => Opcode::MSIZE,
            0x5a => Opcode::GAS,
            0x5b => Opcode::JUMPDEST,
            0x60 => Opcode::PUSH1,
            0x61 => Opcode::PUSH2,
            0x62 => Opcode::PUSH3,
            0x63 => Opcode::PUSH4,
            0x64 => Opcode::PUSH5,
            0x65 => Opcode::PUSH6,
            0x66 => Opcode::PUSH7,
            0x67 => Opcode::PUSH8,
            0x68 => Opcode::PUSH9,
            0x69 => Opcode::PUSH10,
            0x6a => Opcode::PUSH11,
            0x6b => Opcode::PUSH12,
            0x6c => Opcode::PUSH13,
            0x6d => Opcode::PUSH14,
            0x6e => Opcode::PUSH15,
            0x6f => Opcode::PUSH16,
            0x70 => Opcode::PUSH17,
            0x71 => Opcode::PUSH18,
            0x72 => Opcode::PUSH19,
            0x73 => Opcode::PUSH20,
            0x74 => Opcode::PUSH21,
            0x75 => Opcode::PUSH22,
            0x76 => Opcode::PUSH23,
            0x77 => Opcode::PUSH24,
            0x78 => Opcode::PUSH25,
            0x79 => Opcode::PUSH26,
            0x7a => Opcode::PUSH27,
            0x7b => Opcode::PUSH28,
            0x7c => Opcode::PUSH29,
            0x7d => Opcode::PUSH30,
            0x7e => Opcode::PUSH31,
            0x7f => Opcode::PUSH32,
            0x80 => Opcode::DUP1,
            0x81 => Opcode::DUP2,
            0x82 => Opcode::DUP3,
            0x83 => Opcode::DUP4,
            0x84 => Opcode::DUP5,
            0x85 => Opcode::DUP6,
            0x86 => Opcode::DUP7,
            0x87 => Opcode::DUP8,
            0x88 => Opcode::DUP9,
            0x89 => Opcode::DUP10,
            0x8a => Opcode::DUP11,
            0x8b => Opcode::DUP12,
            0x8c => Opcode::DUP13,
            0x8d => Opcode::DUP14,
            0x8e => Opcode::DUP15,
            0x8f => Opcode::DUP16,
            0x90 => Opcode::SWAP1,
            0x91 => Opcode::SWAP2,
            0x92 => Opcode::SWAP3,
            0x93 => Opcode::SWAP4,
            0x94 => Opcode::SWAP5,
            0x95 => Opcode::SWAP6,
            0x96 => Opcode::SWAP7,
            0x97 => Opcode::SWAP8,
            0x98 => Opcode::SWAP9,
            0x99 => Opcode::SWAP10,
            0x9a => Opcode::SWAP11,
            0x9b => Opcode::SWAP12,
            0x9c => Opcode::SWAP13,
            0x9d => Opcode::SWAP14,
            0x9e => Opcode::SWAP15,
            0x9f => Opcode::SWAP16,
            0xa0 => Opcode::LOG0,
            0xa1 => Opcode::LOG1,
            0xa2 => Opcode::LOG2,
            0xa3 => Opcode::LOG3,
            0xa4 => Opcode::LOG4,
            0xf0 => Opcode::CREATE,
            0xf1 => Opcode::CALL,
            0xf2 => Opcode::CALLCODE,
            0xf3 => Opcode::RETURN,
            0xf4 => Opcode::DELEGATECALL,
            0xf5 => Opcode::CREATE2,
            0xfa => Opcode::STATICCALL,
            0xfd => Opcode::REVERT,
            0xfe => Opcode::INVALID,
            0xff => Opcode::SELFDESTRUCT,
            _ => Opcode::UNKNOWN(byte),
        }
    }
    
    /// Get the number of bytes this opcode consumes (including immediate data)
    pub fn operand_size(&self) -> usize {
        match self {
            Opcode::PUSH1 => 1,
            Opcode::PUSH2 => 2,
            Opcode::PUSH3 => 3,
            Opcode::PUSH4 => 4,
            Opcode::PUSH5 => 5,
            Opcode::PUSH6 => 6,
            Opcode::PUSH7 => 7,
            Opcode::PUSH8 => 8,
            Opcode::PUSH9 => 9,
            Opcode::PUSH10 => 10,
            Opcode::PUSH11 => 11,
            Opcode::PUSH12 => 12,
            Opcode::PUSH13 => 13,
            Opcode::PUSH14 => 14,
            Opcode::PUSH15 => 15,
            Opcode::PUSH16 => 16,
            Opcode::PUSH17 => 17,
            Opcode::PUSH18 => 18,
            Opcode::PUSH19 => 19,
            Opcode::PUSH20 => 20,
            Opcode::PUSH21 => 21,
            Opcode::PUSH22 => 22,
            Opcode::PUSH23 => 23,
            Opcode::PUSH24 => 24,
            Opcode::PUSH25 => 25,
            Opcode::PUSH26 => 26,
            Opcode::PUSH27 => 27,
            Opcode::PUSH28 => 28,
            Opcode::PUSH29 => 29,
            Opcode::PUSH30 => 30,
            Opcode::PUSH31 => 31,
            Opcode::PUSH32 => 32,
            _ => 0,
        }
    }
    
    /// Check if this opcode is a jump destination
    pub fn is_jumpdest(&self) -> bool {
        *self == Opcode::JUMPDEST
    }
    
    /// Check if this opcode is a jump instruction
    pub fn is_jump(&self) -> bool {
        matches!(self, Opcode::JUMP | Opcode::JUMPI)
    }
    
    /// Check if this opcode is a terminating instruction
    pub fn is_terminating(&self) -> bool {
        matches!(self, Opcode::STOP | Opcode::RETURN | Opcode::REVERT | Opcode::SELFDESTRUCT | Opcode::INVALID)
    }
    
    /// Check if this opcode is considered dangerous
    pub fn is_dangerous(&self) -> bool {
        matches!(self, 
            Opcode::SELFDESTRUCT | 
            Opcode::DELEGATECALL | 
            Opcode::CALLCODE |
            Opcode::SSTORE
        )
    }
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Opcode::STOP => write!(f, "STOP"),
            Opcode::ADD => write!(f, "ADD"),
            Opcode::MUL => write!(f, "MUL"),
            Opcode::SUB => write!(f, "SUB"),
            Opcode::DIV => write!(f, "DIV"),
            Opcode::SDIV => write!(f, "SDIV"),
            Opcode::MOD => write!(f, "MOD"),
            Opcode::SMOD => write!(f, "SMOD"),
            Opcode::ADDMOD => write!(f, "ADDMOD"),
            Opcode::MULMOD => write!(f, "MULMOD"),
            Opcode::EXP => write!(f, "EXP"),
            Opcode::SIGNEXTEND => write!(f, "SIGNEXTEND"),
            Opcode::LT => write!(f, "LT"),
            Opcode::GT => write!(f, "GT"),
            Opcode::SLT => write!(f, "SLT"),
            Opcode::SGT => write!(f, "SGT"),
            Opcode::EQ => write!(f, "EQ"),
            Opcode::ISZERO => write!(f, "ISZERO"),
            Opcode::AND => write!(f, "AND"),
            Opcode::OR => write!(f, "OR"),
            Opcode::XOR => write!(f, "XOR"),
            Opcode::NOT => write!(f, "NOT"),
            Opcode::BYTE => write!(f, "BYTE"),
            Opcode::SHL => write!(f, "SHL"),
            Opcode::SHR => write!(f, "SHR"),
            Opcode::SAR => write!(f, "SAR"),
            Opcode::SHA3 => write!(f, "SHA3"),
            Opcode::ADDRESS => write!(f, "ADDRESS"),
            Opcode::BALANCE => write!(f, "BALANCE"),
            Opcode::ORIGIN => write!(f, "ORIGIN"),
            Opcode::CALLER => write!(f, "CALLER"),
            Opcode::CALLVALUE => write!(f, "CALLVALUE"),
            Opcode::CALLDATALOAD => write!(f, "CALLDATALOAD"),
            Opcode::CALLDATASIZE => write!(f, "CALLDATASIZE"),
            Opcode::CALLDATACOPY => write!(f, "CALLDATACOPY"),
            Opcode::CODESIZE => write!(f, "CODESIZE"),
            Opcode::CODECOPY => write!(f, "CODECOPY"),
            Opcode::GASPRICE => write!(f, "GASPRICE"),
            Opcode::EXTCODESIZE => write!(f, "EXTCODESIZE"),
            Opcode::EXTCODECOPY => write!(f, "EXTCODECOPY"),
            Opcode::RETURNDATASIZE => write!(f, "RETURNDATASIZE"),
            Opcode::RETURNDATACOPY => write!(f, "RETURNDATACOPY"),
            Opcode::EXTCODEHASH => write!(f, "EXTCODEHASH"),
            Opcode::BLOCKHASH => write!(f, "BLOCKHASH"),
            Opcode::COINBASE => write!(f, "COINBASE"),
            Opcode::TIMESTAMP => write!(f, "TIMESTAMP"),
            Opcode::NUMBER => write!(f, "NUMBER"),
            Opcode::DIFFICULTY => write!(f, "DIFFICULTY"),
            Opcode::GASLIMIT => write!(f, "GASLIMIT"),
            Opcode::CHAINID => write!(f, "CHAINID"),
            Opcode::SELFBALANCE => write!(f, "SELFBALANCE"),
            Opcode::BASEFEE => write!(f, "BASEFEE"),
            Opcode::POP => write!(f, "POP"),
            Opcode::MLOAD => write!(f, "MLOAD"),
            Opcode::MSTORE => write!(f, "MSTORE"),
            Opcode::MSTORE8 => write!(f, "MSTORE8"),
            Opcode::SLOAD => write!(f, "SLOAD"),
            Opcode::SSTORE => write!(f, "SSTORE"),
            Opcode::JUMP => write!(f, "JUMP"),
            Opcode::JUMPI => write!(f, "JUMPI"),
            Opcode::PC => write!(f, "PC"),
            Opcode::MSIZE => write!(f, "MSIZE"),
            Opcode::GAS => write!(f, "GAS"),
            Opcode::JUMPDEST => write!(f, "JUMPDEST"),
            Opcode::PUSH1 => write!(f, "PUSH1"),
            Opcode::PUSH2 => write!(f, "PUSH2"),
            Opcode::PUSH3 => write!(f, "PUSH3"),
            Opcode::PUSH4 => write!(f, "PUSH4"),
            Opcode::PUSH5 => write!(f, "PUSH5"),
            Opcode::PUSH6 => write!(f, "PUSH6"),
            Opcode::PUSH7 => write!(f, "PUSH7"),
            Opcode::PUSH8 => write!(f, "PUSH8"),
            Opcode::PUSH9 => write!(f, "PUSH9"),
            Opcode::PUSH10 => write!(f, "PUSH10"),
            Opcode::PUSH11 => write!(f, "PUSH11"),
            Opcode::PUSH12 => write!(f, "PUSH12"),
            Opcode::PUSH13 => write!(f, "PUSH13"),
            Opcode::PUSH14 => write!(f, "PUSH14"),
            Opcode::PUSH15 => write!(f, "PUSH15"),
            Opcode::PUSH16 => write!(f, "PUSH16"),
            Opcode::PUSH17 => write!(f, "PUSH17"),
            Opcode::PUSH18 => write!(f, "PUSH18"),
            Opcode::PUSH19 => write!(f, "PUSH19"),
            Opcode::PUSH20 => write!(f, "PUSH20"),
            Opcode::PUSH21 => write!(f, "PUSH21"),
            Opcode::PUSH22 => write!(f, "PUSH22"),
            Opcode::PUSH23 => write!(f, "PUSH23"),
            Opcode::PUSH24 => write!(f, "PUSH24"),
            Opcode::PUSH25 => write!(f, "PUSH25"),
            Opcode::PUSH26 => write!(f, "PUSH26"),
            Opcode::PUSH27 => write!(f, "PUSH27"),
            Opcode::PUSH28 => write!(f, "PUSH28"),
            Opcode::PUSH29 => write!(f, "PUSH29"),
            Opcode::PUSH30 => write!(f, "PUSH30"),
            Opcode::PUSH31 => write!(f, "PUSH31"),
            Opcode::PUSH32 => write!(f, "PUSH32"),
            Opcode::DUP1 => write!(f, "DUP1"),
            Opcode::DUP2 => write!(f, "DUP2"),
            Opcode::DUP3 => write!(f, "DUP3"),
            Opcode::DUP4 => write!(f, "DUP4"),
            Opcode::DUP5 => write!(f, "DUP5"),
            Opcode::DUP6 => write!(f, "DUP6"),
            Opcode::DUP7 => write!(f, "DUP7"),
            Opcode::DUP8 => write!(f, "DUP8"),
            Opcode::DUP9 => write!(f, "DUP9"),
            Opcode::DUP10 => write!(f, "DUP10"),
            Opcode::DUP11 => write!(f, "DUP11"),
            Opcode::DUP12 => write!(f, "DUP12"),
            Opcode::DUP13 => write!(f, "DUP13"),
            Opcode::DUP14 => write!(f, "DUP14"),
            Opcode::DUP15 => write!(f, "DUP15"),
            Opcode::DUP16 => write!(f, "DUP16"),
            Opcode::SWAP1 => write!(f, "SWAP1"),
            Opcode::SWAP2 => write!(f, "SWAP2"),
            Opcode::SWAP3 => write!(f, "SWAP3"),
            Opcode::SWAP4 => write!(f, "SWAP4"),
            Opcode::SWAP5 => write!(f, "SWAP5"),
            Opcode::SWAP6 => write!(f, "SWAP6"),
            Opcode::SWAP7 => write!(f, "SWAP7"),
            Opcode::SWAP8 => write!(f, "SWAP8"),
            Opcode::SWAP9 => write!(f, "SWAP9"),
            Opcode::SWAP10 => write!(f, "SWAP10"),
            Opcode::SWAP11 => write!(f, "SWAP11"),
            Opcode::SWAP12 => write!(f, "SWAP12"),
            Opcode::SWAP13 => write!(f, "SWAP13"),
            Opcode::SWAP14 => write!(f, "SWAP14"),
            Opcode::SWAP15 => write!(f, "SWAP15"),
            Opcode::SWAP16 => write!(f, "SWAP16"),
            Opcode::LOG0 => write!(f, "LOG0"),
            Opcode::LOG1 => write!(f, "LOG1"),
            Opcode::LOG2 => write!(f, "LOG2"),
            Opcode::LOG3 => write!(f, "LOG3"),
            Opcode::LOG4 => write!(f, "LOG4"),
            Opcode::CREATE => write!(f, "CREATE"),
            Opcode::CALL => write!(f, "CALL"),
            Opcode::CALLCODE => write!(f, "CALLCODE"),
            Opcode::RETURN => write!(f, "RETURN"),
            Opcode::DELEGATECALL => write!(f, "DELEGATECALL"),
            Opcode::CREATE2 => write!(f, "CREATE2"),
            Opcode::STATICCALL => write!(f, "STATICCALL"),
            Opcode::REVERT => write!(f, "REVERT"),
            Opcode::INVALID => write!(f, "INVALID"),
            Opcode::SELFDESTRUCT => write!(f, "SELFDESTRUCT"),
            Opcode::UNKNOWN(byte) => write!(f, "UNKNOWN(0x{:02x})", byte),
        }
    }
}

/// A single disassembled instruction
#[derive(Debug, Clone)]
pub struct Instruction {
    pub pc: usize,
    pub opcode: Opcode,
    pub operand: Option<Vec<u8>>,
}

impl Instruction {
    pub fn new(pc: usize, opcode: Opcode, operand: Option<Vec<u8>>) -> Self {
        Self { pc, opcode, operand }
    }
}

/// Basic block in control flow graph
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub start_pc: usize,
    pub end_pc: usize,
    pub instructions: Vec<Instruction>,
    pub successors: Vec<usize>,
    pub predecessors: Vec<usize>,
}

impl BasicBlock {
    pub fn new(start_pc: usize) -> Self {
        Self {
            start_pc,
            end_pc: start_pc,
            instructions: Vec::new(),
            successors: Vec::new(),
            predecessors: Vec::new(),
        }
    }
    
    pub fn add_instruction(&mut self, instruction: Instruction) {
        self.end_pc = instruction.pc;
        self.instructions.push(instruction);
    }
    
    pub fn is_entry(&self) -> bool {
        self.start_pc == 0
    }
    
    pub fn is_exit(&self) -> bool {
        self.instructions.iter().any(|instr| instr.opcode.is_terminating())
    }
}

/// Control Flow Graph
#[derive(Debug, Clone)]
pub struct ControlFlowGraph {
    pub blocks: Vec<BasicBlock>,
    pub entry_block: Option<usize>,
    pub exit_blocks: Vec<usize>,
}

impl ControlFlowGraph {
    pub fn new() -> Self {
        Self {
            blocks: Vec::new(),
            entry_block: None,
            exit_blocks: Vec::new(),
        }
    }
    
    pub fn add_block(&mut self, block: BasicBlock) -> usize {
        let index = self.blocks.len();
        if block.is_entry() {
            self.entry_block = Some(index);
        }
        if block.is_exit() {
            self.exit_blocks.push(index);
        }
        self.blocks.push(block);
        index
    }
    
    pub fn get_block(&self, index: usize) -> Option<&BasicBlock> {
        self.blocks.get(index)
    }
    
    pub fn get_block_mut(&mut self, index: usize) -> Option<&mut BasicBlock> {
        self.blocks.get_mut(index)
    }
    
    /// Get all reachable blocks from entry
    pub fn reachable_blocks(&self) -> Vec<usize> {
        let mut visited = HashSet::new();
        let mut worklist = Vec::new();
        
        if let Some(entry) = self.entry_block {
            worklist.push(entry);
            visited.insert(entry);
        }
        
        while let Some(current) = worklist.pop() {
            if let Some(block) = self.get_block(current) {
                for &successor in &block.successors {
                    if visited.insert(successor) {
                        worklist.push(successor);
                    }
                }
            }
        }
        
        visited.into_iter().collect()
    }
    
    /// Detect loops in the CFG
    pub fn detect_loops(&self) -> Vec<Vec<usize>> {
        let mut loops = Vec::new();
        let reachable = self.reachable_blocks();
        
        // Simple back-edge detection
        for &block_idx in &reachable {
            if let Some(block) = self.get_block(block_idx) {
                for &successor in &block.successors {
                    // If successor dominates current (simplified check), it's a back edge
                    if successor <= block_idx && reachable.contains(&successor) {
                        loops.push(vec![successor, block_idx]);
                    }
                }
            }
        }
        
        loops
    }
}

/// EVM Bytecode Disassembler
pub struct Disassembler {
    bytecode: Vec<u8>,
    instructions: Vec<Instruction>,
    jump_destinations: HashSet<usize>,
}

impl Disassembler {
    /// Create a new disassembler from hex bytecode string
    pub fn from_hex(hex_string: &str) -> Result<Self, String> {
        let hex_string = hex_string.trim_start_matches("0x");
        let bytecode = hex::decode(hex_string)
            .map_err(|e| format!("Invalid hex string: {}", e))?;
        
        Self::from_bytes(bytecode)
    }
    
    /// Create a new disassembler from raw bytecode bytes
    pub fn from_bytes(bytecode: Vec<u8>) -> Result<Self, String> {
        let mut disassembler = Self {
            bytecode,
            instructions: Vec::new(),
            jump_destinations: HashSet::new(),
        };
        
        disassembler.disassemble()?;
        Ok(disassembler)
    }
    
    /// Disassemble the bytecode into instructions
    fn disassemble(&mut self) -> Result<(), String> {
        let mut pc = 0;
        
        while pc < self.bytecode.len() {
            let opcode_byte = self.bytecode[pc];
            let opcode = Opcode::from_byte(opcode_byte);
            let operand_size = opcode.operand_size();
            
            let operand = if operand_size > 0 {
                let end = pc + 1 + operand_size;
                if end > self.bytecode.len() {
                    return Err(format!("Incomplete operand at PC {}", pc));
                }
                Some(self.bytecode[pc + 1..end].to_vec())
            } else {
                None
            };
            
            let instruction = Instruction::new(pc, opcode, operand);
            self.instructions.push(instruction.clone());
            
            // Track jump destinations
            if opcode.is_jumpdest() {
                self.jump_destinations.insert(pc);
            }
            
            pc += 1 + operand_size;
        }
        
        Ok(())
    }
    
    /// Get all disassembled instructions
    pub fn instructions(&self) -> &[Instruction] {
        &self.instructions
    }
    
    /// Get jump destinations
    pub fn jump_destinations(&self) -> &HashSet<usize> {
        &self.jump_destinations
    }
    
    /// Find instruction at specific program counter
    pub fn instruction_at(&self, pc: usize) -> Option<&Instruction> {
        self.instructions.iter().find(|instr| instr.pc == pc)
    }
    
    /// Get instructions in a range
    pub fn instructions_in_range(&self, start: usize, end: usize) -> Vec<&Instruction> {
        self.instructions.iter()
            .filter(|instr| instr.pc >= start && instr.pc < end)
            .collect()
    }
    
    /// Get human-readable disassembly
    pub fn to_string(&self) -> String {
        let mut output = String::new();
        
        for instr in &self.instructions {
            output.push_str(&format!("{:04x}: ", instr.pc));
            
            match &instr.operand {
                Some(operand) if !operand.is_empty() => {
                    let operand_hex = hex::encode(operand);
                    output.push_str(&format!("{} 0x{}\n", instr.opcode, operand_hex));
                }
                _ => {
                    output.push_str(&format!("{}\n", instr.opcode));
                }
            }
        }
        
        output
    }
    
    /// Generate control flow graph from disassembled instructions
    pub fn generate_cfg(&self) -> ControlFlowGraph {
        let mut cfg = ControlFlowGraph::new();
        let mut block_map: HashMap<usize, usize> = HashMap::new(); // PC -> block index
        let mut current_block: Option<usize> = None;
        
        // First pass: identify basic block boundaries
        let mut block_starts: HashSet<usize> = HashSet::new();
        block_starts.insert(0); // Entry point
        
        // Add jump destinations as block starts
        for &dest in &self.jump_destinations {
            block_starts.insert(dest);
        }
        
        // Add instructions after jumps as block starts
        for instr in &self.instructions {
            if instr.opcode.is_jump() || instr.opcode.is_terminating() {
                if let Some(next_instr) = self.instruction_at(instr.pc + 1 + instr.opcode.operand_size()) {
                    block_starts.insert(next_instr.pc);
                }
            }
        }
        
        // Second pass: create basic blocks
        let mut sorted_starts: Vec<_> = block_starts.iter().cloned().collect();
        sorted_starts.sort();
        
        for (i, &start_pc) in sorted_starts.iter().enumerate() {
            let block_idx = cfg.add_block(BasicBlock::new(start_pc));
            block_map.insert(start_pc, block_idx);
            
            // Find end of this block
            let end_pc = if i + 1 < sorted_starts.len() {
                sorted_starts[i + 1]
            } else {
                self.bytecode.len()
            };
            
            // Add instructions to block
            for instr in self.instructions_in_range(start_pc, end_pc) {
                if let Some(block) = cfg.get_block_mut(block_idx) {
                    block.add_instruction(instr.clone());
                }
            }
        }
        
        // Third pass: connect blocks (edges)
        for block_idx in 0..cfg.blocks.len() {
            if let Some(block) = cfg.get_block(block_idx).cloned() {
                if let Some(last_instr) = block.instructions.last() {
                    match last_instr.opcode {
                        Opcode::JUMP => {
                            // Unconditional jump - get target from operand
                            if let Some(operand) = &last_instr.operand {
                                if operand.len() >= 4 {
                                    let target_pc = usize::from_be_bytes([
                                        0, 0, 0, operand[0]
                                    ]);
                                    if let Some(&target_block) = block_map.get(&target_pc) {
                                        cfg.get_block_mut(block_idx).unwrap().successors.push(target_block);
                                        cfg.get_block_mut(target_block).unwrap().predecessors.push(block_idx);
                                    }
                                }
                            }
                        }
                        Opcode::JUMPI => {
                            // Conditional jump - two successors
                            if let Some(operand) = &last_instr.operand {
                                if operand.len() >= 4 {
                                    let target_pc = usize::from_be_bytes([
                                        0, 0, 0, operand[0]
                                    ]);
                                    if let Some(&target_block) = block_map.get(&target_pc) {
                                        cfg.get_block_mut(block_idx).unwrap().successors.push(target_block);
                                        cfg.get_block_mut(target_block).unwrap().predecessors.push(block_idx);
                                    }
                                }
                            }
                            // Fall-through edge
                            let fallthrough_pc = last_instr.pc + 1 + last_instr.opcode.operand_size();
                            if let Some(&fallthrough_block) = block_map.get(&fallthrough_pc) {
                                cfg.get_block_mut(block_idx).unwrap().successors.push(fallthrough_block);
                                cfg.get_block_mut(fallthrough_block).unwrap().predecessors.push(block_idx);
                            }
                        }
                        _ if !last_instr.opcode.is_terminating() => {
                            // Fall-through for non-terminating instructions
                            let fallthrough_pc = last_instr.pc + 1 + last_instr.opcode.operand_size();
                            if let Some(&fallthrough_block) = block_map.get(&fallthrough_pc) {
                                cfg.get_block_mut(block_idx).unwrap().successors.push(fallthrough_block);
                                cfg.get_block_mut(fallthrough_block).unwrap().predecessors.push(block_idx);
                            }
                        }
                        _ => {
                            // Terminating instruction - no successors
                        }
                    }
                }
            }
        }
        
        cfg
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_opcode_parsing() {
        assert_eq!(Opcode::from_byte(0x00), Opcode::STOP);
        assert_eq!(Opcode::from_byte(0x60), Opcode::PUSH1);
        assert_eq!(Opcode::from_byte(0xff), Opcode::SELFDESTRUCT);
        assert_eq!(Opcode::from_byte(0x99), Opcode::UNKNOWN(0x99));
    }
    
    #[test]
    fn test_operand_size() {
        assert_eq!(Opcode::PUSH1.operand_size(), 1);
        assert_eq!(Opcode::PUSH32.operand_size(), 32);
        assert_eq!(Opcode::ADD.operand_size(), 0);
    }
    
    #[test]
    fn test_dangerous_opcodes() {
        assert!(Opcode::SELFDESTRUCT.is_dangerous());
        assert!(Opcode::DELEGATECALL.is_dangerous());
        assert!(Opcode::SSTORE.is_dangerous());
        assert!(!Opcode::ADD.is_dangerous());
    }
    
    #[test]
    fn test_simple_disassembly() {
        let bytecode = hex::decode("6060604052").unwrap();
        let disassembler = Disassembler::from_bytes(bytecode).unwrap();
        
        assert_eq!(disassembler.instructions().len(), 4);
        assert_eq!(disassembler.instructions()[0].opcode, Opcode::PUSH1);
        assert_eq!(disassembler.instructions()[0].operand, Some(vec![0x60]));
    }
    
    #[test]
    fn test_jump_detection() {
        let bytecode = hex::decode("5b600056").unwrap(); // JUMPDEST PUSH1 0x00 JUMP
        let disassembler = Disassembler::from_bytes(bytecode).unwrap();
        
        assert!(disassembler.jump_destinations().contains(&0));
        assert_eq!(disassembler.instructions()[2].opcode, Opcode::JUMP);
    }
    
    #[test]
    fn test_cfg_generation() {
        // Bytecode with conditional jump: PUSH1 0x00 DUP1 JUMPI
        let bytecode = hex::decode("60008057").unwrap();
        let disassembler = Disassembler::from_bytes(bytecode).unwrap();
        let cfg = disassembler.generate_cfg();
        
        assert!(!cfg.blocks.is_empty());
        assert!(cfg.entry_block.is_some());
    }
    
    #[test]
    fn test_pattern_detection() {
        // Bytecode with SELFDESTRUCT
        let bytecode = hex::decode("6000ff").unwrap();
        let disassembler = Disassembler::from_bytes(bytecode).unwrap();
        let matcher = PatternMatcher::new(disassembler);
        
        let patterns = matcher.detect_patterns();
        assert!(!patterns.is_empty());
    }
    
    #[test]
    fn test_decompiler() {
        let bytecode = hex::decode("6060604052").unwrap();
        let disassembler = Disassembler::from_bytes(bytecode).unwrap();
        let decompiler = Decompiler::new(disassembler);
        
        let signatures = decompiler.generate_signatures();
        assert!(!signatures.is_empty());
        
        let pseudo_solidity = decompiler.generate_pseudo_solidity();
        assert!(pseudo_solidity.contains("pragma solidity"));
        assert!(pseudo_solidity.contains("contract DecompiledContract"));
    }
    
    #[test]
    fn test_disassembler_from_hex() {
        let bytecode = "6060604052";
        let disassembler = Disassembler::from_hex(bytecode).unwrap();
        assert_eq!(disassembler.instructions().len(), 4);
    }
    
    #[test]
    fn test_cfg_reachability() {
        let bytecode = hex::decode("6060604052").unwrap();
        let disassembler = Disassembler::from_bytes(bytecode).unwrap();
        let cfg = disassembler.generate_cfg();
        
        let reachable = cfg.reachable_blocks();
        assert!(!reachable.is_empty());
    }
    
    #[test]
    fn test_risk_pattern_severity() {
        let bytecode = hex::decode("6000ff").unwrap();
        let disassembler = Disassembler::from_bytes(bytecode).unwrap();
        let matcher = PatternMatcher::new(disassembler);
        
        let patterns = matcher.detect_patterns();
        if let Some(pattern) = patterns.first() {
            assert!(!pattern.severity().is_empty());
            assert!(!pattern.description().is_empty());
        }
    }
    
    #[test]
    fn test_error_handling() {
        let result = Disassembler::from_hex("invalid hex");
        assert!(result.is_err());
        
        let result = Disassembler::from_bytes(vec![]);
        assert!(result.is_ok());
    }
}
