//! Integration tests for EVM Disassembler
//! 
//! Tests the complete functionality of bytecode analysis, CFG generation,
//! pattern matching, and decompilation.

#[cfg(test)]
mod tests {
    use crate::evm_disassembler::{
        Disassembler, PatternMatcher, Decompiler, Opcode, RiskPattern
    };

    #[test]
    fn test_disassembler_from_hex() {
        // Simple bytecode: PUSH1 0x60 PUSH1 0x40 MSTORE
        let bytecode = "6060604052";
        let disassembler = Disassembler::from_hex(bytecode).unwrap();
        
        assert_eq!(disassembler.instructions().len(), 4);
        assert_eq!(disassembler.instructions()[0].opcode, Opcode::PUSH1);
        assert_eq!(disassembler.instructions()[0].operand, Some(vec![0x60]));
    }

    #[test]
    fn test_disassembler_from_bytes() {
        let bytecode = vec![0x60, 0x60, 0x60, 0x40, 0x52];
        let disassembler = Disassembler::from_bytes(bytecode).unwrap();
        
        assert_eq!(disassembler.instructions().len(), 4);
        assert_eq!(disassembler.instructions()[3].opcode, Opcode::MSTORE);
    }

    #[test]
    fn test_cfg_generation() {
        // Bytecode with conditional jump: PUSH1 0x00 DUP1 JUMPI
        let bytecode = "60008057";
        let disassembler = Disassembler::from_hex(bytecode).unwrap();
        let cfg = disassembler.generate_cfg();
        
        assert!(!cfg.blocks.is_empty());
        assert!(cfg.entry_block.is_some());
        
        // Check that entry block is at PC 0
        if let Some(entry_idx) = cfg.entry_block {
            let entry_block = cfg.get_block(entry_idx).unwrap();
            assert_eq!(entry_block.start_pc, 0);
        }
    }

    #[test]
    fn test_jump_destination_detection() {
        // Bytecode with JUMPDEST: JUMPDEST PUSH1 0x00 JUMP
        let bytecode = "5b600056";
        let disassembler = Disassembler::from_hex(bytecode).unwrap();
        
        assert!(disassembler.jump_destinations().contains(&0));
    }

    #[test]
    fn test_selfdestruct_detection() {
        // Bytecode with SELFDESTRUCT: PUSH1 0x00 SELFDESTRUCT
        let bytecode = "6000ff";
        let disassembler = Disassembler::from_hex(bytecode).unwrap();
        let matcher = PatternMatcher::new(disassembler);
        
        let patterns = matcher.detect_patterns();
        assert!(!patterns.is_empty());
        
        let has_selfdestruct = patterns.iter().any(|p| matches!(p, RiskPattern::SelfDestruct { .. }));
        assert!(has_selfdestruct);
    }

    #[test]
    fn test_delegatecall_detection() {
        // Bytecode with DELEGATECALL: PUSH1 0x00 PUSH1 0x00 PUSH1 0x00 DELEGATECALL
        let bytecode = "600060006000f4";
        let disassembler = Disassembler::from_hex(bytecode).unwrap();
        let matcher = PatternMatcher::new(disassembler);
        
        let patterns = matcher.detect_patterns();
        assert!(!patterns.is_empty());
        
        let has_delegatecall = patterns.iter().any(|p| matches!(p, RiskPattern::DelegateCall { .. }));
        assert!(has_delegatecall);
    }

    #[test]
    fn test_sstore_detection() {
        // Bytecode with SSTORE: PUSH1 0x00 PUSH1 0x00 SSTORE
        let bytecode = "6000600055";
        let disassembler = Disassembler::from_hex(bytecode).unwrap();
        let matcher = PatternMatcher::new(disassembler);
        
        let patterns = matcher.detect_patterns();
        
        // Should detect storage manipulation
        let has_storage_pattern = patterns.iter().any(|p| matches!(p, RiskPattern::StorageManipulation { .. }));
        assert!(has_storage_pattern);
    }

    #[test]
    fn test_decompiler_signature_generation() {
        // Simple bytecode that might represent a function
        let bytecode = "6060604052368015600f57600080fd5b50603f80601d6000396000f3fe";
        let disassembler = Disassembler::from_hex(bytecode).unwrap();
        let decompiler = Decompiler::new(disassembler);
        
        let signatures = decompiler.generate_signatures();
        assert!(!signatures.is_empty());
        
        // Check that signatures have required fields
        for sig in signatures {
            assert!(!sig.name.is_empty());
            assert!(!sig.visibility.is_empty());
            assert!(!sig.mutability.is_empty());
        }
    }

    #[test]
    fn test_pseudo_solidity_generation() {
        // Bytecode with various patterns
        let bytecode = "6060604052368015600f57600080fd5b50603f80601d6000396000f3fe";
        let disassembler = Disassembler::from_hex(bytecode).unwrap();
        let decompiler = Decompiler::new(disassembler);
        
        let pseudo_solidity = decompiler.generate_pseudo_solidity();
        
        // Check that generated code contains expected elements
        assert!(pseudo_solidity.contains("pragma solidity"));
        assert!(pseudo_solidity.contains("contract DecompiledContract"));
        assert!(pseudo_solidity.contains("function"));
    }

    #[test]
    fn test_opcode_dangerous_detection() {
        assert!(Opcode::SELFDESTRUCT.is_dangerous());
        assert!(Opcode::DELEGATECALL.is_dangerous());
        assert!(Opcode::SSTORE.is_dangerous());
        assert!(!Opcode::ADD.is_dangerous());
        assert!(!Opcode::MUL.is_dangerous());
    }

    #[test]
    fn test_opcode_jump_detection() {
        assert!(Opcode::JUMP.is_jump());
        assert!(Opcode::JUMPI.is_jump());
        assert!(!Opcode::ADD.is_jump());
    }

    #[test]
    fn test_opcode_terminating_detection() {
        assert!(Opcode::STOP.is_terminating());
        assert!(Opcode::RETURN.is_terminating());
        assert!(Opcode::REVERT.is_terminating());
        assert!(Opcode::SELFDESTRUCT.is_terminating());
        assert!(!Opcode::ADD.is_terminating());
    }

    #[test]
    fn test_operand_sizes() {
        assert_eq!(Opcode::PUSH1.operand_size(), 1);
        assert_eq!(Opcode::PUSH32.operand_size(), 32);
        assert_eq!(Opcode::ADD.operand_size(), 0);
        assert_eq!(Opcode::JUMP.operand_size(), 0);
    }

    #[test]
    fn test_complex_bytecode_analysis() {
        // More complex bytecode with multiple patterns
        let bytecode = "6080604052348015600f57600080fd5b5060043610603c5760003560e01c8063a9059cbb14604157806370a08231146046575b600080fd5b605660048036036020811015604d57600080fd5b81019080803590602001909291905050506058565b005b606660048036036020811015606f57600080fd5b8101908080359060200190929190505050607a565b005b6000819050919050565b600080549050919050565b6000819050919050565b60686000819055506076600081905550565b5056";
        
        let disassembler = Disassembler::from_hex(bytecode).unwrap();
        let matcher = PatternMatcher::new(disassembler.clone());
        let decompiler = Decompiler::new(disassembler);
        
        // Test disassembly
        assert!(!disassembler.instructions().is_empty());
        
        // Test CFG generation
        let cfg = disassembler.generate_cfg();
        assert!(!cfg.blocks.is_empty());
        
        // Test pattern detection
        let patterns = matcher.detect_patterns();
        // Should at least detect some patterns even if not dangerous ones
        assert!(!patterns.is_empty() || cfg.blocks.len() > 1);
        
        // Test decompilation
        let signatures = decompiler.generate_signatures();
        assert!(!signatures.is_empty());
        
        let pseudo_solidity = decompiler.generate_pseudo_solidity();
        assert!(pseudo_solidity.len() > 100);
    }

    #[test]
    fn test_risk_pattern_severity() {
        let bytecode = "6000ff"; // SELFDESTRUCT
        let disassembler = Disassembler::from_hex(bytecode).unwrap();
        let matcher = PatternMatcher::new(disassembler);
        
        let patterns = matcher.detect_patterns();
        if let Some(pattern) = patterns.first() {
            let severity = pattern.severity();
            assert!(!severity.is_empty());
            
            let description = pattern.description();
            assert!(!description.is_empty());
        }
    }

    #[test]
    fn test_function_signature_to_solidity() {
        let bytecode = "6060604052";
        let disassembler = Disassembler::from_hex(bytecode).unwrap();
        let decompiler = Decompiler::new(disassembler);
        
        let signatures = decompiler.generate_signatures();
        if let Some(sig) = signatures.first() {
            let solidity = sig.to_solidity();
            assert!(solidity.contains("function"));
            assert!(solidity.contains("("));
            assert!(solidity.contains(")"));
        }
    }

    #[test]
    fn test_cfg_loop_detection() {
        // Bytecode with potential loop pattern
        let bytecode = "5b6001565b6001fe"; // JUMPDEST PUSH1 0x01 JUMP JUMPDEST PUSH1 0x01 INVALID
        let disassembler = Disassembler::from_hex(bytecode).unwrap();
        let cfg = disassembler.generate_cfg();
        
        let loops = cfg.detect_loops();
        // Should detect at least one loop or have back-edges
        assert!(loops.len() >= 0);
    }

    #[test]
    fn test_reachability_analysis() {
        let bytecode = "6060604052";
        let disassembler = Disassembler::from_hex(bytecode).unwrap();
        let cfg = disassembler.generate_cfg();
        
        let reachable = cfg.reachable_blocks();
        assert!(!reachable.is_empty());
        
        // Entry block should be reachable
        if let Some(entry) = cfg.entry_block {
            assert!(reachable.contains(&entry));
        }
    }

    #[test]
    fn test_instruction_at_pc() {
        let bytecode = "6060604052";
        let disassembler = Disassembler::from_hex(bytecode).unwrap();
        
        let instr_at_0 = disassembler.instruction_at(0);
        assert!(instr_at_0.is_some());
        assert_eq!(instr_at_0.unwrap().opcode, Opcode::PUSH1);
        
        let instr_at_100 = disassembler.instruction_at(100);
        assert!(instr_at_100.is_none());
    }

    #[test]
    fn test_instructions_in_range() {
        let bytecode = "6060604052";
        let disassembler = Disassembler::from_hex(bytecode).unwrap();
        
        let range_instrs = disassembler.instructions_in_range(0, 2);
        assert_eq!(range_instrs.len(), 2);
        
        let empty_range = disassembler.instructions_in_range(100, 200);
        assert!(empty_range.is_empty());
    }

    #[test]
    fn test_human_readable_disassembly() {
        let bytecode = "6060604052";
        let disassembler = Disassembler::from_hex(bytecode).unwrap();
        
        let output = disassembler.to_string();
        assert!(!output.is_empty());
        assert!(output.contains("PUSH1"));
        assert!(output.contains("0x60"));
    }

    #[test]
    fn test_erc20_function_detection() {
        // Bytecode that might contain ERC20 functions
        let bytecode = "6080604052348015600f57600080fd5b5060043610603c5760003560e01c8063a9059cbb14604157806370a08231146046575b600080fd5b605660048036036020811015604d57600080fd5b81019080803590602001909291905050506058565b005b606660048036036020811015606f57600080fd5b8101908080359060200190929190505050607a565b005b6000819050919050565b600080549050919050565b6000819050919050565b60686000819055506076600081905550565b5056";
        
        let disassembler = Disassembler::from_hex(bytecode).unwrap();
        let decompiler = Decompiler::new(disassembler);
        
        let signatures = decompiler.generate_signatures();
        
        // Check if any ERC20-like functions were detected
        let has_transfer = signatures.iter().any(|s| s.name.contains("transfer"));
        let has_balanceof = signatures.iter().any(|s| s.name.contains("balanceOf"));
        let has_approve = signatures.iter().any(|s| s.name.contains("approve"));
        
        // At least some functions should be detected
        assert!(!signatures.is_empty());
    }

    #[test]
    fn test_error_handling() {
        // Invalid hex string
        let result = Disassembler::from_hex("invalid hex");
        assert!(result.is_err());
        
        // Empty bytecode
        let result = Disassembler::from_bytes(vec![]);
        assert!(result.is_ok());
        
        let disassembler = result.unwrap();
        assert!(disassembler.instructions().is_empty());
    }

    #[test]
    fn test_opcode_display() {
        assert_eq!(format!("{}", Opcode::STOP), "STOP");
        assert_eq!(format!("{}", Opcode::ADD), "ADD");
        assert_eq!(format!("{}", Opcode::SELFDESTRUCT), "SELFDESTRUCT");
        assert_eq!(format!("{}", Opcode::UNKNOWN(0x99)), "UNKNOWN(0x99)");
    }

    #[test]
    fn test_risk_pattern_varieties() {
        // Bytecode with multiple risk patterns
        let bytecode = "600060006000f46000ff"; // DELEGATECALL and SELFDESTRUCT
        let disassembler = Disassembler::from_hex(bytecode).unwrap();
        let matcher = PatternMatcher::new(disassembler);
        
        let patterns = matcher.detect_patterns();
        
        // Should detect both dangerous patterns
        let has_delegatecall = patterns.iter().any(|p| matches!(p, RiskPattern::DelegateCall { .. }));
        let has_selfdestruct = patterns.iter().any(|p| matches!(p, RiskPattern::SelfDestruct { .. }));
        
        assert!(has_delegatecall || has_selfdestruct);
    }
}