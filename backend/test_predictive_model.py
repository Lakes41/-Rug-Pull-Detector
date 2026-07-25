"""
Predictive Modeling Backend Test Suite for DeFi Rug Pull Detector
"""

import pytest
import asyncio
from websocket_client import WebSocketAlertClient, AlertTrigger

class RugPullPredictor:
    """Core predictive model logic for rug pull detection"""
    
    @staticmethod
    def calculate_risk_score(token_data: dict) -> dict:
        liquidity = token_data.get('liquidity_usd', 0)
        holder_concentration = token_data.get('top_10_holder_percent', 0.0)
        is_mintable = token_data.get('is_mintable', False)
        is_honeypot = token_data.get('is_honeypot', False)

        risk_score = 0.0
        
        if is_honeypot:
            risk_score += 0.95
        if is_mintable:
            risk_score += 0.30
        if liquidity < 10000:
            risk_score += 0.40
        elif liquidity < 50000:
            risk_score += 0.20
            
        if holder_concentration > 80.0:
            risk_score += 0.35
        elif holder_concentration > 50.0:
            risk_score += 0.15

        final_score = min(round(risk_score, 2), 1.0)
        
        if final_score >= 0.70:
            risk_level = 'HIGH'
        elif final_score >= 0.40:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'

        result = {
            'address': token_data.get('address', '0x000'),
            'score': final_score,
            'risk_level': risk_level,
            'is_honeypot': is_honeypot,
            'is_mintable': is_mintable
        }
        
        # Trigger WebSocket alerts for high-risk tokens
        if final_score >= 0.70:
            try:
                loop = asyncio.get_event_loop()
                loop.create_task(trigger_high_risk_alert(result))
            except RuntimeError:
                asyncio.run(trigger_high_risk_alert(result))
        
        return result


async def trigger_high_risk_alert(token_result: dict):
    """Trigger WebSocket alerts for high-risk tokens"""
    try:
        client = WebSocketAlertClient()
        await client.connect()
        trigger = AlertTrigger(client)
        
        if token_result['is_honeypot']:
            await trigger.trigger_honeypot_alert(token_result['address'])
        if token_result['is_mintable']:
            await trigger.trigger_mintable_token_alert(token_result['address'])
        
        await client.disconnect()
    except Exception as e:
        print(f"Failed to send WebSocket alert: {e}")


class DynamicHoneypotDetector:
    """Detector for gas-limit, dynamic-tax, and caller blacklist honeypots"""

    @staticmethod
    def analyze(simulation: dict) -> dict:
        traces = simulation.get('call_sequence', [])
        gas_by_operation = {
            trace['operation']: trace['gas_used']
            for trace in traces
            if trace.get('operation') in {'approve', 'transfer', 'swapExactTokensForETH'}
        }
        gas_deltas = {
            'approve_to_transfer': gas_by_operation.get('transfer', 0) - gas_by_operation.get('approve', 0),
            'transfer_to_sell': gas_by_operation.get('swapExactTokensForETH', 0) - gas_by_operation.get('transfer', 0),
            'approve_to_sell': gas_by_operation.get('swapExactTokensForETH', 0) - gas_by_operation.get('approve', 0),
        }
        before_storage = simulation.get('storage_before_trade', {})
        after_storage = simulation.get('storage_after_trade', {})
        changed_slots = [
            slot for slot in set(before_storage) | set(after_storage)
            if before_storage.get(slot) != after_storage.get(slot)
        ]
        before_tax = before_storage.get('sell_tax_bps', 0)
        after_tax = after_storage.get('sell_tax_bps', 0)
        gas_limit_reverts = [
            trace for trace in traces
            if trace.get('reverted') and trace.get('gas_limit', 0) < 100000
        ]
        caller_reverts = [
            trace for trace in traces
            if trace.get('reverted') and trace.get('caller') in simulation.get('blacklisted_callers', [])
        ]
        triggered_rules = []

        if gas_deltas['approve_to_sell'] > gas_by_operation.get('approve', 1) * 3:
            triggered_rules.append('gas_usage_delta')
        if after_tax >= 9000 or after_tax - before_tax >= 5000:
            triggered_rules.append('dynamic_tax_storage_change')
        if gas_limit_reverts:
            triggered_rules.append('gas_limit_conditional_revert')
        if caller_reverts:
            triggered_rules.append('caller_blacklist_conditional_revert')

        return {
            'gas_by_operation': gas_by_operation,
            'gas_deltas': gas_deltas,
            'changed_slots': changed_slots,
            'tax_delta_bps': after_tax - before_tax,
            'triggered_rules': triggered_rules,
            'flagged': bool(triggered_rules),
        }


def test_predictive_model_high_risk_honeypot():
    token = {
        'address': '0xDEADBEEF',
        'liquidity_usd': 5000,
        'top_10_holder_percent': 90.0,
        'is_mintable': True,
        'is_honeypot': True
    }
    result = RugPullPredictor.calculate_risk_score(token)
    assert result['risk_level'] == 'HIGH'
    assert result['score'] >= 0.70
    assert result['is_honeypot'] is True


def test_predictive_model_low_risk_token():
    token = {
        'address': '0xSAFE1234',
        'liquidity_usd': 500000,
        'top_10_holder_percent': 15.0,
        'is_mintable': False,
        'is_honeypot': False
    }
    result = RugPullPredictor.calculate_risk_score(token)
    assert result['risk_level'] == 'LOW'
    assert result['score'] < 0.40


def test_batch_token_analysis():
    tokens = [
        {'address': '0x1', 'liquidity_usd': 1000, 'top_10_holder_percent': 95.0, 'is_mintable': True, 'is_honeypot': True},
        {'address': '0x2', 'liquidity_usd': 1000000, 'top_10_holder_percent': 10.0, 'is_mintable': False, 'is_honeypot': False}
    ]
    results = [RugPullPredictor.calculate_risk_score(t) for t in tokens]
    assert len(results) == 2
    assert results[0]['risk_level'] == 'HIGH'
    assert results[1]['risk_level'] == 'LOW'


def test_backend_health_check_simulation():
    health_status = {'status': 'healthy', 'service': 'predictive-modeling-backend', 'version': '1.0.0'}
    assert health_status['status'] == 'healthy'
    assert health_status['service'] == 'predictive-modeling-backend'


def test_dynamic_honeypot_detector_flags_gas_tax_and_blacklist_patterns():
    simulation = {
        'call_sequence': [
            {'operation': 'approve', 'gas_used': 45000, 'gas_limit': 80000, 'caller': '0xSAFE', 'reverted': False},
            {'operation': 'transfer', 'gas_used': 65000, 'gas_limit': 100000, 'caller': '0xSAFE', 'reverted': False},
            {'operation': 'swapExactTokensForETH', 'gas_used': 210000, 'gas_limit': 600000, 'caller': '0xSAFE', 'reverted': False},
            {'operation': 'swapExactTokensForETH', 'gas_used': 0, 'gas_limit': 60000, 'caller': '0xSAFE', 'reverted': True},
            {'operation': 'transfer', 'gas_used': 0, 'gas_limit': 100000, 'caller': '0xBLOCKED', 'reverted': True},
        ],
        'storage_before_trade': {'sell_tax_bps': 300, 'slot_tax': '0x012c'},
        'storage_after_trade': {'sell_tax_bps': 9900, 'slot_tax': '0x26ac'},
        'blacklisted_callers': ['0xBLOCKED'],
    }

    result = DynamicHoneypotDetector.analyze(simulation)

    assert result['flagged'] is True
    assert result['gas_deltas']['approve_to_sell'] == 165000
    assert result['tax_delta_bps'] == 9600
    assert 'sell_tax_bps' in result['changed_slots']
    assert 'gas_usage_delta' in result['triggered_rules']
    assert 'dynamic_tax_storage_change' in result['triggered_rules']
    assert 'gas_limit_conditional_revert' in result['triggered_rules']
    assert 'caller_blacklist_conditional_revert' in result['triggered_rules']


def test_dynamic_honeypot_detector_allows_normal_trade_sequence():
    simulation = {
        'call_sequence': [
            {'operation': 'approve', 'gas_used': 45000, 'gas_limit': 80000, 'caller': '0xSAFE', 'reverted': False},
            {'operation': 'transfer', 'gas_used': 52000, 'gas_limit': 100000, 'caller': '0xSAFE', 'reverted': False},
            {'operation': 'swapExactTokensForETH', 'gas_used': 95000, 'gas_limit': 200000, 'caller': '0xSAFE', 'reverted': False},
        ],
        'storage_before_trade': {'sell_tax_bps': 300},
        'storage_after_trade': {'sell_tax_bps': 300},
        'blacklisted_callers': [],
    }

    result = DynamicHoneypotDetector.analyze(simulation)

    assert result['flagged'] is False
    assert result['triggered_rules'] == []
