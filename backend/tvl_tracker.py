"""
TVL Tracker and Anomaly Detection Module
Tracks historical Total Value Locked (TVL) and detects sudden collateral withdrawals
from lending pool smart contracts.
"""

import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import statistics


class AnomalyType(Enum):
    """Types of TVL anomalies"""
    SUDDEN_DROP = "sudden_drop"
    GRADUAL_DECLINE = "gradual_decline"
    SPIKE_WITHDRAWAL = "spike_withdrawal"
    COLLATERAL_DRAIN = "collateral_drain"
    UNUSUAL_PATTERN = "unusual_pattern"


@dataclass
class TVLSnapshot:
    """Represents a TVL snapshot at a point in time"""
    pool_address: str
    timestamp: datetime
    total_value_locked: float
    collateral_amount: float
    borrowed_amount: float
    liquidity_tokens: float
    token_prices: Dict[str, float]
    block_number: Optional[int] = None


@dataclass
class TVLAnomaly:
    """Represents a detected TVL anomaly"""
    pool_address: str
    anomaly_type: AnomalyType
    severity: str  # "critical", "high", "medium", "low"
    timestamp: datetime
    previous_tvl: float
    current_tvl: float
    percentage_change: float
    description: str
    affected_collateral: Optional[str] = None


class TVLDatabase:
    """SQLite database for storing historical TVL data"""
    
    def __init__(self, db_path: str = "tvl_history.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._create_tables()
    
    def _create_tables(self):
        """Create database tables"""
        cursor = self.conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tvl_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pool_address TEXT NOT NULL,
                timestamp DATETIME NOT NULL,
                total_value_locked REAL NOT NULL,
                collateral_amount REAL NOT NULL,
                borrowed_amount REAL NOT NULL,
                liquidity_tokens REAL NOT NULL,
                token_prices TEXT NOT NULL,
                block_number INTEGER,
                UNIQUE(pool_address, timestamp, block_number)
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_pool_address 
            ON tvl_snapshots(pool_address)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp 
            ON tvl_snapshots(timestamp)
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pool_address TEXT NOT NULL,
                anomaly_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                timestamp DATETIME NOT NULL,
                previous_tvl REAL NOT NULL,
                current_tvl REAL NOT NULL,
                percentage_change REAL NOT NULL,
                description TEXT NOT NULL,
                affected_collateral TEXT
            )
        """)
        
        self.conn.commit()
    
    def store_snapshot(self, snapshot: TVLSnapshot):
        """Store a TVL snapshot"""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO tvl_snapshots 
            (pool_address, timestamp, total_value_locked, collateral_amount, 
             borrowed_amount, liquidity_tokens, token_prices, block_number)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            snapshot.pool_address,
            snapshot.timestamp.isoformat(),
            snapshot.total_value_locked,
            snapshot.collateral_amount,
            snapshot.borrowed_amount,
            snapshot.liquidity_tokens,
            json.dumps(snapshot.token_prices),
            snapshot.block_number
        ))
        self.conn.commit()
    
    def store_anomaly(self, anomaly: TVLAnomaly):
        """Store a detected anomaly"""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO anomalies 
            (pool_address, anomaly_type, severity, timestamp, previous_tvl, 
             current_tvl, percentage_change, description, affected_collateral)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            anomaly.pool_address,
            anomaly.anomaly_type.value,
            anomaly.severity,
            anomaly.timestamp.isoformat(),
            anomaly.previous_tvl,
            anomaly.current_tvl,
            anomaly.percentage_change,
            anomaly.description,
            anomaly.affected_collateral
        ))
        self.conn.commit()
    
    def get_snapshots(self, pool_address: str, 
                     start_time: Optional[datetime] = None,
                     end_time: Optional[datetime] = None,
                     limit: int = 1000) -> List[TVLSnapshot]:
        """Retrieve TVL snapshots for a pool"""
        cursor = self.conn.cursor()
        
        query = "SELECT * FROM tvl_snapshots WHERE pool_address = ?"
        params = [pool_address]
        
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time.isoformat())
        
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time.isoformat())
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        snapshots = []
        for row in rows:
            snapshots.append(TVLSnapshot(
                pool_address=row[1],
                timestamp=datetime.fromisoformat(row[2]),
                total_value_locked=row[3],
                collateral_amount=row[4],
                borrowed_amount=row[5],
                liquidity_tokens=row[6],
                token_prices=json.loads(row[7]),
                block_number=row[8]
            ))
        
        return snapshots
    
    def get_anomalies(self, pool_address: Optional[str] = None,
                     severity: Optional[str] = None,
                     limit: int = 100) -> List[TVLAnomaly]:
        """Retrieve detected anomalies"""
        cursor = self.conn.cursor()
        
        query = "SELECT * FROM anomalies WHERE 1=1"
        params = []
        
        if pool_address:
            query += " AND pool_address = ?"
            params.append(pool_address)
        
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        anomalies = []
        for row in rows:
            anomalies.append(TVLAnomaly(
                pool_address=row[1],
                anomaly_type=AnomalyType(row[2]),
                severity=row[3],
                timestamp=datetime.fromisoformat(row[4]),
                previous_tvl=row[5],
                current_tvl=row[6],
                percentage_change=row[7],
                description=row[8],
                affected_collateral=row[9]
            ))
        
        return anomalies
    
    def close(self):
        """Close database connection"""
        self.conn.close()


class AnomalyDetector:
    """Detects anomalies in TVL data"""
    
    def __init__(self, threshold_percent: float = 20.0):
        self.threshold_percent = threshold_percent
    
    def detect_sudden_drop(self, current_tvl: float, 
                          historical_tvl: List[float]) -> Optional[TVLAnomaly]:
        """
        Detect sudden TVL drops
        
        Args:
            current_tvl: Current TVL value
            historical_tvl: List of historical TVL values
            
        Returns:
            TVLAnomaly if anomaly detected, None otherwise
        """
        if not historical_tvl:
            return None
        
        avg_tvl = statistics.mean(historical_tvl)
        if avg_tvl == 0:
            return None
        
        change_percent = ((current_tvl - avg_tvl) / avg_tvl) * 100
        
        if change_percent < -self.threshold_percent:
            return TVLAnomaly(
                pool_address="",  # To be filled by caller
                anomaly_type=AnomalyType.SUDDEN_DROP,
                severity="critical" if change_percent < -50 else "high",
                timestamp=datetime.now(),
                previous_tvl=avg_tvl,
                current_tvl=current_tvl,
                percentage_change=change_percent,
                description=f"TVL dropped by {abs(change_percent):.2f}% from historical average"
            )
        
        return None
    
    def detect_spike_withdrawal(self, collateral_amount: float,
                               borrowed_amount: float,
                               historical_collateral: List[float]) -> Optional[TVLAnomaly]:
        """
        Detect sudden collateral withdrawal spikes
        
        Args:
            collateral_amount: Current collateral amount
            borrowed_amount: Current borrowed amount
            historical_collateral: List of historical collateral values
            
        Returns:
            TVLAnomaly if anomaly detected, None otherwise
        """
        if not historical_collateral:
            return None
        
        avg_collateral = statistics.mean(historical_collateral)
        if avg_collateral == 0:
            return None
        
        change_percent = ((collateral_amount - avg_collateral) / avg_collateral) * 100
        
        # Check if collateral dropped significantly while borrowing remained stable
        if change_percent < -self.threshold_percent:
            return TVLAnomaly(
                pool_address="",
                anomaly_type=AnomalyType.SPIKE_WITHDRAWAL,
                severity="high" if change_percent < -40 else "medium",
                timestamp=datetime.now(),
                previous_tvl=avg_collateral,
                current_tvl=collateral_amount,
                percentage_change=change_percent,
                description=f"Collateral withdrawal spike: {abs(change_percent):.2f}% decrease"
            )
        
        return None
    
    def detect_collateral_drain(self, current_tvl: float,
                               previous_tvl: float,
                               time_delta_minutes: int) -> Optional[TVLAnomaly]:
        """
        Detect rapid collateral drain over short time period
        
        Args:
            current_tvl: Current TVL
            previous_tvl: Previous TVL
            time_delta_minutes: Time difference in minutes
            
        Returns:
            TVLAnomaly if anomaly detected, None otherwise
        """
        if previous_tvl == 0:
            return None
        
        change_percent = ((current_tvl - previous_tvl) / previous_tvl) * 100
        
        # More severe if it happens quickly
        severity_threshold = 30 if time_delta_minutes < 60 else 20
        
        if change_percent < -severity_threshold:
            return TVLAnomaly(
                pool_address="",
                anomaly_type=AnomalyType.COLLATERAL_DRAIN,
                severity="critical" if change_percent < -50 else "high",
                timestamp=datetime.now(),
                previous_tvl=previous_tvl,
                current_tvl=current_tvl,
                percentage_change=change_percent,
                description=f"Rapid collateral drain: {abs(change_percent):.2f}% in {time_delta_minutes} minutes"
            )
        
        return None
    
    def detect_gradual_decline(self, historical_tvl: List[float],
                              window_size: int = 10) -> Optional[TVLAnomaly]:
        """
        Detect gradual but consistent TVL decline
        
        Args:
            historical_tvl: List of historical TVL values (oldest to newest)
            window_size: Size of window to analyze
            
        Returns:
            TVLAnomaly if anomaly detected, None otherwise
        """
        if len(historical_tvl) < window_size:
            return None
        
        recent_window = historical_tvl[-window_size:]
        older_window = historical_tvl[-(window_size * 2):-window_size]
        
        recent_avg = statistics.mean(recent_window)
        older_avg = statistics.mean(older_window)
        
        if older_avg == 0:
            return None
        
        decline_percent = ((recent_avg - older_avg) / older_avg) * 100
        
        # Check if consistently declining
        is_consistent = all(
            recent_window[i] <= recent_window[i-1] 
            for i in range(1, len(recent_window))
        )
        
        if decline_percent < -15 and is_consistent:
            return TVLAnomaly(
                pool_address="",
                anomaly_type=AnomalyType.GRADUAL_DECLINE,
                severity="medium",
                timestamp=datetime.now(),
                previous_tvl=older_avg,
                current_tvl=recent_avg,
                percentage_change=decline_percent,
                description=f"Gradual TVL decline: {abs(decline_percent):.2f}% over {window_size} periods"
            )
        
        return None


class TVLTracker:
    """Main TVL tracking and anomaly detection system"""
    
    def __init__(self, db_path: str = "tvl_history.db"):
        self.db = TVLDatabase(db_path)
        self.detector = AnomalyDetector(threshold_percent=20.0)
    
    def record_snapshot(self, snapshot: TVLSnapshot) -> List[TVLAnomaly]:
        """
        Record a TVL snapshot and detect anomalies
        
        Args:
            snapshot: TVLSnapshot to record
            
        Returns:
            List of detected anomalies
        """
        # Store snapshot
        self.db.store_snapshot(snapshot)
        
        # Get historical data for anomaly detection
        historical_snapshots = self.db.get_snapshots(
            snapshot.pool_address,
            start_time=datetime.now() - timedelta(days=7),
            limit=100
        )
        
        anomalies = []
        
        if len(historical_snapshots) >= 2:
            # Extract historical TVL values
            historical_tvl = [s.total_value_locked for s in historical_snapshots[1:]]
            historical_collateral = [s.collateral_amount for s in historical_snapshots[1:]]
            
            # Detect sudden drop
            drop_anomaly = self.detector.detect_sudden_drop(
                snapshot.total_value_locked,
                historical_tvl
            )
            if drop_anomaly:
                drop_anomaly.pool_address = snapshot.pool_address
                anomalies.append(drop_anomaly)
            
            # Detect spike withdrawal
            withdrawal_anomaly = self.detector.detect_spike_withdrawal(
                snapshot.collateral_amount,
                snapshot.borrowed_amount,
                historical_collateral
            )
            if withdrawal_anomaly:
                withdrawal_anomaly.pool_address = snapshot.pool_address
                anomalies.append(withdrawal_anomaly)
            
            # Detect rapid drain
            if len(historical_snapshots) >= 1:
                prev_snapshot = historical_snapshots[0]
                time_delta = (snapshot.timestamp - prev_snapshot.timestamp).total_seconds() / 60
                drain_anomaly = self.detector.detect_collateral_drain(
                    snapshot.total_value_locked,
                    prev_snapshot.total_value_locked,
                    int(time_delta)
                )
                if drain_anomaly:
                    drain_anomaly.pool_address = snapshot.pool_address
                    anomalies.append(drain_anomaly)
            
            # Detect gradual decline
            decline_anomaly = self.detector.detect_gradual_decline(
                list(reversed(historical_tvl))
            )
            if decline_anomaly:
                decline_anomaly.pool_address = snapshot.pool_address
                anomalies.append(decline_anomaly)
        
        # Store detected anomalies
        for anomaly in anomalies:
            self.db.store_anomaly(anomaly)
        
        return anomalies
    
    def get_pool_history(self, pool_address: str, 
                        days: int = 30) -> List[TVLSnapshot]:
        """
        Get TVL history for a pool
        
        Args:
            pool_address: Pool contract address
            days: Number of days of history to retrieve
            
        Returns:
            List of TVL snapshots
        """
        start_time = datetime.now() - timedelta(days=days)
        return self.db.get_snapshots(pool_address, start_time=start_time)
    
    def get_pool_anomalies(self, pool_address: str) -> List[TVLAnomaly]:
        """
        Get anomalies for a specific pool
        
        Args:
            pool_address: Pool contract address
            
        Returns:
            List of detected anomalies
        """
        return self.db.get_anomalies(pool_address=pool_address)
    
    def get_risk_score(self, pool_address: str) -> float:
        """
        Calculate risk score based on TVL anomalies
        
        Args:
            pool_address: Pool contract address
            
        Returns:
            Risk score between 0 (safe) and 1 (critical)
        """
        anomalies = self.get_pool_anomalies(pool_address)
        
        if not anomalies:
            return 0.0
        
        # Weight anomalies by severity
        severity_weights = {
            "critical": 0.5,
            "high": 0.3,
            "medium": 0.15,
            "low": 0.05
        }
        
        score = 0.0
        for anomaly in anomalies:
            weight = severity_weights.get(anomaly.severity, 0.1)
            score += weight
        
        # Normalize to 0-1 range
        return min(score, 1.0)
    
    def close(self):
        """Close database connection"""
        self.db.close()


def create_mock_snapshot(pool_address: str, tvl: float) -> TVLSnapshot:
    """Create a mock TVL snapshot for testing"""
    return TVLSnapshot(
        pool_address=pool_address,
        timestamp=datetime.now(),
        total_value_locked=tvl,
        collateral_amount=tvl * 0.8,
        borrowed_amount=tvl * 0.3,
        liquidity_tokens=tvl * 0.5,
        token_prices={"USDC": 1.0, "ETH": 2000.0}
    )


if __name__ == "__main__":
    # Example usage
    tracker = TVLTracker()
    
    # Record some snapshots
    pool_address = "0x1234567890abcdef"
    
    for i in range(10):
        snapshot = create_mock_snapshot(pool_address, 1000000 - (i * 50000))
        anomalies = tracker.record_snapshot(snapshot)
        if anomalies:
            print(f"Anomalies detected: {len(anomalies)}")
            for anomaly in anomalies:
                print(f"  - {anomaly.anomaly_type.value}: {anomaly.description}")
    
    # Get risk score
    risk_score = tracker.get_risk_score(pool_address)
    print(f"Risk score for pool: {risk_score}")
    
    tracker.close()
