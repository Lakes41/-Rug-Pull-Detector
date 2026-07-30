"""
Oracle vs On-Chain Mint/Burn Monitoring Module
Maps and monitors off-chain oracle updates vs on-chain mint/burn functions
to detect infinite minting vulnerabilities in tokenized assets.
"""

import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import statistics


class MintBurnEventType(Enum):
    """Types of mint/burn events"""
    MINT = "mint"
    BURN = "burn"
    TRANSFER = "transfer"


class OracleUpdateType(Enum):
    """Types of oracle updates"""
    PRICE_UPDATE = "price_update"
    COLLATERAL_UPDATE = "collateral_update"
    ASSET_VALUE_UPDATE = "asset_value_update"


@dataclass
class MintBurnEvent:
    """Represents an on-chain mint or burn event"""
    token_address: str
    event_type: MintBurnEventType
    amount: float
    timestamp: datetime
    transaction_hash: str
    from_address: Optional[str] = None
    to_address: Optional[str] = None
    block_number: Optional[int] = None
    total_supply_after: Optional[float] = None


@dataclass
class OracleUpdate:
    """Represents an off-chain oracle update"""
    asset_id: str
    update_type: OracleUpdateType
    old_value: float
    new_value: float
    timestamp: datetime
    oracle_address: str
    signature: Optional[str] = None
    update_source: Optional[str] = None


@dataclass
class MintBurnAnomaly:
    """Represents a detected mint/burn anomaly"""
    token_address: str
    anomaly_type: str
    severity: str
    timestamp: datetime
    description: str
    mint_events: List[MintBurnEvent] = field(default_factory=list)
    oracle_updates: List[OracleUpdate] = field(default_factory=list)
    total_minted: float = 0.0
    total_burned: float = 0.0
    supply_change_percent: float = 0.0


class OracleMintDatabase:
    """Database for storing oracle updates and mint/burn events"""
    
    def __init__(self, db_path: str = "oracle_mint_history.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._create_tables()
    
    def _create_tables(self):
        """Create database tables"""
        cursor = self.conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS mint_burn_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_address TEXT NOT NULL,
                event_type TEXT NOT NULL,
                amount REAL NOT NULL,
                timestamp DATETIME NOT NULL,
                transaction_hash TEXT NOT NULL,
                from_address TEXT,
                to_address TEXT,
                block_number INTEGER,
                total_supply_after REAL,
                UNIQUE(transaction_hash, token_address)
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_token_address 
            ON mint_burn_events(token_address)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_event_timestamp 
            ON mint_burn_events(timestamp)
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS oracle_updates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id TEXT NOT NULL,
                update_type TEXT NOT NULL,
                old_value REAL NOT NULL,
                new_value REAL NOT NULL,
                timestamp DATETIME NOT NULL,
                oracle_address TEXT NOT NULL,
                signature TEXT,
                update_source TEXT
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_asset_id 
            ON oracle_updates(asset_id)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_oracle_timestamp 
            ON oracle_updates(timestamp)
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS mint_burn_anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_address TEXT NOT NULL,
                anomaly_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                timestamp DATETIME NOT NULL,
                description TEXT NOT NULL,
                total_minted REAL,
                total_burned REAL,
                supply_change_percent REAL
            )
        """)
        
        self.conn.commit()
    
    def store_mint_burn_event(self, event: MintBurnEvent):
        """Store a mint/burn event"""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO mint_burn_events 
            (token_address, event_type, amount, timestamp, transaction_hash,
             from_address, to_address, block_number, total_supply_after)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.token_address,
            event.event_type.value,
            event.amount,
            event.timestamp.isoformat(),
            event.transaction_hash,
            event.from_address,
            event.to_address,
            event.block_number,
            event.total_supply_after
        ))
        self.conn.commit()
    
    def store_oracle_update(self, update: OracleUpdate):
        """Store an oracle update"""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO oracle_updates 
            (asset_id, update_type, old_value, new_value, timestamp,
             oracle_address, signature, update_source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            update.asset_id,
            update.update_type.value,
            update.old_value,
            update.new_value,
            update.timestamp.isoformat(),
            update.oracle_address,
            update.signature,
            update.update_source
        ))
        self.conn.commit()
    
    def store_anomaly(self, anomaly: MintBurnAnomaly):
        """Store a detected anomaly"""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO mint_burn_anomalies 
            (token_address, anomaly_type, severity, timestamp, description,
             total_minted, total_burned, supply_change_percent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            anomaly.token_address,
            anomaly.anomaly_type,
            anomaly.severity,
            anomaly.timestamp.isoformat(),
            anomaly.description,
            anomaly.total_minted,
            anomaly.total_burned,
            anomaly.supply_change_percent
        ))
        self.conn.commit()
    
    def get_mint_burn_events(self, token_address: str,
                            start_time: Optional[datetime] = None,
                            end_time: Optional[datetime] = None,
                            limit: int = 1000) -> List[MintBurnEvent]:
        """Retrieve mint/burn events for a token"""
        cursor = self.conn.cursor()
        
        query = "SELECT * FROM mint_burn_events WHERE token_address = ?"
        params = [token_address]
        
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
        
        events = []
        for row in rows:
            events.append(MintBurnEvent(
                token_address=row[1],
                event_type=MintBurnEventType(row[2]),
                amount=row[3],
                timestamp=datetime.fromisoformat(row[4]),
                transaction_hash=row[5],
                from_address=row[6],
                to_address=row[7],
                block_number=row[8],
                total_supply_after=row[9]
            ))
        
        return events
    
    def get_oracle_updates(self, asset_id: str,
                          start_time: Optional[datetime] = None,
                          end_time: Optional[datetime] = None,
                          limit: int = 1000) -> List[OracleUpdate]:
        """Retrieve oracle updates for an asset"""
        cursor = self.conn.cursor()
        
        query = "SELECT * FROM oracle_updates WHERE asset_id = ?"
        params = [asset_id]
        
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
        
        updates = []
        for row in rows:
            updates.append(OracleUpdate(
                asset_id=row[1],
                update_type=OracleUpdateType(row[2]),
                old_value=row[3],
                new_value=row[4],
                timestamp=datetime.fromisoformat(row[5]),
                oracle_address=row[6],
                signature=row[7],
                update_source=row[8]
            ))
        
        return updates
    
    def get_anomalies(self, token_address: Optional[str] = None,
                     severity: Optional[str] = None,
                     limit: int = 100) -> List[MintBurnAnomaly]:
        """Retrieve detected anomalies"""
        cursor = self.conn.cursor()
        
        query = "SELECT * FROM mint_burn_anomalies WHERE 1=1"
        params = []
        
        if token_address:
            query += " AND token_address = ?"
            params.append(token_address)
        
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        anomalies = []
        for row in rows:
            anomalies.append(MintBurnAnomaly(
                token_address=row[1],
                anomaly_type=row[2],
                severity=row[3],
                timestamp=datetime.fromisoformat(row[4]),
                description=row[5],
                total_minted=row[6],
                total_burned=row[7],
                supply_change_percent=row[8]
            ))
        
        return anomalies
    
    def close(self):
        """Close database connection"""
        self.conn.close()


class InfiniteMintDetector:
    """Detects infinite minting vulnerabilities"""
    
    def __init__(self, supply_change_threshold: float = 50.0):
        self.supply_change_threshold = supply_change_threshold
    
    def detect_rapid_minting(self, events: List[MintBurnEvent],
                            time_window_minutes: int = 60) -> Optional[MintBurnAnomaly]:
        """
        Detect rapid minting within a short time window
        
        Args:
            events: List of mint/burn events
            time_window_minutes: Time window to analyze
            
        Returns:
            MintBurnAnomaly if detected, None otherwise
        """
        if not events:
            return None
        
        # Filter for mint events
        mint_events = [e for e in events if e.event_type == MintBurnEventType.MINT]
        
        if len(mint_events) < 2:
            return None
        
        # Check for rapid minting
        sorted_events = sorted(mint_events, key=lambda x: x.timestamp)
        
        for i in range(len(sorted_events) - 1):
            time_delta = (sorted_events[i+1].timestamp - sorted_events[i].timestamp).total_seconds() / 60
            
            if time_delta <= time_window_minutes:
                total_minted = sum(e.amount for e in sorted_events)
                
                # Calculate supply change if we have total supply data
                supply_change_percent = 0.0
                if sorted_events[0].total_supply_after and sorted_events[-1].total_supply_after:
                    initial_supply = sorted_events[0].total_supply_after - sorted_events[0].amount
                    if initial_supply > 0:
                        supply_change_percent = ((sorted_events[-1].total_supply_after - initial_supply) / initial_supply) * 100
                
                if supply_change_percent > self.supply_change_threshold:
                    return MintBurnAnomaly(
                        token_address=events[0].token_address,
                        anomaly_type="rapid_minting",
                        severity="critical",
                        timestamp=datetime.now(),
                        description=f"Rapid minting detected: {supply_change_percent:.2f}% supply increase in {time_window_minutes} minutes",
                        mint_events=sorted_events,
                        total_minted=total_minted,
                        supply_change_percent=supply_change_percent
                    )
        
        return None
    
    def detect_oracle_price_manipulation(self, oracle_updates: List[OracleUpdate],
                                        mint_events: List[MintBurnEvent]) -> Optional[MintBurnAnomaly]:
        """
        Detect if oracle price changes correlate with minting (potential manipulation)
        
        Args:
            oracle_updates: List of oracle updates
            mint_events: List of mint events
            
        Returns:
            MintBurnAnomaly if detected, None otherwise
        """
        if not oracle_updates or not mint_events:
            return None
        
        # Look for price updates followed by minting
        price_updates = [u for u in oracle_updates if u.update_type == OracleUpdateType.PRICE_UPDATE]
        
        for price_update in price_updates:
            # Check if minting occurred shortly after price update
            time_window = timedelta(minutes=30)
            
            related_mints = [
                e for e in mint_events
                if abs((e.timestamp - price_update.timestamp).total_seconds()) <= time_window.total_seconds()
            ]
            
            if related_mints:
                price_change_percent = ((price_update.new_value - price_update.old_value) / price_update.old_value) * 100
                
                # Significant price increase followed by minting is suspicious
                if price_change_percent > 10:
                    total_minted = sum(e.amount for e in related_mints)
                    
                    return MintBurnAnomaly(
                        token_address=mint_events[0].token_address,
                        anomaly_type="oracle_price_manipulation",
                        severity="high",
                        timestamp=datetime.now(),
                        description=f"Oracle price increased {price_change_percent:.2f}% followed by {len(related_mints)} mint events totaling {total_minted}",
                        mint_events=related_mints,
                        oracle_updates=[price_update],
                        total_minted=total_minted
                    )
        
        return None
    
    def detect_unbacked_minting(self, mint_events: List[MintBurnEvent],
                               oracle_updates: List[OracleUpdate]) -> Optional[MintBurnAnomaly]:
        """
        Detect minting without corresponding oracle updates (unbacked minting)
        
        Args:
            mint_events: List of mint events
            oracle_updates: List of oracle updates
            
        Returns:
            MintBurnAnomaly if detected, None otherwise
        """
        if not mint_events:
            return None
        
        # Check for minting without recent oracle updates
        time_window = timedelta(hours=24)
        
        suspicious_mints = []
        for mint_event in mint_events:
            has_recent_oracle_update = any(
                abs((mint_event.timestamp - update.timestamp).total_seconds()) <= time_window.total_seconds()
                for update in oracle_updates
            )
            
            if not has_recent_oracle_update:
                suspicious_mints.append(mint_event)
        
        if suspicious_mints:
            total_minted = sum(e.amount for e in suspicious_mints)
            
            return MintBurnAnomaly(
                token_address=mint_events[0].token_address,
                anomaly_type="unbacked_minting",
                severity="critical",
                timestamp=datetime.now(),
                description=f"Detected {len(suspicious_mints)} mint events without corresponding oracle updates in last 24 hours",
                mint_events=suspicious_mints,
                total_minted=total_minted
            )
        
        return None
    
    def detect_supply_inflation(self, events: List[MintBurnEvent],
                               inflation_threshold: float = 100.0) -> Optional[MintBurnAnomaly]:
        """
        Detect excessive supply inflation over time
        
        Args:
            events: List of mint/burn events
            inflation_threshold: Percentage threshold for inflation
            
        Returns:
            MintBurnAnomaly if detected, None otherwise
        """
        if not events or len(events) < 2:
            return None
        
        # Calculate net supply change
        total_minted = sum(e.amount for e in events if e.event_type == MintBurnEventType.MINT)
        total_burned = sum(e.amount for e in events if e.event_type == MintBurnEventType.BURN)
        net_change = total_minted - total_burned
        
        # Get initial and final supply if available
        events_with_supply = [e for e in events if e.total_supply_after is not None]
        
        if len(events_with_supply) >= 2:
            initial_supply = events_with_supply[-1].total_supply_after - (
                events_with_supply[-1].amount if events_with_supply[-1].event_type == MintBurnEventType.MINT else 0
            )
            final_supply = events_with_supply[0].total_supply_after
            
            if initial_supply > 0:
                inflation_percent = ((final_supply - initial_supply) / initial_supply) * 100
                
                if inflation_percent > inflation_threshold:
                    return MintBurnAnomaly(
                        token_address=events[0].token_address,
                        anomaly_type="supply_inflation",
                        severity="high" if inflation_percent < 200 else "critical",
                        timestamp=datetime.now(),
                        description=f"Supply inflation detected: {inflation_percent:.2f}% increase",
                        mint_events=[e for e in events if e.event_type == MintBurnEventType.MINT],
                        total_minted=total_minted,
                        total_burned=total_burned,
                        supply_change_percent=inflation_percent
                    )
        
        return None


class OracleMintMonitor:
    """Main oracle vs mint/burn monitoring system"""
    
    def __init__(self, db_path: str = "oracle_mint_history.db"):
        self.db = OracleMintDatabase(db_path)
        self.detector = InfiniteMintDetector(supply_change_threshold=50.0)
    
    def record_mint_burn_event(self, event: MintBurnEvent) -> List[MintBurnAnomaly]:
        """
        Record a mint/burn event and detect anomalies
        
        Args:
            event: MintBurnEvent to record
            
        Returns:
            List of detected anomalies
        """
        self.db.store_mint_burn_event(event)
        
        # Get recent events for anomaly detection
        recent_events = self.db.get_mint_burn_events(
            event.token_address,
            start_time=datetime.now() - timedelta(days=7),
            limit=100
        )
        
        # Get recent oracle updates
        recent_oracle_updates = self.db.get_oracle_updates(
            event.token_address,  # Assuming asset_id matches token_address
            start_time=datetime.now() - timedelta(days=7),
            limit=100
        )
        
        anomalies = []
        
        # Detect rapid minting
        rapid_mint = self.detector.detect_rapid_minting(recent_events)
        if rapid_mint:
            anomalies.append(rapid_mint)
        
        # Detect oracle price manipulation
        price_manip = self.detector.detect_oracle_price_manipulation(
            recent_oracle_updates,
            recent_events
        )
        if price_manip:
            anomalies.append(price_manip)
        
        # Detect unbacked minting
        unbacked_mint = self.detector.detect_unbacked_minting(
            recent_events,
            recent_oracle_updates
        )
        if unbacked_mint:
            anomalies.append(unbacked_mint)
        
        # Detect supply inflation
        supply_inflation = self.detector.detect_supply_inflation(recent_events)
        if supply_inflation:
            anomalies.append(supply_inflation)
        
        # Store anomalies
        for anomaly in anomalies:
            self.db.store_anomaly(anomaly)
        
        return anomalies
    
    def record_oracle_update(self, update: OracleUpdate) -> List[MintBurnAnomaly]:
        """
        Record an oracle update and detect anomalies
        
        Args:
            update: OracleUpdate to record
            
        Returns:
            List of detected anomalies
        """
        self.db.store_oracle_update(update)
        
        # Get recent mint events for anomaly detection
        recent_events = self.db.get_mint_burn_events(
            update.asset_id,
            start_time=datetime.now() - timedelta(days=7),
            limit=100
        )
        
        # Get recent oracle updates
        recent_oracle_updates = self.db.get_oracle_updates(
            update.asset_id,
            start_time=datetime.now() - timedelta(days=7),
            limit=100
        )
        
        anomalies = []
        
        # Detect oracle price manipulation
        price_manip = self.detector.detect_oracle_price_manipulation(
            recent_oracle_updates,
            recent_events
        )
        if price_manip:
            anomalies.append(price_manip)
        
        # Store anomalies
        for anomaly in anomalies:
            self.db.store_anomaly(anomaly)
        
        return anomalies
    
    def get_token_history(self, token_address: str, 
                         days: int = 30) -> Tuple[List[MintBurnEvent], List[OracleUpdate]]:
        """
        Get mint/burn and oracle history for a token
        
        Args:
            token_address: Token contract address
            days: Number of days of history to retrieve
            
        Returns:
            Tuple of (mint_burn_events, oracle_updates)
        """
        start_time = datetime.now() - timedelta(days=days)
        events = self.db.get_mint_burn_events(token_address, start_time=start_time)
        updates = self.db.get_oracle_updates(token_address, start_time=start_time)
        return events, updates
    
    def get_token_anomalies(self, token_address: str) -> List[MintBurnAnomaly]:
        """
        Get anomalies for a specific token
        
        Args:
            token_address: Token contract address
            
        Returns:
            List of detected anomalies
        """
        return self.db.get_anomalies(token_address=token_address)
    
    def get_risk_score(self, token_address: str) -> float:
        """
        Calculate risk score based on mint/burn anomalies
        
        Args:
            token_address: Token contract address
            
        Returns:
            Risk score between 0 (safe) and 1 (critical)
        """
        anomalies = self.get_token_anomalies(token_address)
        
        if not anomalies:
            return 0.0
        
        # Weight anomalies by severity and type
        severity_weights = {
            "critical": 0.5,
            "high": 0.3,
            "medium": 0.15,
            "low": 0.05
        }
        
        # Extra weight for infinite minting related anomalies
        anomaly_type_weights = {
            "rapid_minting": 1.5,
            "unbacked_minting": 2.0,
            "supply_inflation": 1.3,
            "oracle_price_manipulation": 1.2
        }
        
        score = 0.0
        for anomaly in anomalies:
            severity_weight = severity_weights.get(anomaly.severity, 0.1)
            type_weight = anomaly_type_weights.get(anomaly.anomaly_type, 1.0)
            score += severity_weight * type_weight
        
        # Normalize to 0-1 range
        return min(score, 1.0)
    
    def close(self):
        """Close database connection"""
        self.db.close()


if __name__ == "__main__":
    # Example usage
    monitor = OracleMintMonitor()
    
    # Record some mint events
    token_address = "0x1234567890abcdef"
    
    for i in range(5):
        event = MintBurnEvent(
            token_address=token_address,
            event_type=MintBurnEventType.MINT,
            amount=1000000 * (i + 1),
            timestamp=datetime.now() - timedelta(minutes=i * 10),
            transaction_hash=f"0x{i:064x}",
            total_supply_after=10000000 + (1000000 * (i + 1))
        )
        anomalies = monitor.record_mint_burn_event(event)
        if anomalies:
            print(f"Anomalies detected: {len(anomalies)}")
            for anomaly in anomalies:
                print(f"  - {anomaly.anomaly_type}: {anomaly.description}")
    
    # Get risk score
    risk_score = monitor.get_risk_score(token_address)
    print(f"Risk score for token: {risk_score}")
    
    monitor.close()
