# AI-Powered Threat Intelligence Engine

import asyncio
import json
import logging
import hashlib
import time
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib
import aiohttp
import ipaddress

logger = logging.getLogger(__name__)

class ThreatLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ThreatType(str, Enum):
    MALWARE = "malware"
    PHISHING = "phishing"
    BOTNET = "botnet"
    APT = "apt"
    DDOS = "ddos"
    INTRUSION = "intrusion"
    DATA_EXFILTRATION = "data_exfiltration"
    RANSOMWARE = "ransomware"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    UNKNOWN = "unknown"

@dataclass
class ThreatIndicator:
    """Threat indicator data structure."""
    id: str
    type: ThreatType
    value: str
    confidence: float
    severity: ThreatLevel
    source: str
    first_seen: datetime
    last_seen: datetime
    tags: List[str]
    context: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            **asdict(self),
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat()
        }

@dataclass
class ThreatEvent:
    """Threat event data structure."""
    id: str
    timestamp: datetime
    source_ip: str
    destination_ip: Optional[str]
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: str
    event_type: ThreatType
    severity: ThreatLevel
    confidence: float
    description: str
    indicators: List[ThreatIndicator]
    raw_data: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            **asdict(self),
            'timestamp': self.timestamp.isoformat(),
            'indicators': [indicator.to_dict() for indicator in self.indicators]
        }

class ThreatIntelligenceFeeds:
    """Manage threat intelligence feeds from various sources."""
    
    def __init__(self):
        self.feeds = {
            'abuse_ch': {
                'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
                'type': 'ip',
                'format': 'json'
            },
            'malware_domains': {
                'url': 'https://mirror1.malwaredomains.com/files/domains.txt',
                'type': 'domain',
                'format': 'text'
            },
            'emergingthreats': {
                'url': 'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
                'type': 'ip',
                'format': 'text'
            }
        }
        
        self.indicators: Dict[str, ThreatIndicator] = {}
        self.last_update = {}
        
    async def update_feeds(self):
        """Update threat intelligence feeds."""
        logger.info("Updating threat intelligence feeds...")
        
        async with aiohttp.ClientSession() as session:
            for feed_name, feed_config in self.feeds.items():
                try:
                    await self._update_single_feed(session, feed_name, feed_config)
                except Exception as e:
                    logger.error(f"Failed to update feed {feed_name}: {e}")
        
        logger.info(f"Threat intelligence update complete. Total indicators: {len(self.indicators)}")
    
    async def _update_single_feed(self, session: aiohttp.ClientSession, feed_name: str, config: Dict[str, Any]):
        """Update a single threat intelligence feed."""
        try:
            async with session.get(config['url'], timeout=30) as response:
                if response.status == 200:
                    content = await response.text()
                    indicators = self._parse_feed_content(content, config, feed_name)
                    
                    for indicator in indicators:
                        self.indicators[indicator.id] = indicator
                    
                    self.last_update[feed_name] = datetime.utcnow()
                    logger.info(f"Updated feed {feed_name}: {len(indicators)} indicators")
                else:
                    logger.warning(f"Feed {feed_name} returned status {response.status}")
        
        except Exception as e:
            logger.error(f"Error updating feed {feed_name}: {e}")
    
    def _parse_feed_content(self, content: str, config: Dict[str, Any], source: str) -> List[ThreatIndicator]:
        """Parse feed content based on format."""
        indicators = []
        now = datetime.utcnow()
        
        if config['format'] == 'json':
            try:
                data = json.loads(content)
                for item in data:
                    if isinstance(item, dict):
                        value = item.get('ip') or item.get('domain') or item.get('url')
                        if value:
                            indicator = ThreatIndicator(
                                id=hashlib.md5(f"{source}:{value}".encode()).hexdigest(),
                                type=ThreatType.MALWARE,
                                value=value,
                                confidence=0.8,
                                severity=ThreatLevel.MEDIUM,
                                source=source,
                                first_seen=now,
                                last_seen=now,
                                tags=[config['type']],
                                context=item
                            )
                            indicators.append(indicator)
            except json.JSONDecodeError:
                logger.error(f"Failed to parse JSON from {source}")
        
        elif config['format'] == 'text':
            lines = content.strip().split('\n')
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Extract IP or domain
                    value = line.split()[0] if ' ' in line else line
                    
                    if self._is_valid_indicator(value, config['type']):
                        indicator = ThreatIndicator(
                            id=hashlib.md5(f"{source}:{value}".encode()).hexdigest(),
                            type=ThreatType.MALWARE,
                            value=value,
                            confidence=0.7,
                            severity=ThreatLevel.MEDIUM,
                            source=source,
                            first_seen=now,
                            last_seen=now,
                            tags=[config['type']],
                            context={'raw_line': line}
                        )
                        indicators.append(indicator)
        
        return indicators
    
    def _is_valid_indicator(self, value: str, indicator_type: str) -> bool:
        """Validate indicator value."""
        if indicator_type == 'ip':
            try:
                ipaddress.ip_address(value)
                return True
            except ValueError:
                return False
        
        elif indicator_type == 'domain':
            # Basic domain validation
            return '.' in value and len(value) > 3 and not value.startswith('.')
        
        return True
    
    def lookup_indicator(self, value: str) -> Optional[ThreatIndicator]:
        """Lookup threat indicator by value."""
        for indicator in self.indicators.values():
            if indicator.value == value:
                return indicator
        return None
    
    def get_indicators_by_type(self, threat_type: ThreatType) -> List[ThreatIndicator]:
        """Get indicators by threat type."""
        return [indicator for indicator in self.indicators.values() if indicator.type == threat_type]

class BehavioralAnalyzer:
    """Analyze network behavior for anomalies using machine learning."""
    
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_columns = [
            'packet_count', 'byte_count', 'duration', 'src_port', 'dst_port',
            'protocol_tcp', 'protocol_udp', 'protocol_icmp', 'hour', 'day_of_week'
        ]
    
    def extract_features(self, network_data: Dict[str, Any]) -> np.ndarray:
        """Extract features from network data."""
        features = []
        
        # Basic network features
        features.append(network_data.get('packet_count', 0))
        features.append(network_data.get('byte_count', 0))
        features.append(network_data.get('duration', 0))
        features.append(network_data.get('src_port', 0))
        features.append(network_data.get('dst_port', 0))
        
        # Protocol encoding
        protocol = network_data.get('protocol', '').lower()
        features.append(1 if protocol == 'tcp' else 0)
        features.append(1 if protocol == 'udp' else 0)
        features.append(1 if protocol == 'icmp' else 0)
        
        # Time features
        timestamp = network_data.get('timestamp', datetime.utcnow())
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)
        
        features.append(timestamp.hour)
        features.append(timestamp.weekday())
        
        return np.array(features).reshape(1, -1)
    
    def train_models(self, training_data: List[Dict[str, Any]], labels: Optional[List[int]] = None):
        """Train anomaly detection and classification models."""
        logger.info("Training behavioral analysis models...")
        
        # Extract features
        features_list = []
        for data in training_data:
            features = self.extract_features(data)
            features_list.append(features.flatten())
        
        if not features_list:
            logger.warning("No training data available")
            return
        
        X = np.array(features_list)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train isolation forest for anomaly detection
        self.isolation_forest.fit(X_scaled)
        
        # Train classifier if labels are provided
        if labels and len(labels) == len(X):
            X_train, X_test, y_train, y_test = train_test_split(
                X_scaled, labels, test_size=0.2, random_state=42
            )
            self.classifier.fit(X_train, y_train)
            
            # Evaluate classifier
            accuracy = self.classifier.score(X_test, y_test)
            logger.info(f"Classifier accuracy: {accuracy:.3f}")
        
        self.is_trained = True
        logger.info("Behavioral analysis models trained successfully")
    
    def detect_anomaly(self, network_data: Dict[str, Any]) -> Tuple[bool, float]:
        """Detect if network data is anomalous."""
        if not self.is_trained:
            return False, 0.0
        
        features = self.extract_features(network_data)
        features_scaled = self.scaler.transform(features)
        
        # Get anomaly score
        anomaly_score = self.isolation_forest.decision_function(features_scaled)[0]
        is_anomaly = self.isolation_forest.predict(features_scaled)[0] == -1
        
        # Convert score to confidence (0-1)
        confidence = max(0, min(1, (0.5 - anomaly_score) * 2))
        
        return is_anomaly, confidence
    
    def classify_threat(self, network_data: Dict[str, Any]) -> Tuple[ThreatType, float]:
        """Classify threat type."""
        if not self.is_trained:
            return ThreatType.UNKNOWN, 0.0
        
        features = self.extract_features(network_data)
        features_scaled = self.scaler.transform(features)
        
        # Get prediction probabilities
        probabilities = self.classifier.predict_proba(features_scaled)[0]
        predicted_class = self.classifier.predict(features_scaled)[0]
        confidence = max(probabilities)
        
        # Map class to threat type (simplified)
        threat_mapping = {
            0: ThreatType.SUSPICIOUS_ACTIVITY,
            1: ThreatType.MALWARE,
            2: ThreatType.INTRUSION,
            3: ThreatType.DDOS,
            4: ThreatType.DATA_EXFILTRATION
        }
        
        threat_type = threat_mapping.get(predicted_class, ThreatType.UNKNOWN)
        
        return threat_type, confidence

class ThreatIntelligenceEngine:
    """Main threat intelligence engine."""
    
    def __init__(self):
        self.feeds = ThreatIntelligenceFeeds()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.threat_events: List[ThreatEvent] = []
        self.running = False
        
        # Configuration
        self.update_interval = 3600  # 1 hour
        self.max_events = 10000
        
    async def start(self):
        """Start the threat intelligence engine."""
        logger.info("Starting threat intelligence engine...")
        self.running = True
        
        # Initial feed update
        await self.feeds.update_feeds()
        
        # Start background tasks
        asyncio.create_task(self._feed_update_loop())
        asyncio.create_task(self._model_training_loop())
        
        logger.info("Threat intelligence engine started")
    
    async def stop(self):
        """Stop the threat intelligence engine."""
        logger.info("Stopping threat intelligence engine...")
        self.running = False
    
    async def _feed_update_loop(self):
        """Background loop to update threat feeds."""
        while self.running:
            try:
                await asyncio.sleep(self.update_interval)
                await self.feeds.update_feeds()
            except Exception as e:
                logger.error(f"Feed update loop error: {e}")
                await asyncio.sleep(60)
    
    async def _model_training_loop(self):
        """Background loop to retrain models."""
        while self.running:
            try:
                await asyncio.sleep(3600)  # Retrain every hour
                await self._retrain_models()
            except Exception as e:
                logger.error(f"Model training loop error: {e}")
                await asyncio.sleep(300)
    
    async def _retrain_models(self):
        """Retrain behavioral analysis models."""
        if len(self.threat_events) < 100:
            return
        
        # Prepare training data
        training_data = []
        labels = []
        
        for event in self.threat_events[-1000:]:  # Use last 1000 events
            training_data.append(event.raw_data)
            # Simple labeling based on severity
            if event.severity == ThreatLevel.CRITICAL:
                labels.append(4)
            elif event.severity == ThreatLevel.HIGH:
                labels.append(3)
            elif event.severity == ThreatLevel.MEDIUM:
                labels.append(2)
            else:
                labels.append(1)
        
        # Train models in background thread
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None, 
            self.behavioral_analyzer.train_models, 
            training_data, 
            labels
        )
    
    async def analyze_network_event(self, network_data: Dict[str, Any]) -> Optional[ThreatEvent]:
        """Analyze network event for threats."""
        try:
            # Extract key information
            src_ip = network_data.get('src_ip', '')
            dst_ip = network_data.get('dst_ip', '')
            
            # Check against threat intelligence
            threat_indicators = []
            
            # Check source IP
            if src_ip:
                indicator = self.feeds.lookup_indicator(src_ip)
                if indicator:
                    threat_indicators.append(indicator)
            
            # Check destination IP
            if dst_ip:
                indicator = self.feeds.lookup_indicator(dst_ip)
                if indicator:
                    threat_indicators.append(indicator)
            
            # Behavioral analysis
            is_anomaly, anomaly_confidence = self.behavioral_analyzer.detect_anomaly(network_data)
            threat_type, classification_confidence = self.behavioral_analyzer.classify_threat(network_data)
            
            # Determine if this is a threat
            is_threat = bool(threat_indicators) or is_anomaly
            
            if is_threat:
                # Calculate overall confidence and severity
                confidence = max(
                    max([ind.confidence for ind in threat_indicators], default=0),
                    anomaly_confidence,
                    classification_confidence
                )
                
                severity = self._calculate_severity(confidence, threat_indicators, is_anomaly)
                
                # Create threat event
                event = ThreatEvent(
                    id=hashlib.md5(f"{src_ip}:{dst_ip}:{time.time()}".encode()).hexdigest(),
                    timestamp=datetime.utcnow(),
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=network_data.get('src_port'),
                    destination_port=network_data.get('dst_port'),
                    protocol=network_data.get('protocol', 'unknown'),
                    event_type=threat_type,
                    severity=severity,
                    confidence=confidence,
                    description=self._generate_description(threat_indicators, is_anomaly, threat_type),
                    indicators=threat_indicators,
                    raw_data=network_data
                )
                
                # Store event
                self.threat_events.append(event)
                
                # Limit stored events
                if len(self.threat_events) > self.max_events:
                    self.threat_events = self.threat_events[-self.max_events:]
                
                logger.warning(f"Threat detected: {event.description}")
                return event
            
            return None
            
        except Exception as e:
            logger.error(f"Error analyzing network event: {e}")
            return None
    
    def _calculate_severity(self, confidence: float, indicators: List[ThreatIndicator], is_anomaly: bool) -> ThreatLevel:
        """Calculate threat severity."""
        if confidence >= 0.9 or any(ind.severity == ThreatLevel.CRITICAL for ind in indicators):
            return ThreatLevel.CRITICAL
        elif confidence >= 0.7 or any(ind.severity == ThreatLevel.HIGH for ind in indicators):
            return ThreatLevel.HIGH
        elif confidence >= 0.5 or is_anomaly:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
    
    def _generate_description(self, indicators: List[ThreatIndicator], is_anomaly: bool, threat_type: ThreatType) -> str:
        """Generate threat description."""
        descriptions = []
        
        if indicators:
            sources = set(ind.source for ind in indicators)
            descriptions.append(f"Matched threat intelligence from {', '.join(sources)}")
        
        if is_anomaly:
            descriptions.append("Anomalous network behavior detected")
        
        descriptions.append(f"Classified as {threat_type.value}")
        
        return "; ".join(descriptions)
    
    def get_threat_statistics(self) -> Dict[str, Any]:
        """Get threat statistics."""
        if not self.threat_events:
            return {}
        
        now = datetime.utcnow()
        last_24h = now - timedelta(hours=24)
        recent_events = [e for e in self.threat_events if e.timestamp > last_24h]
        
        return {
            'total_threats': len(self.threat_events),
            'threats_last_24h': len(recent_events),
            'threat_types': {
                threat_type.value: len([e for e in recent_events if e.event_type == threat_type])
                for threat_type in ThreatType
            },
            'severity_distribution': {
                severity.value: len([e for e in recent_events if e.severity == severity])
                for severity in ThreatLevel
            },
            'top_source_ips': self._get_top_source_ips(recent_events),
            'indicators_count': len(self.feeds.indicators),
            'last_feed_update': max(self.feeds.last_update.values()) if self.feeds.last_update else None
        }
    
    def _get_top_source_ips(self, events: List[ThreatEvent], limit: int = 10) -> List[Dict[str, Any]]:
        """Get top source IPs by threat count."""
        ip_counts = {}
        for event in events:
            ip = event.source_ip
            if ip:
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        return [
            {'ip': ip, 'count': count}
            for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        ]
    
    def save_models(self, filepath: str):
        """Save trained models to disk."""
        try:
            model_data = {
                'isolation_forest': self.behavioral_analyzer.isolation_forest,
                'classifier': self.behavioral_analyzer.classifier,
                'scaler': self.behavioral_analyzer.scaler,
                'is_trained': self.behavioral_analyzer.is_trained,
                'feature_columns': self.behavioral_analyzer.feature_columns
            }
            joblib.dump(model_data, filepath)
            logger.info(f"Models saved to {filepath}")
        except Exception as e:
            logger.error(f"Error saving models: {e}")
    
    def load_models(self, filepath: str):
        """Load trained models from disk."""
        try:
            model_data = joblib.load(filepath)
            self.behavioral_analyzer.isolation_forest = model_data['isolation_forest']
            self.behavioral_analyzer.classifier = model_data['classifier']
            self.behavioral_analyzer.scaler = model_data['scaler']
            self.behavioral_analyzer.is_trained = model_data['is_trained']
            self.behavioral_analyzer.feature_columns = model_data['feature_columns']
            logger.info(f"Models loaded from {filepath}")
        except Exception as e:
            logger.error(f"Error loading models: {e}")

# Global threat intelligence engine
threat_intelligence_engine = ThreatIntelligenceEngine()

# Export threat intelligence components
__all__ = [
    'ThreatLevel',
    'ThreatType',
    'ThreatIndicator',
    'ThreatEvent',
    'ThreatIntelligenceFeeds',
    'BehavioralAnalyzer',
    'ThreatIntelligenceEngine',
    'threat_intelligence_engine'
]

