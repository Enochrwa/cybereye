# Security Information and Event Management (SIEM) System

import asyncio
import logging
import json
import time
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict, deque
import hashlib
import re

logger = logging.getLogger(__name__)

class EventType(str, Enum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    NETWORK = "network"
    SYSTEM = "system"
    APPLICATION = "application"
    SECURITY = "security"
    AUDIT = "audit"

class EventSeverity(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

@dataclass
class SecurityEvent:
    """Security event data structure."""
    event_id: str
    timestamp: datetime
    source: str
    event_type: EventType
    severity: EventSeverity
    message: str
    details: Dict[str, Any]
    user_id: Optional[str] = None
    ip_address: Optional[str] = None
    tags: Optional[List[str]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            **asdict(self),
            'timestamp': self.timestamp.isoformat(),
            'tags': self.tags or []
        }

@dataclass
class CorrelationRule:
    """Event correlation rule."""
    rule_id: str
    name: str
    description: str
    conditions: List[Dict[str, Any]]
    time_window: int  # seconds
    threshold: int
    severity: EventSeverity
    actions: List[str]
    enabled: bool = True

class EventProcessor:
    """Process and normalize security events."""
    
    def __init__(self):
        self.parsers = {
            'apache': self._parse_apache_log,
            'nginx': self._parse_nginx_log,
            'syslog': self._parse_syslog,
            'windows_event': self._parse_windows_event,
            'application': self._parse_application_log
        }
    
    def process_raw_event(self, raw_data: str, source_type: str) -> Optional[SecurityEvent]:
        """Process raw log data into security event."""
        try:
            parser = self.parsers.get(source_type, self._parse_generic_log)
            return parser(raw_data)
        except Exception as e:
            logger.error(f"Event processing error: {e}")
            return None
    
    def _parse_apache_log(self, log_line: str) -> Optional[SecurityEvent]:
        """Parse Apache access log."""
        # Common Log Format: IP - - [timestamp] "method path protocol" status size
        pattern = r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\S+)'
        match = re.match(pattern, log_line)
        
        if match:
            ip, timestamp_str, method, path, protocol, status, size = match.groups()
            
            # Parse timestamp
            try:
                timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
            except ValueError:
                timestamp = datetime.utcnow()
            
            # Determine severity based on status code
            status_code = int(status)
            if status_code >= 500:
                severity = EventSeverity.ERROR
            elif status_code >= 400:
                severity = EventSeverity.WARNING
            else:
                severity = EventSeverity.INFO
            
            return SecurityEvent(
                event_id=hashlib.md5(log_line.encode()).hexdigest(),
                timestamp=timestamp,
                source="apache",
                event_type=EventType.APPLICATION,
                severity=severity,
                message=f"{method} {path} - {status}",
                details={
                    'method': method,
                    'path': path,
                    'protocol': protocol,
                    'status_code': status_code,
                    'size': size,
                    'raw_log': log_line
                },
                ip_address=ip
            )
        
        return None
    
    def _parse_nginx_log(self, log_line: str) -> Optional[SecurityEvent]:
        """Parse Nginx access log."""
        # Similar to Apache but with slight differences
        return self._parse_apache_log(log_line)  # Simplified
    
    def _parse_syslog(self, log_line: str) -> Optional[SecurityEvent]:
        """Parse syslog format."""
        # RFC3164 format: <priority>timestamp hostname tag: message
        pattern = r'<(\d+)>(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+([^:]+):\s*(.*)'
        match = re.match(pattern, log_line)
        
        if match:
            priority, timestamp_str, hostname, tag, message = match.groups()
            
            try:
                timestamp = datetime.strptime(f"{datetime.now().year} {timestamp_str}", '%Y %b %d %H:%M:%S')
            except ValueError:
                timestamp = datetime.utcnow()
            
            # Determine severity from priority
            facility = int(priority) >> 3
            severity_num = int(priority) & 7
            
            severity_map = {
                0: EventSeverity.CRITICAL,
                1: EventSeverity.CRITICAL,
                2: EventSeverity.CRITICAL,
                3: EventSeverity.ERROR,
                4: EventSeverity.WARNING,
                5: EventSeverity.WARNING,
                6: EventSeverity.INFO,
                7: EventSeverity.DEBUG
            }
            
            severity = severity_map.get(severity_num, EventSeverity.INFO)
            
            return SecurityEvent(
                event_id=hashlib.md5(log_line.encode()).hexdigest(),
                timestamp=timestamp,
                source="syslog",
                event_type=EventType.SYSTEM,
                severity=severity,
                message=message,
                details={
                    'hostname': hostname,
                    'tag': tag,
                    'facility': facility,
                    'priority': priority,
                    'raw_log': log_line
                }
            )
        
        return None
    
    def _parse_windows_event(self, log_data: str) -> Optional[SecurityEvent]:
        """Parse Windows Event Log (simplified JSON format)."""
        try:
            data = json.loads(log_data)
            
            event_id = data.get('EventID', '')
            timestamp_str = data.get('TimeCreated', '')
            
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            except ValueError:
                timestamp = datetime.utcnow()
            
            # Map Windows event levels to severity
            level_map = {
                1: EventSeverity.CRITICAL,  # Critical
                2: EventSeverity.ERROR,     # Error
                3: EventSeverity.WARNING,   # Warning
                4: EventSeverity.INFO,      # Information
                5: EventSeverity.DEBUG      # Verbose
            }
            
            level = data.get('Level', 4)
            severity = level_map.get(level, EventSeverity.INFO)
            
            return SecurityEvent(
                event_id=hashlib.md5(log_data.encode()).hexdigest(),
                timestamp=timestamp,
                source="windows_event",
                event_type=EventType.SYSTEM,
                severity=severity,
                message=data.get('Message', ''),
                details=data,
                user_id=data.get('UserID')
            )
            
        except json.JSONDecodeError:
            return None
    
    def _parse_application_log(self, log_line: str) -> Optional[SecurityEvent]:
        """Parse application log (JSON format)."""
        try:
            data = json.loads(log_line)
            
            timestamp_str = data.get('timestamp', '')
            try:
                timestamp = datetime.fromisoformat(timestamp_str)
            except ValueError:
                timestamp = datetime.utcnow()
            
            severity_str = data.get('level', 'info').lower()
            severity_map = {
                'debug': EventSeverity.DEBUG,
                'info': EventSeverity.INFO,
                'warning': EventSeverity.WARNING,
                'error': EventSeverity.ERROR,
                'critical': EventSeverity.CRITICAL
            }
            severity = severity_map.get(severity_str, EventSeverity.INFO)
            
            return SecurityEvent(
                event_id=hashlib.md5(log_line.encode()).hexdigest(),
                timestamp=timestamp,
                source=data.get('source', 'application'),
                event_type=EventType.APPLICATION,
                severity=severity,
                message=data.get('message', ''),
                details=data,
                user_id=data.get('user_id'),
                ip_address=data.get('ip_address')
            )
            
        except json.JSONDecodeError:
            return self._parse_generic_log(log_line)
    
    def _parse_generic_log(self, log_line: str) -> SecurityEvent:
        """Parse generic log format."""
        return SecurityEvent(
            event_id=hashlib.md5(log_line.encode()).hexdigest(),
            timestamp=datetime.utcnow(),
            source="generic",
            event_type=EventType.APPLICATION,
            severity=EventSeverity.INFO,
            message=log_line.strip(),
            details={'raw_log': log_line}
        )

class EventCorrelator:
    """Correlate security events based on rules."""
    
    def __init__(self):
        self.rules: Dict[str, CorrelationRule] = {}
        self.event_buffer: deque = deque(maxlen=10000)
        self.correlation_results: List[Dict[str, Any]] = []
        
        # Load default rules
        self._load_default_rules()
    
    def _load_default_rules(self):
        """Load default correlation rules."""
        # Brute force detection
        self.add_rule(CorrelationRule(
            rule_id="brute_force_login",
            name="Brute Force Login Attempt",
            description="Multiple failed login attempts from same IP",
            conditions=[
                {'field': 'event_type', 'operator': 'equals', 'value': 'authentication'},
                {'field': 'message', 'operator': 'contains', 'value': 'failed'},
                {'field': 'ip_address', 'operator': 'exists'}
            ],
            time_window=300,  # 5 minutes
            threshold=5,
            severity=EventSeverity.WARNING,
            actions=['alert', 'block_ip']
        ))
        
        # Privilege escalation
        self.add_rule(CorrelationRule(
            rule_id="privilege_escalation",
            name="Privilege Escalation Attempt",
            description="User attempting to access privileged resources",
            conditions=[
                {'field': 'event_type', 'operator': 'equals', 'value': 'authorization'},
                {'field': 'message', 'operator': 'contains', 'value': 'denied'},
                {'field': 'details.resource', 'operator': 'contains', 'value': 'admin'}
            ],
            time_window=600,  # 10 minutes
            threshold=3,
            severity=EventSeverity.ERROR,
            actions=['alert', 'notify_admin']
        ))
        
        # Suspicious network activity
        self.add_rule(CorrelationRule(
            rule_id="suspicious_network",
            name="Suspicious Network Activity",
            description="High volume of network connections",
            conditions=[
                {'field': 'event_type', 'operator': 'equals', 'value': 'network'},
                {'field': 'severity', 'operator': 'in', 'value': ['warning', 'error']}
            ],
            time_window=60,  # 1 minute
            threshold=50,
            severity=EventSeverity.WARNING,
            actions=['alert']
        ))
    
    def add_rule(self, rule: CorrelationRule):
        """Add correlation rule."""
        self.rules[rule.rule_id] = rule
        logger.info(f"Added correlation rule: {rule.name}")
    
    def remove_rule(self, rule_id: str):
        """Remove correlation rule."""
        if rule_id in self.rules:
            del self.rules[rule_id]
            logger.info(f"Removed correlation rule: {rule_id}")
    
    def process_event(self, event: SecurityEvent) -> List[Dict[str, Any]]:
        """Process event and check for correlations."""
        self.event_buffer.append(event)
        correlations = []
        
        for rule in self.rules.values():
            if not rule.enabled:
                continue
            
            correlation = self._check_rule(rule, event)
            if correlation:
                correlations.append(correlation)
                self.correlation_results.append(correlation)
        
        # Limit stored results
        if len(self.correlation_results) > 1000:
            self.correlation_results = self.correlation_results[-1000:]
        
        return correlations
    
    def _check_rule(self, rule: CorrelationRule, trigger_event: SecurityEvent) -> Optional[Dict[str, Any]]:
        """Check if rule conditions are met."""
        # Get events within time window
        cutoff_time = trigger_event.timestamp - timedelta(seconds=rule.time_window)
        relevant_events = [
            event for event in self.event_buffer
            if event.timestamp >= cutoff_time
        ]
        
        # Filter events matching conditions
        matching_events = []
        for event in relevant_events:
            if self._event_matches_conditions(event, rule.conditions):
                matching_events.append(event)
        
        # Check threshold
        if len(matching_events) >= rule.threshold:
            return {
                'rule_id': rule.rule_id,
                'rule_name': rule.name,
                'description': rule.description,
                'severity': rule.severity.value,
                'trigger_event': trigger_event.to_dict(),
                'matching_events': [event.to_dict() for event in matching_events],
                'event_count': len(matching_events),
                'time_window': rule.time_window,
                'threshold': rule.threshold,
                'actions': rule.actions,
                'timestamp': datetime.utcnow().isoformat()
            }
        
        return None
    
    def _event_matches_conditions(self, event: SecurityEvent, conditions: List[Dict[str, Any]]) -> bool:
        """Check if event matches all conditions."""
        for condition in conditions:
            if not self._check_condition(event, condition):
                return False
        return True
    
    def _check_condition(self, event: SecurityEvent, condition: Dict[str, Any]) -> bool:
        """Check single condition against event."""
        field = condition['field']
        operator = condition['operator']
        value = condition['value']
        
        # Get field value from event
        event_value = self._get_field_value(event, field)
        
        if operator == 'equals':
            return event_value == value
        elif operator == 'contains':
            return value.lower() in str(event_value).lower()
        elif operator == 'exists':
            return event_value is not None
        elif operator == 'in':
            return event_value in value
        elif operator == 'greater_than':
            return float(event_value or 0) > float(value)
        elif operator == 'less_than':
            return float(event_value or 0) < float(value)
        
        return False
    
    def _get_field_value(self, event: SecurityEvent, field: str) -> Any:
        """Get field value from event using dot notation."""
        parts = field.split('.')
        value = event
        
        for part in parts:
            if hasattr(value, part):
                value = getattr(value, part)
            elif isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return None
        
        return value

class SIEMDashboard:
    """SIEM dashboard and reporting."""
    
    def __init__(self, event_store: List[SecurityEvent]):
        self.event_store = event_store
    
    def get_dashboard_data(self, time_range: int = 24) -> Dict[str, Any]:
        """Get dashboard data for specified time range (hours)."""
        cutoff_time = datetime.utcnow() - timedelta(hours=time_range)
        recent_events = [
            event for event in self.event_store
            if event.timestamp >= cutoff_time
        ]
        
        return {
            'summary': self._get_summary_stats(recent_events),
            'severity_distribution': self._get_severity_distribution(recent_events),
            'event_type_distribution': self._get_event_type_distribution(recent_events),
            'top_sources': self._get_top_sources(recent_events),
            'timeline': self._get_event_timeline(recent_events),
            'top_ips': self._get_top_ips(recent_events),
            'recent_critical_events': self._get_recent_critical_events(recent_events)
        }
    
    def _get_summary_stats(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Get summary statistics."""
        total_events = len(events)
        critical_events = len([e for e in events if e.severity == EventSeverity.CRITICAL])
        error_events = len([e for e in events if e.severity == EventSeverity.ERROR])
        warning_events = len([e for e in events if e.severity == EventSeverity.WARNING])
        
        return {
            'total_events': total_events,
            'critical_events': critical_events,
            'error_events': error_events,
            'warning_events': warning_events,
            'info_events': total_events - critical_events - error_events - warning_events
        }
    
    def _get_severity_distribution(self, events: List[SecurityEvent]) -> Dict[str, int]:
        """Get severity distribution."""
        distribution = defaultdict(int)
        for event in events:
            distribution[event.severity.value] += 1
        return dict(distribution)
    
    def _get_event_type_distribution(self, events: List[SecurityEvent]) -> Dict[str, int]:
        """Get event type distribution."""
        distribution = defaultdict(int)
        for event in events:
            distribution[event.event_type.value] += 1
        return dict(distribution)
    
    def _get_top_sources(self, events: List[SecurityEvent], limit: int = 10) -> List[Dict[str, Any]]:
        """Get top event sources."""
        source_counts = defaultdict(int)
        for event in events:
            source_counts[event.source] += 1
        
        return [
            {'source': source, 'count': count}
            for source, count in sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        ]
    
    def _get_event_timeline(self, events: List[SecurityEvent], buckets: int = 24) -> List[Dict[str, Any]]:
        """Get event timeline with hourly buckets."""
        if not events:
            return []
        
        # Create time buckets
        end_time = max(event.timestamp for event in events)
        start_time = end_time - timedelta(hours=buckets)
        bucket_size = timedelta(hours=1)
        
        timeline = []
        current_time = start_time
        
        while current_time <= end_time:
            bucket_end = current_time + bucket_size
            bucket_events = [
                event for event in events
                if current_time <= event.timestamp < bucket_end
            ]
            
            timeline.append({
                'timestamp': current_time.isoformat(),
                'count': len(bucket_events),
                'critical': len([e for e in bucket_events if e.severity == EventSeverity.CRITICAL]),
                'error': len([e for e in bucket_events if e.severity == EventSeverity.ERROR]),
                'warning': len([e for e in bucket_events if e.severity == EventSeverity.WARNING])
            })
            
            current_time = bucket_end
        
        return timeline
    
    def _get_top_ips(self, events: List[SecurityEvent], limit: int = 10) -> List[Dict[str, Any]]:
        """Get top IP addresses by event count."""
        ip_counts = defaultdict(int)
        for event in events:
            if event.ip_address:
                ip_counts[event.ip_address] += 1
        
        return [
            {'ip': ip, 'count': count}
            for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        ]
    
    def _get_recent_critical_events(self, events: List[SecurityEvent], limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent critical events."""
        critical_events = [
            event for event in events
            if event.severity in [EventSeverity.CRITICAL, EventSeverity.ERROR]
        ]
        
        # Sort by timestamp (most recent first)
        critical_events.sort(key=lambda x: x.timestamp, reverse=True)
        
        return [event.to_dict() for event in critical_events[:limit]]

class SIEMSystem:
    """Main SIEM system."""
    
    def __init__(self):
        self.event_processor = EventProcessor()
        self.event_correlator = EventCorrelator()
        self.event_store: List[SecurityEvent] = []
        self.dashboard = SIEMDashboard(self.event_store)
        self.running = False
        
        # Configuration
        self.max_events = 100000
        self.retention_days = 30
    
    async def start(self):
        """Start SIEM system."""
        logger.info("Starting SIEM system...")
        self.running = True
        
        # Start background tasks
        asyncio.create_task(self._cleanup_loop())
        
        logger.info("SIEM system started")
    
    async def stop(self):
        """Stop SIEM system."""
        logger.info("Stopping SIEM system...")
        self.running = False
    
    async def _cleanup_loop(self):
        """Background cleanup loop."""
        while self.running:
            try:
                await asyncio.sleep(3600)  # Cleanup every hour
                self._cleanup_old_events()
            except Exception as e:
                logger.error(f"SIEM cleanup error: {e}")
    
    def _cleanup_old_events(self):
        """Remove old events based on retention policy."""
        cutoff_time = datetime.utcnow() - timedelta(days=self.retention_days)
        
        original_count = len(self.event_store)
        self.event_store = [
            event for event in self.event_store
            if event.timestamp >= cutoff_time
        ]
        
        removed_count = original_count - len(self.event_store)
        if removed_count > 0:
            logger.info(f"Cleaned up {removed_count} old events")
    
    async def ingest_raw_log(self, raw_data: str, source_type: str) -> Optional[Dict[str, Any]]:
        """Ingest raw log data."""
        try:
            # Process raw data into security event
            event = self.event_processor.process_raw_event(raw_data, source_type)
            
            if event:
                return await self.ingest_event(event)
            
            return None
            
        except Exception as e:
            logger.error(f"Raw log ingestion error: {e}")
            return None
    
    async def ingest_event(self, event: SecurityEvent) -> Dict[str, Any]:
        """Ingest security event."""
        try:
            # Store event
            self.event_store.append(event)
            
            # Limit stored events
            if len(self.event_store) > self.max_events:
                self.event_store = self.event_store[-self.max_events:]
            
            # Run correlation
            correlations = self.event_correlator.process_event(event)
            
            # Log correlations
            for correlation in correlations:
                logger.warning(f"Event correlation: {correlation['rule_name']}")
            
            return {
                'event': event.to_dict(),
                'correlations': correlations,
                'event_count': len(self.event_store)
            }
            
        except Exception as e:
            logger.error(f"Event ingestion error: {e}")
            return {}
    
    def get_dashboard_data(self, time_range: int = 24) -> Dict[str, Any]:
        """Get SIEM dashboard data."""
        return self.dashboard.get_dashboard_data(time_range)
    
    def search_events(self, query: Dict[str, Any], limit: int = 100) -> List[Dict[str, Any]]:
        """Search events based on query."""
        results = []
        
        for event in reversed(self.event_store):  # Most recent first
            if len(results) >= limit:
                break
            
            if self._event_matches_query(event, query):
                results.append(event.to_dict())
        
        return results
    
    def _event_matches_query(self, event: SecurityEvent, query: Dict[str, Any]) -> bool:
        """Check if event matches search query."""
        for field, value in query.items():
            if field == 'severity' and event.severity.value != value:
                return False
            elif field == 'event_type' and event.event_type.value != value:
                return False
            elif field == 'source' and event.source != value:
                return False
            elif field == 'message' and value.lower() not in event.message.lower():
                return False
            elif field == 'ip_address' and event.ip_address != value:
                return False
            elif field == 'user_id' and event.user_id != value:
                return False
        
        return True
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get SIEM system statistics."""
        return {
            'total_events': len(self.event_store),
            'correlation_rules': len(self.event_correlator.rules),
            'correlations_found': len(self.event_correlator.correlation_results),
            'dashboard_data': self.get_dashboard_data(1),  # Last hour
            'timestamp': datetime.utcnow().isoformat()
        }

# Global SIEM system
siem_system = SIEMSystem()

# Export SIEM components
__all__ = [
    'EventType',
    'EventSeverity',
    'SecurityEvent',
    'CorrelationRule',
    'EventProcessor',
    'EventCorrelator',
    'SIEMDashboard',
    'SIEMSystem',
    'siem_system'
]

