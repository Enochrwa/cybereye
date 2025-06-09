# Advanced Network Security Monitoring System

import asyncio
import logging
import time
import json
import struct
import socket
from typing import Dict, List, Any, Optional, Tuple, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import threading
from collections import defaultdict, deque
import ipaddress
import re

# Network packet analysis
try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS
    from scapy.layers.http import HTTP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available, some network monitoring features will be limited")

logger = logging.getLogger(__name__)

class ProtocolType(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    DNS = "dns"
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    FTP = "ftp"
    SMTP = "smtp"
    UNKNOWN = "unknown"

class AlertSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class NetworkFlow:
    """Network flow data structure."""
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: ProtocolType
    start_time: datetime
    end_time: Optional[datetime]
    packet_count: int
    byte_count: int
    flags: Set[str]
    duration: float
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            **asdict(self),
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'flags': list(self.flags)
        }

@dataclass
class NetworkAlert:
    """Network security alert."""
    alert_id: str
    timestamp: datetime
    severity: AlertSeverity
    alert_type: str
    source_ip: str
    destination_ip: str
    protocol: ProtocolType
    description: str
    details: Dict[str, Any]
    flow_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            **asdict(self),
            'timestamp': self.timestamp.isoformat()
        }

class PacketAnalyzer:
    """Deep packet inspection and analysis."""
    
    def __init__(self):
        self.suspicious_patterns = {
            'sql_injection': [
                r'union\s+select',
                r'drop\s+table',
                r'insert\s+into',
                r'delete\s+from',
                r'update\s+.*\s+set',
                r'exec\s*\(',
                r'sp_executesql'
            ],
            'xss': [
                r'<script[^>]*>',
                r'javascript:',
                r'eval\s*\(',
                r'document\.cookie',
                r'window\.location'
            ],
            'command_injection': [
                r';\s*(cat|ls|pwd|whoami|id)',
                r'\|\s*(cat|ls|pwd|whoami|id)',
                r'&&\s*(cat|ls|pwd|whoami|id)',
                r'`[^`]*`',
                r'\$\([^)]*\)'
            ],
            'directory_traversal': [
                r'\.\./.*\.\.',
                r'\.\.\\.*\.\.',
                r'%2e%2e%2f',
                r'%2e%2e%5c'
            ]
        }
        
        # Compile regex patterns
        self.compiled_patterns = {}
        for category, patterns in self.suspicious_patterns.items():
            self.compiled_patterns[category] = [
                re.compile(pattern, re.IGNORECASE) for pattern in patterns
            ]
    
    def analyze_packet(self, packet_data: bytes) -> Dict[str, Any]:
        """Analyze packet for suspicious content."""
        if not SCAPY_AVAILABLE:
            return self._basic_packet_analysis(packet_data)
        
        try:
            packet = scapy.Ether(packet_data)
            analysis = {
                'timestamp': datetime.utcnow(),
                'size': len(packet_data),
                'protocols': [],
                'suspicious_content': [],
                'metadata': {}
            }
            
            # Extract protocol information
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                analysis['src_ip'] = ip_layer.src
                analysis['dst_ip'] = ip_layer.dst
                analysis['protocols'].append('IP')
                
                # TCP analysis
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    analysis['src_port'] = tcp_layer.sport
                    analysis['dst_port'] = tcp_layer.dport
                    analysis['protocols'].append('TCP')
                    analysis['tcp_flags'] = self._get_tcp_flags(tcp_layer)
                    
                    # HTTP analysis
                    if packet.haslayer(HTTP):
                        analysis['protocols'].append('HTTP')
                        http_analysis = self._analyze_http_packet(packet)
                        analysis['metadata'].update(http_analysis)
                
                # UDP analysis
                elif packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    analysis['src_port'] = udp_layer.sport
                    analysis['dst_port'] = udp_layer.dport
                    analysis['protocols'].append('UDP')
                    
                    # DNS analysis
                    if packet.haslayer(DNS):
                        analysis['protocols'].append('DNS')
                        dns_analysis = self._analyze_dns_packet(packet)
                        analysis['metadata'].update(dns_analysis)
                
                # ICMP analysis
                elif packet.haslayer(ICMP):
                    icmp_layer = packet[ICMP]
                    analysis['protocols'].append('ICMP')
                    analysis['icmp_type'] = icmp_layer.type
                    analysis['icmp_code'] = icmp_layer.code
            
            # Payload analysis
            if packet.haslayer(scapy.Raw):
                payload = packet[scapy.Raw].load
                suspicious_content = self._analyze_payload(payload)
                analysis['suspicious_content'] = suspicious_content
            
            return analysis
            
        except Exception as e:
            logger.error(f"Packet analysis error: {e}")
            return self._basic_packet_analysis(packet_data)
    
    def _basic_packet_analysis(self, packet_data: bytes) -> Dict[str, Any]:
        """Basic packet analysis without Scapy."""
        analysis = {
            'timestamp': datetime.utcnow(),
            'size': len(packet_data),
            'protocols': ['RAW'],
            'suspicious_content': [],
            'metadata': {}
        }
        
        # Basic payload analysis
        try:
            payload_str = packet_data.decode('utf-8', errors='ignore')
            suspicious_content = self._analyze_payload(payload_str.encode())
            analysis['suspicious_content'] = suspicious_content
        except Exception:
            pass
        
        return analysis
    
    def _get_tcp_flags(self, tcp_layer) -> List[str]:
        """Extract TCP flags."""
        flags = []
        if tcp_layer.flags.F: flags.append('FIN')
        if tcp_layer.flags.S: flags.append('SYN')
        if tcp_layer.flags.R: flags.append('RST')
        if tcp_layer.flags.P: flags.append('PSH')
        if tcp_layer.flags.A: flags.append('ACK')
        if tcp_layer.flags.U: flags.append('URG')
        return flags
    
    def _analyze_http_packet(self, packet) -> Dict[str, Any]:
        """Analyze HTTP packet."""
        http_data = {}
        
        try:
            if hasattr(packet[HTTP], 'Method'):
                http_data['method'] = packet[HTTP].Method.decode()
            if hasattr(packet[HTTP], 'Host'):
                http_data['host'] = packet[HTTP].Host.decode()
            if hasattr(packet[HTTP], 'Path'):
                http_data['path'] = packet[HTTP].Path.decode()
            if hasattr(packet[HTTP], 'User_Agent'):
                http_data['user_agent'] = packet[HTTP].User_Agent.decode()
        except Exception as e:
            logger.debug(f"HTTP analysis error: {e}")
        
        return http_data
    
    def _analyze_dns_packet(self, packet) -> Dict[str, Any]:
        """Analyze DNS packet."""
        dns_data = {}
        
        try:
            dns_layer = packet[DNS]
            dns_data['query_id'] = dns_layer.id
            dns_data['query_type'] = dns_layer.qr
            
            if dns_layer.qd:
                dns_data['query_name'] = dns_layer.qd.qname.decode()
                dns_data['query_type'] = dns_layer.qd.qtype
        except Exception as e:
            logger.debug(f"DNS analysis error: {e}")
        
        return dns_data
    
    def _analyze_payload(self, payload: bytes) -> List[Dict[str, Any]]:
        """Analyze payload for suspicious patterns."""
        suspicious_content = []
        
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
            
            for category, patterns in self.compiled_patterns.items():
                for pattern in patterns:
                    matches = pattern.findall(payload_str)
                    if matches:
                        suspicious_content.append({
                            'category': category,
                            'pattern': pattern.pattern,
                            'matches': matches[:5]  # Limit matches
                        })
        except Exception as e:
            logger.debug(f"Payload analysis error: {e}")
        
        return suspicious_content

class NetworkFlowTracker:
    """Track and analyze network flows."""
    
    def __init__(self, flow_timeout: int = 300):
        self.flows: Dict[str, NetworkFlow] = {}
        self.flow_timeout = flow_timeout
        self.flow_stats = defaultdict(int)
        
    def _generate_flow_id(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> str:
        """Generate unique flow ID."""
        return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
    
    def update_flow(self, packet_analysis: Dict[str, Any]) -> Optional[NetworkFlow]:
        """Update or create network flow."""
        try:
            src_ip = packet_analysis.get('src_ip', '')
            dst_ip = packet_analysis.get('dst_ip', '')
            src_port = packet_analysis.get('src_port', 0)
            dst_port = packet_analysis.get('dst_port', 0)
            
            # Determine protocol
            protocols = packet_analysis.get('protocols', [])
            if 'TCP' in protocols:
                protocol = ProtocolType.TCP
            elif 'UDP' in protocols:
                protocol = ProtocolType.UDP
            elif 'ICMP' in protocols:
                protocol = ProtocolType.ICMP
            else:
                protocol = ProtocolType.UNKNOWN
            
            flow_id = self._generate_flow_id(src_ip, dst_ip, src_port, dst_port, protocol.value)
            
            now = datetime.utcnow()
            packet_size = packet_analysis.get('size', 0)
            
            if flow_id in self.flows:
                # Update existing flow
                flow = self.flows[flow_id]
                flow.packet_count += 1
                flow.byte_count += packet_size
                flow.end_time = now
                flow.duration = (now - flow.start_time).total_seconds()
                
                # Update flags for TCP
                if protocol == ProtocolType.TCP and 'tcp_flags' in packet_analysis:
                    flow.flags.update(packet_analysis['tcp_flags'])
            else:
                # Create new flow
                flags = set()
                if protocol == ProtocolType.TCP and 'tcp_flags' in packet_analysis:
                    flags.update(packet_analysis['tcp_flags'])
                
                flow = NetworkFlow(
                    flow_id=flow_id,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    start_time=now,
                    end_time=now,
                    packet_count=1,
                    byte_count=packet_size,
                    flags=flags,
                    duration=0.0
                )
                
                self.flows[flow_id] = flow
                self.flow_stats['total_flows'] += 1
            
            return flow
            
        except Exception as e:
            logger.error(f"Flow update error: {e}")
            return None
    
    def cleanup_expired_flows(self):
        """Remove expired flows."""
        now = datetime.utcnow()
        expired_flows = []
        
        for flow_id, flow in self.flows.items():
            if flow.end_time and (now - flow.end_time).total_seconds() > self.flow_timeout:
                expired_flows.append(flow_id)
        
        for flow_id in expired_flows:
            del self.flows[flow_id]
        
        if expired_flows:
            logger.debug(f"Cleaned up {len(expired_flows)} expired flows")
    
    def get_flow_statistics(self) -> Dict[str, Any]:
        """Get flow statistics."""
        now = datetime.utcnow()
        active_flows = len(self.flows)
        
        # Protocol distribution
        protocol_dist = defaultdict(int)
        for flow in self.flows.values():
            protocol_dist[flow.protocol.value] += 1
        
        # Top talkers
        src_ip_counts = defaultdict(int)
        dst_ip_counts = defaultdict(int)
        
        for flow in self.flows.values():
            src_ip_counts[flow.src_ip] += flow.packet_count
            dst_ip_counts[flow.dst_ip] += flow.packet_count
        
        top_src_ips = sorted(src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        top_dst_ips = sorted(dst_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            'active_flows': active_flows,
            'total_flows': self.flow_stats['total_flows'],
            'protocol_distribution': dict(protocol_dist),
            'top_source_ips': [{'ip': ip, 'packets': count} for ip, count in top_src_ips],
            'top_destination_ips': [{'ip': ip, 'packets': count} for ip, count in top_dst_ips],
            'timestamp': now.isoformat()
        }

class IntrusionDetectionSystem:
    """Network-based intrusion detection system."""
    
    def __init__(self):
        self.rules = self._load_detection_rules()
        self.alerts: List[NetworkAlert] = []
        self.alert_stats = defaultdict(int)
        
    def _load_detection_rules(self) -> Dict[str, Any]:
        """Load intrusion detection rules."""
        return {
            'port_scan': {
                'description': 'Port scan detection',
                'threshold': 10,  # connections to different ports
                'time_window': 60,  # seconds
                'severity': AlertSeverity.MEDIUM
            },
            'syn_flood': {
                'description': 'SYN flood attack',
                'threshold': 100,  # SYN packets
                'time_window': 10,  # seconds
                'severity': AlertSeverity.HIGH
            },
            'dns_tunneling': {
                'description': 'DNS tunneling detection',
                'threshold': 50,  # DNS queries
                'time_window': 60,  # seconds
                'severity': AlertSeverity.MEDIUM
            },
            'large_upload': {
                'description': 'Large data upload',
                'threshold': 100 * 1024 * 1024,  # 100MB
                'time_window': 300,  # 5 minutes
                'severity': AlertSeverity.LOW
            },
            'suspicious_user_agent': {
                'description': 'Suspicious user agent',
                'patterns': ['sqlmap', 'nikto', 'nmap', 'masscan', 'burp'],
                'severity': AlertSeverity.HIGH
            },
            'brute_force': {
                'description': 'Brute force attack',
                'threshold': 20,  # failed attempts
                'time_window': 300,  # 5 minutes
                'severity': AlertSeverity.HIGH
            }
        }
    
    def analyze_flow(self, flow: NetworkFlow) -> List[NetworkAlert]:
        """Analyze network flow for intrusions."""
        alerts = []
        
        try:
            # Port scan detection
            port_scan_alert = self._detect_port_scan(flow)
            if port_scan_alert:
                alerts.append(port_scan_alert)
            
            # SYN flood detection
            syn_flood_alert = self._detect_syn_flood(flow)
            if syn_flood_alert:
                alerts.append(syn_flood_alert)
            
            # Large data transfer detection
            large_transfer_alert = self._detect_large_transfer(flow)
            if large_transfer_alert:
                alerts.append(large_transfer_alert)
            
            # Store alerts
            for alert in alerts:
                self.alerts.append(alert)
                self.alert_stats[alert.alert_type] += 1
            
            # Limit stored alerts
            if len(self.alerts) > 10000:
                self.alerts = self.alerts[-10000:]
            
        except Exception as e:
            logger.error(f"Flow analysis error: {e}")
        
        return alerts
    
    def analyze_packet(self, packet_analysis: Dict[str, Any]) -> List[NetworkAlert]:
        """Analyze packet for intrusions."""
        alerts = []
        
        try:
            # Suspicious user agent detection
            if 'user_agent' in packet_analysis.get('metadata', {}):
                user_agent_alert = self._detect_suspicious_user_agent(packet_analysis)
                if user_agent_alert:
                    alerts.append(user_agent_alert)
            
            # Suspicious payload detection
            suspicious_content = packet_analysis.get('suspicious_content', [])
            if suspicious_content:
                payload_alert = self._create_payload_alert(packet_analysis, suspicious_content)
                alerts.append(payload_alert)
            
            # Store alerts
            for alert in alerts:
                self.alerts.append(alert)
                self.alert_stats[alert.alert_type] += 1
            
        except Exception as e:
            logger.error(f"Packet analysis error: {e}")
        
        return alerts
    
    def _detect_port_scan(self, flow: NetworkFlow) -> Optional[NetworkAlert]:
        """Detect port scanning activity."""
        # This is a simplified implementation
        # In practice, you'd track connections across multiple flows
        return None
    
    def _detect_syn_flood(self, flow: NetworkFlow) -> Optional[NetworkAlert]:
        """Detect SYN flood attacks."""
        if (flow.protocol == ProtocolType.TCP and 
            'SYN' in flow.flags and 
            flow.packet_count > 50 and 
            flow.duration < 10):
            
            return NetworkAlert(
                alert_id=f"syn_flood_{int(time.time())}",
                timestamp=datetime.utcnow(),
                severity=AlertSeverity.HIGH,
                alert_type="syn_flood",
                source_ip=flow.src_ip,
                destination_ip=flow.dst_ip,
                protocol=flow.protocol,
                description=f"Potential SYN flood from {flow.src_ip}",
                details={
                    'packet_count': flow.packet_count,
                    'duration': flow.duration,
                    'flags': list(flow.flags)
                },
                flow_id=flow.flow_id
            )
        
        return None
    
    def _detect_large_transfer(self, flow: NetworkFlow) -> Optional[NetworkAlert]:
        """Detect large data transfers."""
        threshold = self.rules['large_upload']['threshold']
        
        if flow.byte_count > threshold:
            return NetworkAlert(
                alert_id=f"large_transfer_{int(time.time())}",
                timestamp=datetime.utcnow(),
                severity=AlertSeverity.LOW,
                alert_type="large_transfer",
                source_ip=flow.src_ip,
                destination_ip=flow.dst_ip,
                protocol=flow.protocol,
                description=f"Large data transfer detected: {flow.byte_count} bytes",
                details={
                    'byte_count': flow.byte_count,
                    'packet_count': flow.packet_count,
                    'duration': flow.duration
                },
                flow_id=flow.flow_id
            )
        
        return None
    
    def _detect_suspicious_user_agent(self, packet_analysis: Dict[str, Any]) -> Optional[NetworkAlert]:
        """Detect suspicious user agents."""
        user_agent = packet_analysis.get('metadata', {}).get('user_agent', '').lower()
        suspicious_patterns = self.rules['suspicious_user_agent']['patterns']
        
        for pattern in suspicious_patterns:
            if pattern in user_agent:
                return NetworkAlert(
                    alert_id=f"suspicious_ua_{int(time.time())}",
                    timestamp=datetime.utcnow(),
                    severity=AlertSeverity.HIGH,
                    alert_type="suspicious_user_agent",
                    source_ip=packet_analysis.get('src_ip', ''),
                    destination_ip=packet_analysis.get('dst_ip', ''),
                    protocol=ProtocolType.HTTP,
                    description=f"Suspicious user agent detected: {pattern}",
                    details={
                        'user_agent': user_agent,
                        'pattern_matched': pattern
                    }
                )
        
        return None
    
    def _create_payload_alert(self, packet_analysis: Dict[str, Any], suspicious_content: List[Dict[str, Any]]) -> NetworkAlert:
        """Create alert for suspicious payload content."""
        categories = [content['category'] for content in suspicious_content]
        
        return NetworkAlert(
            alert_id=f"suspicious_payload_{int(time.time())}",
            timestamp=datetime.utcnow(),
            severity=AlertSeverity.MEDIUM,
            alert_type="suspicious_payload",
            source_ip=packet_analysis.get('src_ip', ''),
            destination_ip=packet_analysis.get('dst_ip', ''),
            protocol=ProtocolType.HTTP,
            description=f"Suspicious payload detected: {', '.join(set(categories))}",
            details={
                'suspicious_content': suspicious_content,
                'packet_size': packet_analysis.get('size', 0)
            }
        )
    
    def get_alert_statistics(self) -> Dict[str, Any]:
        """Get alert statistics."""
        now = datetime.utcnow()
        last_24h = now - timedelta(hours=24)
        recent_alerts = [alert for alert in self.alerts if alert.timestamp > last_24h]
        
        # Severity distribution
        severity_dist = defaultdict(int)
        for alert in recent_alerts:
            severity_dist[alert.severity.value] += 1
        
        # Alert type distribution
        type_dist = defaultdict(int)
        for alert in recent_alerts:
            type_dist[alert.alert_type] += 1
        
        return {
            'total_alerts': len(self.alerts),
            'alerts_last_24h': len(recent_alerts),
            'severity_distribution': dict(severity_dist),
            'alert_type_distribution': dict(type_dist),
            'top_source_ips': self._get_top_alert_ips(recent_alerts, 'source_ip'),
            'timestamp': now.isoformat()
        }
    
    def _get_top_alert_ips(self, alerts: List[NetworkAlert], ip_field: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top IPs by alert count."""
        ip_counts = defaultdict(int)
        for alert in alerts:
            ip = getattr(alert, ip_field, '')
            if ip:
                ip_counts[ip] += 1
        
        return [
            {'ip': ip, 'count': count}
            for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        ]

class NetworkSecurityMonitor:
    """Main network security monitoring system."""
    
    def __init__(self):
        self.packet_analyzer = PacketAnalyzer()
        self.flow_tracker = NetworkFlowTracker()
        self.ids = IntrusionDetectionSystem()
        self.running = False
        
        # Statistics
        self.packet_count = 0
        self.start_time = None
        
    async def start(self):
        """Start network monitoring."""
        logger.info("Starting network security monitor...")
        self.running = True
        self.start_time = datetime.utcnow()
        
        # Start background tasks
        asyncio.create_task(self._cleanup_loop())
        
        logger.info("Network security monitor started")
    
    async def stop(self):
        """Stop network monitoring."""
        logger.info("Stopping network security monitor...")
        self.running = False
    
    async def _cleanup_loop(self):
        """Background cleanup loop."""
        while self.running:
            try:
                await asyncio.sleep(60)  # Cleanup every minute
                self.flow_tracker.cleanup_expired_flows()
            except Exception as e:
                logger.error(f"Cleanup loop error: {e}")
    
    async def process_packet(self, packet_data: bytes) -> Dict[str, Any]:
        """Process network packet."""
        try:
            self.packet_count += 1
            
            # Analyze packet
            packet_analysis = self.packet_analyzer.analyze_packet(packet_data)
            
            # Update flow tracking
            flow = self.flow_tracker.update_flow(packet_analysis)
            
            # Run intrusion detection
            packet_alerts = self.ids.analyze_packet(packet_analysis)
            flow_alerts = []
            
            if flow:
                flow_alerts = self.ids.analyze_flow(flow)
            
            all_alerts = packet_alerts + flow_alerts
            
            # Log alerts
            for alert in all_alerts:
                logger.warning(f"Security Alert: {alert.description}")
            
            return {
                'packet_analysis': packet_analysis,
                'flow': flow.to_dict() if flow else None,
                'alerts': [alert.to_dict() for alert in all_alerts],
                'packet_count': self.packet_count
            }
            
        except Exception as e:
            logger.error(f"Packet processing error: {e}")
            return {}
    
    def get_monitoring_statistics(self) -> Dict[str, Any]:
        """Get comprehensive monitoring statistics."""
        uptime = None
        if self.start_time:
            uptime = (datetime.utcnow() - self.start_time).total_seconds()
        
        return {
            'uptime_seconds': uptime,
            'packets_processed': self.packet_count,
            'packets_per_second': self.packet_count / uptime if uptime else 0,
            'flow_statistics': self.flow_tracker.get_flow_statistics(),
            'alert_statistics': self.ids.get_alert_statistics(),
            'timestamp': datetime.utcnow().isoformat()
        }

# Global network security monitor
network_security_monitor = NetworkSecurityMonitor()

# Export network monitoring components
__all__ = [
    'ProtocolType',
    'AlertSeverity',
    'NetworkFlow',
    'NetworkAlert',
    'PacketAnalyzer',
    'NetworkFlowTracker',
    'IntrusionDetectionSystem',
    'NetworkSecurityMonitor',
    'network_security_monitor'
]

