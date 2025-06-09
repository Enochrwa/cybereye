# Comprehensive Test Suite for eCyber Security Platform

import pytest
import asyncio
import json
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Import application modules
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from main import app
from app.core.security import create_access_token, verify_password, get_password_hash
from app.core.config import settings
from app.database import get_db
from app.models.user import User
from app.features.threat_intelligence import ThreatIntelligenceEngine, ThreatIndicator, ThreatType, ThreatLevel
from app.features.network_monitoring import NetworkSecurityMonitor, PacketAnalyzer
from app.features.siem import SIEMSystem, SecurityEvent, EventType, EventSeverity

# Test configuration
TEST_DATABASE_URL = "sqlite+aiosqlite:///./test.db"

class TestConfig:
    """Test configuration."""
    DATABASE_URL = TEST_DATABASE_URL
    SECRET_KEY = "test-secret-key"
    JWT_SECRET_KEY = "test-jwt-secret"
    TESTING = True

@pytest.fixture
def client():
    """Create test client."""
    with TestClient(app) as c:
        yield c

@pytest.fixture
async def db_session():
    """Create test database session."""
    engine = create_engine(TEST_DATABASE_URL, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    async with async_session() as session:
        yield session

@pytest.fixture
def test_user_data():
    """Test user data."""
    return {
        "username": "testuser",
        "email": "test@example.com",
        "password": "testpassword123",
        "full_name": "Test User"
    }

@pytest.fixture
def auth_headers(client, test_user_data):
    """Create authentication headers."""
    # Create user
    response = client.post("/api/auth/register", json=test_user_data)
    assert response.status_code == 201
    
    # Login
    login_data = {
        "username": test_user_data["username"],
        "password": test_user_data["password"]
    }
    response = client.post("/api/auth/login", data=login_data)
    assert response.status_code == 200
    
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

class TestAuthentication:
    """Test authentication functionality."""
    
    def test_user_registration(self, client, test_user_data):
        """Test user registration."""
        response = client.post("/api/auth/register", json=test_user_data)
        assert response.status_code == 201
        
        data = response.json()
        assert data["username"] == test_user_data["username"]
        assert data["email"] == test_user_data["email"]
        assert "id" in data
    
    def test_user_registration_duplicate_email(self, client, test_user_data):
        """Test registration with duplicate email."""
        # First registration
        response = client.post("/api/auth/register", json=test_user_data)
        assert response.status_code == 201
        
        # Second registration with same email
        response = client.post("/api/auth/register", json=test_user_data)
        assert response.status_code == 400
    
    def test_user_login(self, client, test_user_data):
        """Test user login."""
        # Register user first
        client.post("/api/auth/register", json=test_user_data)
        
        # Login
        login_data = {
            "username": test_user_data["username"],
            "password": test_user_data["password"]
        }
        response = client.post("/api/auth/login", data=login_data)
        assert response.status_code == 200
        
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
    
    def test_user_login_invalid_credentials(self, client, test_user_data):
        """Test login with invalid credentials."""
        login_data = {
            "username": "nonexistent",
            "password": "wrongpassword"
        }
        response = client.post("/api/auth/login", data=login_data)
        assert response.status_code == 401
    
    def test_protected_endpoint_without_token(self, client):
        """Test accessing protected endpoint without token."""
        response = client.get("/api/users/me")
        assert response.status_code == 401
    
    def test_protected_endpoint_with_token(self, client, auth_headers):
        """Test accessing protected endpoint with valid token."""
        response = client.get("/api/users/me", headers=auth_headers)
        assert response.status_code == 200
        
        data = response.json()
        assert "username" in data
        assert "email" in data
    
    def test_password_hashing(self):
        """Test password hashing functionality."""
        password = "testpassword123"
        hashed = get_password_hash(password)
        
        assert hashed != password
        assert verify_password(password, hashed)
        assert not verify_password("wrongpassword", hashed)
    
    def test_jwt_token_creation(self):
        """Test JWT token creation and validation."""
        user_data = {"sub": "testuser", "user_id": 1}
        token = create_access_token(data=user_data)
        
        assert isinstance(token, str)
        assert len(token) > 0

class TestThreatIntelligence:
    """Test threat intelligence functionality."""
    
    @pytest.fixture
    def threat_engine(self):
        """Create threat intelligence engine."""
        return ThreatIntelligenceEngine()
    
    def test_threat_indicator_creation(self):
        """Test threat indicator creation."""
        indicator = ThreatIndicator(
            id="test-indicator-1",
            type=ThreatType.MALWARE,
            value="192.168.1.100",
            confidence=0.8,
            severity=ThreatLevel.HIGH,
            source="test",
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            tags=["test"],
            context={"test": "data"}
        )
        
        assert indicator.id == "test-indicator-1"
        assert indicator.type == ThreatType.MALWARE
        assert indicator.confidence == 0.8
    
    @pytest.mark.asyncio
    async def test_threat_intelligence_feeds(self, threat_engine):
        """Test threat intelligence feed processing."""
        # Mock feed data
        mock_feed_data = [
            {"ip": "192.168.1.100", "type": "malware"},
            {"ip": "10.0.0.1", "type": "botnet"}
        ]
        
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value=json.dumps(mock_feed_data))
            mock_get.return_value.__aenter__.return_value = mock_response
            
            await threat_engine.feeds.update_feeds()
            
            assert len(threat_engine.feeds.indicators) > 0
    
    @pytest.mark.asyncio
    async def test_network_event_analysis(self, threat_engine):
        """Test network event analysis."""
        network_data = {
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "src_port": 80,
            "dst_port": 443,
            "protocol": "tcp",
            "packet_count": 100,
            "byte_count": 50000,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Add a test indicator
        test_indicator = ThreatIndicator(
            id="test-malware-ip",
            type=ThreatType.MALWARE,
            value="192.168.1.100",
            confidence=0.9,
            severity=ThreatLevel.HIGH,
            source="test",
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            tags=["malware"],
            context={}
        )
        threat_engine.feeds.indicators[test_indicator.id] = test_indicator
        
        threat_event = await threat_engine.analyze_network_event(network_data)
        
        assert threat_event is not None
        assert threat_event.source_ip == "192.168.1.100"
        assert len(threat_event.indicators) > 0
    
    def test_behavioral_analyzer_feature_extraction(self, threat_engine):
        """Test behavioral analyzer feature extraction."""
        network_data = {
            "packet_count": 100,
            "byte_count": 50000,
            "duration": 30.5,
            "src_port": 80,
            "dst_port": 443,
            "protocol": "tcp",
            "timestamp": datetime.utcnow()
        }
        
        features = threat_engine.behavioral_analyzer.extract_features(network_data)
        
        assert features.shape == (1, 10)  # Expected feature count
        assert features[0][0] == 100  # packet_count
        assert features[0][1] == 50000  # byte_count

class TestNetworkMonitoring:
    """Test network monitoring functionality."""
    
    @pytest.fixture
    def network_monitor(self):
        """Create network security monitor."""
        return NetworkSecurityMonitor()
    
    @pytest.fixture
    def packet_analyzer(self):
        """Create packet analyzer."""
        return PacketAnalyzer()
    
    def test_packet_analyzer_basic(self, packet_analyzer):
        """Test basic packet analysis."""
        # Mock packet data
        packet_data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        
        analysis = packet_analyzer.analyze_packet(packet_data)
        
        assert "timestamp" in analysis
        assert "size" in analysis
        assert analysis["size"] == len(packet_data)
    
    def test_suspicious_pattern_detection(self, packet_analyzer):
        """Test suspicious pattern detection."""
        # SQL injection payload
        malicious_payload = b"GET /?id=1' UNION SELECT * FROM users-- HTTP/1.1\r\n"
        
        analysis = packet_analyzer.analyze_packet(malicious_payload)
        
        assert "suspicious_content" in analysis
        # Should detect SQL injection pattern
        suspicious_categories = [item["category"] for item in analysis["suspicious_content"]]
        assert "sql_injection" in suspicious_categories
    
    @pytest.mark.asyncio
    async def test_network_flow_tracking(self, network_monitor):
        """Test network flow tracking."""
        packet_analysis = {
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "src_port": 12345,
            "dst_port": 80,
            "protocols": ["TCP"],
            "size": 1500,
            "tcp_flags": ["SYN"]
        }
        
        flow = network_monitor.flow_tracker.update_flow(packet_analysis)
        
        assert flow is not None
        assert flow.src_ip == "192.168.1.100"
        assert flow.dst_ip == "10.0.0.1"
        assert flow.packet_count == 1
        assert flow.byte_count == 1500
    
    @pytest.mark.asyncio
    async def test_intrusion_detection(self, network_monitor):
        """Test intrusion detection system."""
        # Simulate suspicious HTTP request
        packet_analysis = {
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "protocols": ["HTTP"],
            "metadata": {
                "user_agent": "sqlmap/1.0"
            },
            "suspicious_content": [
                {"category": "sql_injection", "pattern": "union select"}
            ]
        }
        
        alerts = network_monitor.ids.analyze_packet(packet_analysis)
        
        assert len(alerts) > 0
        assert any(alert.alert_type == "suspicious_user_agent" for alert in alerts)

class TestSIEM:
    """Test SIEM functionality."""
    
    @pytest.fixture
    def siem_system(self):
        """Create SIEM system."""
        return SIEMSystem()
    
    def test_security_event_creation(self):
        """Test security event creation."""
        event = SecurityEvent(
            event_id="test-event-1",
            timestamp=datetime.utcnow(),
            source="test",
            event_type=EventType.AUTHENTICATION,
            severity=EventSeverity.WARNING,
            message="Test authentication event",
            details={"test": "data"},
            user_id="user123",
            ip_address="192.168.1.100"
        )
        
        assert event.event_id == "test-event-1"
        assert event.event_type == EventType.AUTHENTICATION
        assert event.severity == EventSeverity.WARNING
    
    def test_log_parsing_apache(self, siem_system):
        """Test Apache log parsing."""
        apache_log = '192.168.1.100 - - [25/Dec/2023:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234'
        
        event = siem_system.event_processor.process_raw_event(apache_log, "apache")
        
        assert event is not None
        assert event.ip_address == "192.168.1.100"
        assert event.details["method"] == "GET"
        assert event.details["status_code"] == 200
    
    def test_log_parsing_json(self, siem_system):
        """Test JSON log parsing."""
        json_log = json.dumps({
            "timestamp": "2023-12-25T10:00:00Z",
            "level": "error",
            "message": "Authentication failed",
            "user_id": "user123",
            "ip_address": "192.168.1.100"
        })
        
        event = siem_system.event_processor.process_raw_event(json_log, "application")
        
        assert event is not None
        assert event.severity == EventSeverity.ERROR
        assert event.user_id == "user123"
        assert event.ip_address == "192.168.1.100"
    
    @pytest.mark.asyncio
    async def test_event_correlation(self, siem_system):
        """Test event correlation."""
        # Create multiple failed login events
        base_time = datetime.utcnow()
        
        for i in range(6):  # Exceed threshold of 5
            event = SecurityEvent(
                event_id=f"login-fail-{i}",
                timestamp=base_time + timedelta(seconds=i),
                source="auth",
                event_type=EventType.AUTHENTICATION,
                severity=EventSeverity.WARNING,
                message="Login failed",
                details={"reason": "invalid_password"},
                ip_address="192.168.1.100"
            )
            
            correlations = siem_system.event_correlator.process_event(event)
            
            if i >= 4:  # Should trigger correlation after 5th event
                assert len(correlations) > 0
                assert correlations[0]["rule_id"] == "brute_force_login"
    
    def test_dashboard_data(self, siem_system):
        """Test dashboard data generation."""
        # Add some test events
        events = [
            SecurityEvent(
                event_id=f"test-{i}",
                timestamp=datetime.utcnow() - timedelta(hours=i),
                source="test",
                event_type=EventType.SECURITY,
                severity=EventSeverity.HIGH if i % 2 == 0 else EventSeverity.LOW,
                message=f"Test event {i}",
                details={}
            )
            for i in range(10)
        ]
        
        siem_system.event_store.extend(events)
        
        dashboard_data = siem_system.get_dashboard_data(24)
        
        assert "summary" in dashboard_data
        assert "severity_distribution" in dashboard_data
        assert "event_type_distribution" in dashboard_data
        assert dashboard_data["summary"]["total_events"] == 10

class TestAPI:
    """Test API endpoints."""
    
    def test_health_endpoint(self, client):
        """Test health check endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        
        data = response.json()
        assert data["status"] == "healthy"
    
    def test_metrics_endpoint(self, client, auth_headers):
        """Test metrics endpoint."""
        response = client.get("/api/metrics", headers=auth_headers)
        assert response.status_code == 200
    
    def test_threat_intelligence_endpoint(self, client, auth_headers):
        """Test threat intelligence endpoint."""
        response = client.get("/api/threat-intelligence/statistics", headers=auth_headers)
        assert response.status_code == 200
        
        data = response.json()
        assert "indicators_count" in data
    
    def test_network_monitoring_endpoint(self, client, auth_headers):
        """Test network monitoring endpoint."""
        response = client.get("/api/network/statistics", headers=auth_headers)
        assert response.status_code == 200
        
        data = response.json()
        assert "packets_processed" in data
    
    def test_siem_dashboard_endpoint(self, client, auth_headers):
        """Test SIEM dashboard endpoint."""
        response = client.get("/api/siem/dashboard", headers=auth_headers)
        assert response.status_code == 200
        
        data = response.json()
        assert "summary" in data
        assert "severity_distribution" in data

class TestPerformance:
    """Test performance and load handling."""
    
    @pytest.mark.asyncio
    async def test_concurrent_requests(self, client, auth_headers):
        """Test handling concurrent requests."""
        import asyncio
        import aiohttp
        
        async def make_request():
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "http://localhost:8000/api/users/me",
                    headers=auth_headers
                ) as response:
                    return response.status
        
        # Make 10 concurrent requests
        tasks = [make_request() for _ in range(10)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Most requests should succeed
        success_count = sum(1 for result in results if result == 200)
        assert success_count >= 8  # Allow for some failures
    
    def test_large_payload_handling(self, client, auth_headers):
        """Test handling of large payloads."""
        large_data = {"data": "x" * 10000}  # 10KB payload
        
        response = client.post(
            "/api/siem/events",
            json=large_data,
            headers=auth_headers
        )
        
        # Should handle large payload gracefully
        assert response.status_code in [200, 201, 413]  # 413 = Payload Too Large
    
    def test_rate_limiting(self, client, auth_headers):
        """Test rate limiting functionality."""
        # Make many requests quickly
        responses = []
        for i in range(150):  # Exceed rate limit
            response = client.get("/api/users/me", headers=auth_headers)
            responses.append(response.status_code)
        
        # Should eventually get rate limited
        assert 429 in responses  # 429 = Too Many Requests

class TestSecurity:
    """Test security features."""
    
    def test_sql_injection_protection(self, client, auth_headers):
        """Test SQL injection protection."""
        malicious_input = "'; DROP TABLE users; --"
        
        response = client.get(
            f"/api/users/search?q={malicious_input}",
            headers=auth_headers
        )
        
        # Should not cause server error
        assert response.status_code != 500
    
    def test_xss_protection(self, client, auth_headers):
        """Test XSS protection."""
        xss_payload = "<script>alert('xss')</script>"
        
        response = client.post(
            "/api/users/profile",
            json={"bio": xss_payload},
            headers=auth_headers
        )
        
        # Should sanitize or reject XSS payload
        if response.status_code == 200:
            data = response.json()
            assert "<script>" not in data.get("bio", "")
    
    def test_csrf_protection(self, client):
        """Test CSRF protection."""
        # Attempt to make state-changing request without proper headers
        response = client.post("/api/auth/logout")
        
        # Should require authentication
        assert response.status_code == 401
    
    def test_input_validation(self, client):
        """Test input validation."""
        invalid_data = {
            "username": "",  # Empty username
            "email": "invalid-email",  # Invalid email format
            "password": "123"  # Too short password
        }
        
        response = client.post("/api/auth/register", json=invalid_data)
        assert response.status_code == 422  # Validation error

# Test configuration and fixtures
@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

# Performance benchmarks
class TestBenchmarks:
    """Performance benchmarks."""
    
    def test_authentication_performance(self, client, test_user_data):
        """Benchmark authentication performance."""
        # Register user
        client.post("/api/auth/register", json=test_user_data)
        
        login_data = {
            "username": test_user_data["username"],
            "password": test_user_data["password"]
        }
        
        start_time = time.time()
        
        # Perform 100 login operations
        for _ in range(100):
            response = client.post("/api/auth/login", data=login_data)
            assert response.status_code == 200
        
        end_time = time.time()
        avg_time = (end_time - start_time) / 100
        
        # Should complete login in reasonable time
        assert avg_time < 0.1  # Less than 100ms per login
    
    def test_threat_detection_performance(self):
        """Benchmark threat detection performance."""
        from app.features.threat_intelligence import ThreatIntelligenceEngine
        
        engine = ThreatIntelligenceEngine()
        
        # Create test network data
        network_data = {
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "src_port": 80,
            "dst_port": 443,
            "protocol": "tcp",
            "packet_count": 100,
            "byte_count": 50000,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        start_time = time.time()
        
        # Analyze 1000 network events
        for _ in range(1000):
            asyncio.run(engine.analyze_network_event(network_data))
        
        end_time = time.time()
        avg_time = (end_time - start_time) / 1000
        
        # Should analyze events quickly
        assert avg_time < 0.01  # Less than 10ms per event

if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v", "--tb=short"])

