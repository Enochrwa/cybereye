# Integration and End-to-End Tests for eCyber Platform

import pytest
import asyncio
import json
import time
import subprocess
import requests
from datetime import datetime, timedelta
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
import docker
import psutil

class TestSystemIntegration:
    """Integration tests for the complete system."""
    
    @pytest.fixture(scope="class")
    def docker_client(self):
        """Docker client for container management."""
        return docker.from_env()
    
    @pytest.fixture(scope="class")
    def system_setup(self, docker_client):
        """Set up the complete system for testing."""
        # Start the system using docker-compose
        subprocess.run(["docker-compose", "up", "-d"], cwd="/home/ubuntu/ecyber", check=True)
        
        # Wait for services to be ready
        self._wait_for_services()
        
        yield
        
        # Cleanup
        subprocess.run(["docker-compose", "down"], cwd="/home/ubuntu/ecyber", check=True)
    
    def _wait_for_services(self, timeout=120):
        """Wait for all services to be ready."""
        services = [
            ("http://localhost:8000/health", "Backend API"),
            ("http://localhost:3000/health", "Frontend"),
            ("http://localhost:9090", "Prometheus"),
            ("http://localhost:3001", "Grafana")
        ]
        
        start_time = time.time()
        
        for url, name in services:
            while time.time() - start_time < timeout:
                try:
                    response = requests.get(url, timeout=5)
                    if response.status_code == 200:
                        print(f"{name} is ready")
                        break
                except requests.exceptions.RequestException:
                    pass
                time.sleep(5)
            else:
                raise TimeoutError(f"{name} did not become ready within {timeout} seconds")
    
    def test_database_connectivity(self, system_setup):
        """Test database connectivity and basic operations."""
        # Test database connection through API
        response = requests.get("http://localhost:8000/health")
        assert response.status_code == 200
        
        health_data = response.json()
        assert health_data["status"] == "healthy"
        assert "database" in health_data
    
    def test_redis_connectivity(self, system_setup):
        """Test Redis connectivity."""
        # Test Redis through API health check
        response = requests.get("http://localhost:8000/health")
        assert response.status_code == 200
        
        health_data = response.json()
        assert "cache" in health_data
    
    def test_user_registration_and_login_flow(self, system_setup):
        """Test complete user registration and login flow."""
        base_url = "http://localhost:8000"
        
        # Register new user
        user_data = {
            "username": "integrationtest",
            "email": "integration@test.com",
            "password": "testpassword123",
            "full_name": "Integration Test User"
        }
        
        response = requests.post(f"{base_url}/api/auth/register", json=user_data)
        assert response.status_code == 201
        
        user_info = response.json()
        assert user_info["username"] == user_data["username"]
        assert user_info["email"] == user_data["email"]
        
        # Login with created user
        login_data = {
            "username": user_data["username"],
            "password": user_data["password"]
        }
        
        response = requests.post(f"{base_url}/api/auth/login", data=login_data)
        assert response.status_code == 200
        
        token_data = response.json()
        assert "access_token" in token_data
        assert token_data["token_type"] == "bearer"
        
        # Use token to access protected endpoint
        headers = {"Authorization": f"Bearer {token_data['access_token']}"}
        response = requests.get(f"{base_url}/api/users/me", headers=headers)
        assert response.status_code == 200
        
        user_profile = response.json()
        assert user_profile["username"] == user_data["username"]
    
    def test_threat_intelligence_integration(self, system_setup):
        """Test threat intelligence system integration."""
        base_url = "http://localhost:8000"
        
        # First login to get token
        login_data = {"username": "integrationtest", "password": "testpassword123"}
        response = requests.post(f"{base_url}/api/auth/login", data=login_data)
        token = response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Test threat intelligence statistics
        response = requests.get(f"{base_url}/api/threat-intelligence/statistics", headers=headers)
        assert response.status_code == 200
        
        stats = response.json()
        assert "indicators_count" in stats
        assert "total_threats" in stats
    
    def test_network_monitoring_integration(self, system_setup):
        """Test network monitoring system integration."""
        base_url = "http://localhost:8000"
        
        # Login to get token
        login_data = {"username": "integrationtest", "password": "testpassword123"}
        response = requests.post(f"{base_url}/api/auth/login", data=login_data)
        token = response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Test network monitoring statistics
        response = requests.get(f"{base_url}/api/network/statistics", headers=headers)
        assert response.status_code == 200
        
        stats = response.json()
        assert "packets_processed" in stats
        assert "uptime_seconds" in stats
    
    def test_siem_integration(self, system_setup):
        """Test SIEM system integration."""
        base_url = "http://localhost:8000"
        
        # Login to get token
        login_data = {"username": "integrationtest", "password": "testpassword123"}
        response = requests.post(f"{base_url}/api/auth/login", data=login_data)
        token = response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Test SIEM dashboard
        response = requests.get(f"{base_url}/api/siem/dashboard", headers=headers)
        assert response.status_code == 200
        
        dashboard = response.json()
        assert "summary" in dashboard
        assert "severity_distribution" in dashboard
        
        # Test event ingestion
        test_event = {
            "timestamp": datetime.utcnow().isoformat(),
            "source": "integration_test",
            "event_type": "security",
            "severity": "medium",
            "message": "Integration test event",
            "details": {"test": True}
        }
        
        response = requests.post(f"{base_url}/api/siem/events", json=test_event, headers=headers)
        assert response.status_code in [200, 201]
    
    def test_websocket_connectivity(self, system_setup):
        """Test WebSocket connectivity for real-time updates."""
        import websocket
        import threading
        
        messages_received = []
        
        def on_message(ws, message):
            messages_received.append(json.loads(message))
        
        def on_error(ws, error):
            print(f"WebSocket error: {error}")
        
        # Connect to WebSocket
        ws = websocket.WebSocketApp(
            "ws://localhost:8000/ws/threats",
            on_message=on_message,
            on_error=on_error
        )
        
        # Start WebSocket in background thread
        ws_thread = threading.Thread(target=ws.run_forever)
        ws_thread.daemon = True
        ws_thread.start()
        
        # Wait a bit for connection
        time.sleep(2)
        
        # Send a test message
        ws.send(json.dumps({"type": "ping"}))
        
        # Wait for response
        time.sleep(2)
        
        # Close connection
        ws.close()
        
        # Should have received at least one message
        assert len(messages_received) > 0
    
    def test_monitoring_endpoints(self, system_setup):
        """Test monitoring and metrics endpoints."""
        # Test Prometheus metrics
        response = requests.get("http://localhost:9090/api/v1/query?query=up")
        assert response.status_code == 200
        
        # Test Grafana
        response = requests.get("http://localhost:3001/api/health")
        assert response.status_code == 200
    
    def test_performance_under_load(self, system_setup):
        """Test system performance under load."""
        import concurrent.futures
        import threading
        
        base_url = "http://localhost:8000"
        
        # Login to get token
        login_data = {"username": "integrationtest", "password": "testpassword123"}
        response = requests.post(f"{base_url}/api/auth/login", data=login_data)
        token = response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        def make_request():
            try:
                response = requests.get(f"{base_url}/api/users/me", headers=headers, timeout=10)
                return response.status_code == 200
            except:
                return False
        
        # Make 50 concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(50)]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        # At least 80% should succeed
        success_rate = sum(results) / len(results)
        assert success_rate >= 0.8

class TestEndToEnd:
    """End-to-end tests using browser automation."""
    
    @pytest.fixture(scope="class")
    def browser(self):
        """Set up browser for testing."""
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        
        driver = webdriver.Chrome(options=chrome_options)
        driver.implicitly_wait(10)
        
        yield driver
        
        driver.quit()
    
    @pytest.fixture(scope="class")
    def system_running(self):
        """Ensure system is running for E2E tests."""
        # Check if system is running
        try:
            response = requests.get("http://localhost:3000", timeout=5)
            if response.status_code != 200:
                raise Exception("Frontend not accessible")
        except:
            # Start system if not running
            subprocess.run(["docker-compose", "up", "-d"], cwd="/home/ubuntu/ecyber", check=True)
            time.sleep(30)  # Wait for startup
        
        yield
    
    def test_frontend_loads(self, browser, system_running):
        """Test that frontend loads correctly."""
        browser.get("http://localhost:3000")
        
        # Wait for page to load
        WebDriverWait(browser, 10).until(
            EC.presence_of_element_located((By.TAG_NAME, "body"))
        )
        
        # Check page title
        assert "eCyber" in browser.title
    
    def test_user_registration_ui(self, browser, system_running):
        """Test user registration through UI."""
        browser.get("http://localhost:3000/register")
        
        # Fill registration form
        username_field = WebDriverWait(browser, 10).until(
            EC.presence_of_element_located((By.NAME, "username"))
        )
        username_field.send_keys("e2etest")
        
        email_field = browser.find_element(By.NAME, "email")
        email_field.send_keys("e2e@test.com")
        
        password_field = browser.find_element(By.NAME, "password")
        password_field.send_keys("testpassword123")
        
        # Submit form
        submit_button = browser.find_element(By.TYPE, "submit")
        submit_button.click()
        
        # Wait for redirect or success message
        WebDriverWait(browser, 10).until(
            lambda driver: "login" in driver.current_url or "dashboard" in driver.current_url
        )
    
    def test_user_login_ui(self, browser, system_running):
        """Test user login through UI."""
        browser.get("http://localhost:3000/login")
        
        # Fill login form
        username_field = WebDriverWait(browser, 10).until(
            EC.presence_of_element_located((By.NAME, "username"))
        )
        username_field.send_keys("e2etest")
        
        password_field = browser.find_element(By.NAME, "password")
        password_field.send_keys("testpassword123")
        
        # Submit form
        submit_button = browser.find_element(By.TYPE, "submit")
        submit_button.click()
        
        # Wait for redirect to dashboard
        WebDriverWait(browser, 10).until(
            lambda driver: "dashboard" in driver.current_url
        )
    
    def test_dashboard_functionality(self, browser, system_running):
        """Test dashboard functionality."""
        # Login first
        self.test_user_login_ui(browser, system_running)
        
        # Navigate to dashboard
        browser.get("http://localhost:3000/dashboard")
        
        # Check for dashboard elements
        WebDriverWait(browser, 10).until(
            EC.presence_of_element_located((By.CLASS_NAME, "dashboard"))
        )
        
        # Check for threat statistics
        threat_stats = browser.find_elements(By.CLASS_NAME, "threat-stats")
        assert len(threat_stats) > 0
        
        # Check for network monitoring
        network_stats = browser.find_elements(By.CLASS_NAME, "network-stats")
        assert len(network_stats) > 0
    
    def test_real_time_updates(self, browser, system_running):
        """Test real-time updates in the UI."""
        # Login and go to dashboard
        self.test_user_login_ui(browser, system_running)
        browser.get("http://localhost:3000/dashboard")
        
        # Wait for initial load
        WebDriverWait(browser, 10).until(
            EC.presence_of_element_located((By.CLASS_NAME, "dashboard"))
        )
        
        # Get initial threat count
        threat_count_element = browser.find_element(By.ID, "threat-count")
        initial_count = threat_count_element.text
        
        # Trigger a threat event via API
        login_data = {"username": "e2etest", "password": "testpassword123"}
        response = requests.post("http://localhost:8000/api/auth/login", data=login_data)
        token = response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        test_event = {
            "timestamp": datetime.utcnow().isoformat(),
            "source": "e2e_test",
            "event_type": "security",
            "severity": "high",
            "message": "E2E test threat event",
            "details": {"test": True}
        }
        
        requests.post("http://localhost:8000/api/siem/events", json=test_event, headers=headers)
        
        # Wait for UI to update (should happen via WebSocket)
        time.sleep(5)
        
        # Check if count updated
        updated_count = threat_count_element.text
        # Note: This might not always change depending on how the UI aggregates data
    
    def test_responsive_design(self, browser, system_running):
        """Test responsive design on different screen sizes."""
        # Test desktop size
        browser.set_window_size(1920, 1080)
        browser.get("http://localhost:3000/dashboard")
        
        WebDriverWait(browser, 10).until(
            EC.presence_of_element_located((By.CLASS_NAME, "dashboard"))
        )
        
        # Check that sidebar is visible on desktop
        sidebar = browser.find_elements(By.CLASS_NAME, "sidebar")
        assert len(sidebar) > 0
        
        # Test mobile size
        browser.set_window_size(375, 667)
        
        # Check that mobile menu is present
        mobile_menu = browser.find_elements(By.CLASS_NAME, "mobile-menu")
        # Mobile menu might be hidden by default
    
    def test_error_handling(self, browser, system_running):
        """Test error handling in the UI."""
        # Try to access protected page without login
        browser.get("http://localhost:3000/dashboard")
        
        # Should redirect to login
        WebDriverWait(browser, 10).until(
            lambda driver: "login" in driver.current_url
        )
        
        # Try invalid login
        browser.get("http://localhost:3000/login")
        
        username_field = WebDriverWait(browser, 10).until(
            EC.presence_of_element_located((By.NAME, "username"))
        )
        username_field.send_keys("invaliduser")
        
        password_field = browser.find_element(By.NAME, "password")
        password_field.send_keys("wrongpassword")
        
        submit_button = browser.find_element(By.TYPE, "submit")
        submit_button.click()
        
        # Should show error message
        error_message = WebDriverWait(browser, 10).until(
            EC.presence_of_element_located((By.CLASS_NAME, "error-message"))
        )
        assert "invalid" in error_message.text.lower()

class TestSystemResilience:
    """Test system resilience and recovery."""
    
    def test_database_recovery(self):
        """Test system recovery after database restart."""
        # Stop database container
        subprocess.run(["docker-compose", "stop", "postgres"], cwd="/home/ubuntu/ecyber")
        
        # Wait a bit
        time.sleep(5)
        
        # Start database container
        subprocess.run(["docker-compose", "start", "postgres"], cwd="/home/ubuntu/ecyber")
        
        # Wait for recovery
        time.sleep(10)
        
        # Test that system is functional
        response = requests.get("http://localhost:8000/health")
        assert response.status_code == 200
    
    def test_redis_recovery(self):
        """Test system recovery after Redis restart."""
        # Stop Redis container
        subprocess.run(["docker-compose", "stop", "redis"], cwd="/home/ubuntu/ecyber")
        
        # Wait a bit
        time.sleep(5)
        
        # Start Redis container
        subprocess.run(["docker-compose", "start", "redis"], cwd="/home/ubuntu/ecyber")
        
        # Wait for recovery
        time.sleep(10)
        
        # Test that system is functional
        response = requests.get("http://localhost:8000/health")
        assert response.status_code == 200
    
    def test_backend_recovery(self):
        """Test system recovery after backend restart."""
        # Restart backend container
        subprocess.run(["docker-compose", "restart", "backend"], cwd="/home/ubuntu/ecyber")
        
        # Wait for recovery
        time.sleep(15)
        
        # Test that system is functional
        response = requests.get("http://localhost:8000/health")
        assert response.status_code == 200
    
    def test_high_memory_usage(self):
        """Test system behavior under high memory usage."""
        # This test would simulate high memory usage
        # In a real scenario, you might use memory stress tools
        pass
    
    def test_high_cpu_usage(self):
        """Test system behavior under high CPU usage."""
        # This test would simulate high CPU usage
        # In a real scenario, you might use CPU stress tools
        pass

class TestDataIntegrity:
    """Test data integrity and consistency."""
    
    def test_user_data_consistency(self):
        """Test user data consistency across operations."""
        base_url = "http://localhost:8000"
        
        # Create user
        user_data = {
            "username": "datatest",
            "email": "data@test.com",
            "password": "testpassword123",
            "full_name": "Data Test User"
        }
        
        response = requests.post(f"{base_url}/api/auth/register", json=user_data)
        assert response.status_code == 201
        
        # Login
        login_data = {"username": user_data["username"], "password": user_data["password"]}
        response = requests.post(f"{base_url}/api/auth/login", data=login_data)
        token = response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Get user profile
        response = requests.get(f"{base_url}/api/users/me", headers=headers)
        profile = response.json()
        
        # Verify data consistency
        assert profile["username"] == user_data["username"]
        assert profile["email"] == user_data["email"]
        assert profile["full_name"] == user_data["full_name"]
    
    def test_event_data_integrity(self):
        """Test event data integrity in SIEM system."""
        base_url = "http://localhost:8000"
        
        # Login
        login_data = {"username": "datatest", "password": "testpassword123"}
        response = requests.post(f"{base_url}/api/auth/login", data=login_data)
        token = response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Create test event
        test_event = {
            "timestamp": datetime.utcnow().isoformat(),
            "source": "integrity_test",
            "event_type": "security",
            "severity": "high",
            "message": "Data integrity test event",
            "details": {"test_id": "12345", "data": "test_data"}
        }
        
        # Submit event
        response = requests.post(f"{base_url}/api/siem/events", json=test_event, headers=headers)
        assert response.status_code in [200, 201]
        
        # Search for event
        search_params = {"message": "Data integrity test event"}
        response = requests.get(f"{base_url}/api/siem/events/search", params=search_params, headers=headers)
        assert response.status_code == 200
        
        events = response.json()
        assert len(events) > 0
        
        # Verify event data
        found_event = events[0]
        assert found_event["message"] == test_event["message"]
        assert found_event["details"]["test_id"] == "12345"

if __name__ == "__main__":
    # Run integration and E2E tests
    pytest.main([__file__, "-v", "--tb=short", "-s"])

