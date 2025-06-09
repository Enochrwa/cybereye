# eCyber Security Platform - Advanced Real-Time Cyber Threat Detection System

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![React 18+](https://img.shields.io/badge/react-18+-blue.svg)](https://reactjs.org/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)
[![Security](https://img.shields.io/badge/security-enterprise-green.svg)](https://github.com/Enochrwa/ecyber)

## Overview

eCyber is a comprehensive, enterprise-grade cybersecurity platform designed for real-time threat detection, network monitoring, and security incident response. Built with cutting-edge technologies and AI-powered threat intelligence, eCyber provides organizations with the tools needed to defend against modern cyber threats and achieve compliance with industry standards.

### Key Features

- **🛡️ Real-Time Threat Detection**: AI-powered threat intelligence engine with machine learning capabilities
- **🌐 Advanced Network Monitoring**: Deep packet inspection and behavioral analysis
- **📊 Comprehensive SIEM**: Security Information and Event Management with correlation rules
- **🔐 Enterprise Authentication**: Multi-factor authentication with role-based access control
- **📱 Cross-Platform Support**: Web application, desktop app, and mobile-responsive design
- **⚡ High Performance**: Optimized for speed with caching and multiprocessing
- **🔄 Continuous Operation**: Self-healing architecture with automatic recovery
- **📈 Real-Time Analytics**: Live dashboards with customizable metrics
- **🚨 Automated Response**: Intelligent threat response and mitigation
- **🏢 Enterprise Ready**: Production-grade deployment with monitoring and backup

## Architecture

### System Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Backend API   │    │   Database      │
│   (React TS)    │◄──►│   (FastAPI)     │◄──►│   (PostgreSQL)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │              ┌─────────────────┐              │
         │              │   Redis Cache   │              │
         │              └─────────────────┘              │
         │                       │                       │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Electron      │    │   Monitoring    │    │   AI Engine     │
│   Desktop App   │    │   (Prometheus)  │    │   (TensorFlow)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Technology Stack

**Backend:**
- FastAPI (Python 3.11+) - High-performance async API framework
- PostgreSQL - Primary database with advanced indexing
- Redis - Caching and session management
- Celery - Background task processing
- TensorFlow - Machine learning and AI capabilities
- Scapy - Network packet analysis
- SQLAlchemy - ORM with async support

**Frontend:**
- React 18+ with TypeScript - Modern UI framework
- Vite - Fast build tool and development server
- TailwindCSS - Utility-first CSS framework
- Socket.IO - Real-time communication
- Recharts - Data visualization
- React Query - Server state management

**Infrastructure:**
- Docker & Docker Compose - Containerization
- Nginx - Load balancing and reverse proxy
- Prometheus - Metrics collection
- Grafana - Monitoring dashboards
- Elasticsearch - Log aggregation (optional)

## Quick Start

### Prerequisites

- Docker 20.10+ and Docker Compose 2.0+
- Node.js 18+ (for development)
- Python 3.11+ (for development)
- Git

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Enochrwa/ecyber.git
   cd ecyber
   ```

2. **Configure environment:**
   ```bash
   cp .env.production .env
   # Edit .env file with your configuration
   nano .env
   ```

3. **Deploy the system:**
   ```bash
   chmod +x deploy.sh
   ./deploy.sh deploy
   ```

4. **Access the application:**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000
   - API Documentation: http://localhost:8000/docs
   - Monitoring: http://localhost:9090 (Prometheus)
   - Dashboards: http://localhost:3001 (Grafana)

### Development Setup

For development environment setup:

1. **Backend development:**
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```

2. **Frontend development:**
   ```bash
   cd eCyber
   npm install
   npm run dev
   ```

3. **Electron app development:**
   ```bash
   cd eCyber/electron
   npm install
   npm run electron:dev
   ```

## Configuration

### Environment Variables

The system uses environment variables for configuration. Key variables include:

```bash
# Database Configuration
DATABASE_URL=postgresql://user:password@localhost:5432/ecyber
POSTGRES_PASSWORD=your_secure_password

# Security Configuration
SECRET_KEY=your_super_secret_key
JWT_SECRET_KEY=your_jwt_secret_key
JWT_EXPIRE_MINUTES=1440

# Feature Flags
THREAT_INTELLIGENCE_ENABLED=true
NETWORK_MONITORING_ENABLED=true
SIEM_ENABLED=true
MFA_ENABLED=true

# Performance Settings
CACHE_ENABLED=true
WORKER_PROCESSES=4
DATABASE_POOL_SIZE=20
```

### Security Configuration

eCyber implements multiple layers of security:

- **Authentication**: JWT-based authentication with refresh tokens
- **Authorization**: Role-based access control (RBAC)
- **Rate Limiting**: Configurable request rate limiting
- **Input Validation**: Comprehensive input sanitization
- **HTTPS**: SSL/TLS encryption for all communications
- **CORS**: Configurable cross-origin resource sharing
- **Session Management**: Secure session handling with timeout

## Features

### 1. Threat Intelligence Engine

The AI-powered threat intelligence engine provides:

- **Real-time Threat Feeds**: Integration with multiple threat intelligence sources
- **Machine Learning Detection**: Behavioral analysis using TensorFlow
- **Threat Correlation**: Advanced correlation rules for threat identification
- **Custom Indicators**: Support for custom threat indicators
- **Threat Hunting**: Interactive threat hunting capabilities

### 2. Network Security Monitoring

Advanced network monitoring capabilities include:

- **Deep Packet Inspection**: Analysis of network traffic at packet level
- **Flow Analysis**: Network flow tracking and analysis
- **Intrusion Detection**: Real-time intrusion detection system
- **Anomaly Detection**: ML-based network anomaly detection
- **Protocol Analysis**: Support for multiple network protocols

### 3. SIEM System

Comprehensive Security Information and Event Management:

- **Event Correlation**: Advanced correlation rules and algorithms
- **Log Aggregation**: Centralized log collection and parsing
- **Incident Management**: Automated incident creation and tracking
- **Compliance Reporting**: Built-in compliance reports
- **Custom Dashboards**: Configurable security dashboards

### 4. Real-time Analytics

Live monitoring and analytics features:

- **Real-time Dashboards**: Live updating security metrics
- **Custom Metrics**: Configurable KPIs and metrics
- **Alerting**: Real-time alerts and notifications
- **Trend Analysis**: Historical trend analysis
- **Performance Monitoring**: System performance metrics

## API Documentation

### Authentication Endpoints

```http
POST /api/auth/register
POST /api/auth/login
POST /api/auth/logout
POST /api/auth/refresh
GET  /api/auth/me
```

### Threat Intelligence Endpoints

```http
GET    /api/threat-intelligence/statistics
GET    /api/threat-intelligence/indicators
POST   /api/threat-intelligence/indicators
PUT    /api/threat-intelligence/indicators/{id}
DELETE /api/threat-intelligence/indicators/{id}
```

### Network Monitoring Endpoints

```http
GET  /api/network/statistics
GET  /api/network/flows
GET  /api/network/alerts
POST /api/network/capture/start
POST /api/network/capture/stop
```

### SIEM Endpoints

```http
GET  /api/siem/dashboard
GET  /api/siem/events
POST /api/siem/events
GET  /api/siem/events/search
GET  /api/siem/incidents
POST /api/siem/incidents
```

For complete API documentation, visit `/docs` endpoint when the server is running.

## Deployment

### Production Deployment

1. **Using Docker Compose (Recommended):**
   ```bash
   ./deploy.sh deploy
   ```

2. **Manual Deployment:**
   ```bash
   # Build images
   docker-compose build
   
   # Start services
   docker-compose up -d
   
   # Check status
   docker-compose ps
   ```

3. **Kubernetes Deployment:**
   ```bash
   # Apply Kubernetes manifests
   kubectl apply -f k8s/
   
   # Check deployment status
   kubectl get pods -n ecyber
   ```

### Scaling

The system supports horizontal scaling:

```bash
# Scale backend services
docker-compose up -d --scale backend=3

# Scale worker processes
docker-compose up -d --scale celery-worker=5
```

### Monitoring

Built-in monitoring includes:

- **Prometheus Metrics**: System and application metrics
- **Grafana Dashboards**: Pre-configured monitoring dashboards
- **Health Checks**: Automated health monitoring
- **Log Aggregation**: Centralized logging with rotation
- **Performance Monitoring**: Real-time performance metrics

## Security

### Security Features

- **Multi-Factor Authentication (MFA)**: TOTP-based 2FA
- **Role-Based Access Control**: Granular permission system
- **API Security**: Rate limiting, input validation, CORS
- **Data Encryption**: Encryption at rest and in transit
- **Audit Logging**: Comprehensive audit trail
- **Vulnerability Scanning**: Automated security scanning

### Compliance

eCyber supports compliance with:

- **GDPR**: Data protection and privacy compliance
- **SOC 2**: Security and availability controls
- **ISO 27001**: Information security management
- **NIST Cybersecurity Framework**: Security controls alignment
- **PCI DSS**: Payment card industry standards (optional)

## Performance

### Optimization Features

- **Caching Strategy**: Multi-level caching with Redis
- **Database Optimization**: Optimized queries and indexing
- **Async Processing**: Non-blocking I/O operations
- **Load Balancing**: Nginx-based load balancing
- **Resource Management**: Efficient memory and CPU usage

### Performance Metrics

- **Response Time**: < 100ms for API endpoints
- **Throughput**: 10,000+ requests per second
- **Concurrent Users**: 1,000+ simultaneous users
- **Data Processing**: 1M+ events per minute
- **Uptime**: 99.9% availability target

## Testing

### Test Coverage

The system includes comprehensive testing:

- **Unit Tests**: 90%+ code coverage
- **Integration Tests**: End-to-end API testing
- **Performance Tests**: Load and stress testing
- **Security Tests**: Vulnerability and penetration testing
- **UI Tests**: Automated browser testing

### Running Tests

```bash
# Backend tests
cd backend
pytest tests/ -v --cov=app

# Frontend tests
cd eCyber
npm test

# Integration tests
pytest tests/test_integration.py -v

# Performance tests
pytest tests/test_performance.py -v
```

## Troubleshooting

### Common Issues

1. **Database Connection Issues:**
   ```bash
   # Check database status
   docker-compose logs postgres
   
   # Restart database
   docker-compose restart postgres
   ```

2. **High Memory Usage:**
   ```bash
   # Monitor resource usage
   docker stats
   
   # Adjust memory limits
   # Edit docker-compose.yml memory limits
   ```

3. **Performance Issues:**
   ```bash
   # Check system metrics
   curl http://localhost:9090/metrics
   
   # View performance dashboard
   # Open http://localhost:3001
   ```

### Log Analysis

```bash
# View application logs
docker-compose logs -f backend

# View all service logs
docker-compose logs -f

# Search logs for errors
docker-compose logs backend | grep ERROR
```

## Contributing

We welcome contributions to eCyber! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/new-feature`
3. **Make your changes** with proper tests
4. **Run the test suite**: `npm test && pytest`
5. **Submit a pull request** with detailed description

### Development Guidelines

- Follow PEP 8 for Python code
- Use TypeScript for frontend development
- Write comprehensive tests for new features
- Update documentation for API changes
- Follow semantic versioning for releases

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support and questions:

- **Documentation**: [Wiki](https://github.com/Enochrwa/ecyber/wiki)
- **Issues**: [GitHub Issues](https://github.com/Enochrwa/ecyber/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Enochrwa/ecyber/discussions)
- **Email**: support@ecyber.com

## Acknowledgments

- FastAPI team for the excellent web framework
- React team for the powerful UI library
- TensorFlow team for machine learning capabilities
- The open-source security community for threat intelligence
- All contributors who helped improve this project

---

**eCyber Security Platform** - Protecting organizations from cyber threats with advanced AI-powered detection and response capabilities.

