#!/bin/bash

# eCyber Security Platform Deployment Script
# This script deploys the eCyber platform in production environment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DEPLOY_ENV=${DEPLOY_ENV:-production}
DOMAIN=${DOMAIN:-localhost}
SSL_ENABLED=${SSL_ENABLED:-false}
BACKUP_ENABLED=${BACKUP_ENABLED:-true}

echo -e "${BLUE}eCyber Security Platform Deployment${NC}"
echo -e "${BLUE}====================================${NC}"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check if Docker Compose is installed
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    # Check if required files exist
    required_files=("docker-compose.yml" "Dockerfile.backend" "Dockerfile.frontend" ".env.production")
    for file in "${required_files[@]}"; do
        if [[ ! -f "$file" ]]; then
            print_error "Required file $file not found."
            exit 1
        fi
    done
    
    print_status "Prerequisites check passed."
}

# Setup environment
setup_environment() {
    print_status "Setting up environment..."
    
    # Create necessary directories
    mkdir -p logs models temp backups ssl
    
    # Set permissions
    chmod 755 logs models temp backups
    
    # Copy environment file
    if [[ ! -f .env ]]; then
        cp .env.production .env
        print_warning "Please review and update the .env file with your configuration."
    fi
    
    print_status "Environment setup completed."
}

# Generate SSL certificates (if needed)
setup_ssl() {
    if [[ "$SSL_ENABLED" == "true" ]]; then
        print_status "Setting up SSL certificates..."
        
        if [[ ! -f ssl/cert.pem ]] || [[ ! -f ssl/key.pem ]]; then
            print_status "Generating self-signed SSL certificates..."
            openssl req -x509 -newkey rsa:4096 -keyout ssl/key.pem -out ssl/cert.pem -days 365 -nodes \
                -subj "/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN"
            print_warning "Self-signed certificates generated. For production, use proper SSL certificates."
        fi
        
        print_status "SSL setup completed."
    fi
}

# Database initialization
init_database() {
    print_status "Initializing database..."
    
    # Create init-db.sql if it doesn't exist
    if [[ ! -f init-db.sql ]]; then
        cat > init-db.sql << EOF
-- eCyber Database Initialization
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_network_flows_timestamp ON network_flows(start_time);
CREATE INDEX IF NOT EXISTS idx_threat_indicators_value ON threat_indicators(value);

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO ecyber_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO ecyber_user;
EOF
    fi
    
    print_status "Database initialization completed."
}

# Build and start services
deploy_services() {
    print_status "Building and starting services..."
    
    # Pull latest images
    docker-compose pull
    
    # Build custom images
    docker-compose build --no-cache
    
    # Start services
    docker-compose up -d
    
    print_status "Services deployment completed."
}

# Wait for services to be ready
wait_for_services() {
    print_status "Waiting for services to be ready..."
    
    # Wait for database
    print_status "Waiting for database..."
    timeout 60 bash -c 'until docker-compose exec -T postgres pg_isready -U ecyber_user -d ecyber; do sleep 2; done'
    
    # Wait for Redis
    print_status "Waiting for Redis..."
    timeout 60 bash -c 'until docker-compose exec -T redis redis-cli ping; do sleep 2; done'
    
    # Wait for backend
    print_status "Waiting for backend..."
    timeout 120 bash -c 'until curl -f http://localhost:8000/health; do sleep 5; done'
    
    # Wait for frontend
    print_status "Waiting for frontend..."
    timeout 60 bash -c 'until curl -f http://localhost:3000/health; do sleep 5; done'
    
    print_status "All services are ready."
}

# Run database migrations
run_migrations() {
    print_status "Running database migrations..."
    
    docker-compose exec backend python -c "
from app.database import init_db
import asyncio
asyncio.run(init_db())
"
    
    print_status "Database migrations completed."
}

# Setup monitoring
setup_monitoring() {
    print_status "Setting up monitoring..."
    
    # Create Prometheus configuration
    if [[ ! -f prometheus.yml ]]; then
        cat > prometheus.yml << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  # - "first_rules.yml"
  # - "second_rules.yml"

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'ecyber-backend'
    static_configs:
      - targets: ['backend:8000']
    metrics_path: '/metrics'

  - job_name: 'ecyber-postgres'
    static_configs:
      - targets: ['postgres:5432']

  - job_name: 'ecyber-redis'
    static_configs:
      - targets: ['redis:6379']
EOF
    fi
    
    # Create Grafana provisioning
    mkdir -p grafana/provisioning/dashboards grafana/provisioning/datasources
    
    cat > grafana/provisioning/datasources/prometheus.yml << EOF
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
EOF
    
    print_status "Monitoring setup completed."
}

# Create backup script
create_backup_script() {
    if [[ "$BACKUP_ENABLED" == "true" ]]; then
        print_status "Creating backup script..."
        
        cat > backup.sh << 'EOF'
#!/bin/bash

# eCyber Backup Script
BACKUP_DIR="./backups"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup database
echo "Backing up database..."
docker-compose exec -T postgres pg_dump -U ecyber_user ecyber > "$BACKUP_DIR/database_$DATE.sql"

# Backup application data
echo "Backing up application data..."
tar -czf "$BACKUP_DIR/app_data_$DATE.tar.gz" logs models temp

# Cleanup old backups (keep last 7 days)
find "$BACKUP_DIR" -name "*.sql" -mtime +7 -delete
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +7 -delete

echo "Backup completed: $DATE"
EOF
        
        chmod +x backup.sh
        
        # Add to crontab (daily backup at 2 AM)
        (crontab -l 2>/dev/null; echo "0 2 * * * $(pwd)/backup.sh") | crontab -
        
        print_status "Backup script created and scheduled."
    fi
}

# Health check
health_check() {
    print_status "Performing health check..."
    
    # Check all services
    services=("postgres" "redis" "backend" "frontend" "celery-worker" "celery-beat")
    
    for service in "${services[@]}"; do
        if docker-compose ps "$service" | grep -q "Up"; then
            print_status "$service: Running"
        else
            print_error "$service: Not running"
        fi
    done
    
    # Check endpoints
    endpoints=(
        "http://localhost:8000/health:Backend API"
        "http://localhost:3000/health:Frontend"
        "http://localhost:9090:Prometheus"
        "http://localhost:3001:Grafana"
    )
    
    for endpoint in "${endpoints[@]}"; do
        url=$(echo "$endpoint" | cut -d: -f1-2)
        name=$(echo "$endpoint" | cut -d: -f3)
        
        if curl -f -s "$url" > /dev/null; then
            print_status "$name: Accessible"
        else
            print_warning "$name: Not accessible"
        fi
    done
}

# Display deployment information
show_deployment_info() {
    print_status "Deployment completed successfully!"
    echo
    echo -e "${BLUE}Access Information:${NC}"
    echo -e "Frontend:     http://$DOMAIN:3000"
    echo -e "Backend API:  http://$DOMAIN:8000"
    echo -e "API Docs:     http://$DOMAIN:8000/docs"
    echo -e "Prometheus:   http://$DOMAIN:9090"
    echo -e "Grafana:      http://$DOMAIN:3001 (admin/admin123)"
    echo -e "Flower:       http://$DOMAIN:5555"
    echo
    echo -e "${BLUE}Management Commands:${NC}"
    echo -e "View logs:    docker-compose logs -f [service]"
    echo -e "Stop:         docker-compose down"
    echo -e "Restart:      docker-compose restart [service]"
    echo -e "Backup:       ./backup.sh"
    echo
    echo -e "${YELLOW}Important:${NC}"
    echo -e "1. Change default passwords in .env file"
    echo -e "2. Configure proper SSL certificates for production"
    echo -e "3. Set up proper firewall rules"
    echo -e "4. Configure log rotation"
    echo -e "5. Set up monitoring alerts"
}

# Main deployment function
main() {
    echo -e "${BLUE}Starting deployment...${NC}"
    
    check_prerequisites
    setup_environment
    setup_ssl
    init_database
    setup_monitoring
    deploy_services
    wait_for_services
    run_migrations
    create_backup_script
    health_check
    show_deployment_info
    
    print_status "Deployment completed successfully!"
}

# Handle script arguments
case "${1:-deploy}" in
    "deploy")
        main
        ;;
    "stop")
        print_status "Stopping services..."
        docker-compose down
        ;;
    "restart")
        print_status "Restarting services..."
        docker-compose restart
        ;;
    "logs")
        docker-compose logs -f "${2:-}"
        ;;
    "backup")
        if [[ -f backup.sh ]]; then
            ./backup.sh
        else
            print_error "Backup script not found. Run deployment first."
        fi
        ;;
    "health")
        health_check
        ;;
    "update")
        print_status "Updating services..."
        docker-compose pull
        docker-compose build --no-cache
        docker-compose up -d
        ;;
    *)
        echo "Usage: $0 {deploy|stop|restart|logs|backup|health|update}"
        echo
        echo "Commands:"
        echo "  deploy  - Deploy the entire platform"
        echo "  stop    - Stop all services"
        echo "  restart - Restart all services"
        echo "  logs    - View logs (optionally specify service)"
        echo "  backup  - Create backup"
        echo "  health  - Check service health"
        echo "  update  - Update and restart services"
        exit 1
        ;;
esac

