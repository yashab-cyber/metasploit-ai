#!/bin/bash

# Metasploit-AI Docker Entry Point Script
# This script handles initialization and startup of the containerized application

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" >&2
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}" >&2
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

# Function to wait for a service to be ready
wait_for_service() {
    local host=$1
    local port=$2
    local service_name=$3
    local timeout=${4:-30}
    
    info "Waiting for $service_name at $host:$port..."
    
    for i in $(seq 1 $timeout); do
        if nc -z "$host" "$port" 2>/dev/null; then
            log "$service_name is ready!"
            return 0
        fi
        sleep 1
    done
    
    error "$service_name failed to start within $timeout seconds"
    return 1
}

# Function to check database connection
check_database() {
    info "Checking database connection..."
    
    python3 -c "
import psycopg2
import os
import sys

try:
    conn = psycopg2.connect(
        host=os.getenv('DB_HOST', 'postgres'),
        port=os.getenv('DB_PORT', '5432'),
        database=os.getenv('DB_NAME', 'metasploit_ai'),
        user=os.getenv('DB_USER', 'msf_user'),
        password=os.getenv('DB_PASSWORD', 'secure_password')
    )
    conn.close()
    print('Database connection successful')
except Exception as e:
    print(f'Database connection failed: {e}')
    sys.exit(1)
"
    
    if [ $? -eq 0 ]; then
        log "Database connection verified"
    else
        error "Database connection failed"
        exit 1
    fi
}

# Function to check Redis connection
check_redis() {
    info "Checking Redis connection..."
    
    python3 -c "
import redis
import os
import sys

try:
    r = redis.Redis(
        host=os.getenv('REDIS_HOST', 'redis'),
        port=int(os.getenv('REDIS_PORT', '6379')),
        password=os.getenv('REDIS_PASSWORD', ''),
        decode_responses=True
    )
    r.ping()
    print('Redis connection successful')
except Exception as e:
    print(f'Redis connection failed: {e}')
    sys.exit(1)
"
    
    if [ $? -eq 0 ]; then
        log "Redis connection verified"
    else
        error "Redis connection failed"
        exit 1
    fi
}

# Function to run database migrations
run_migrations() {
    info "Running database migrations..."
    
    python3 -c "
from src.core.database import DatabaseManager
import asyncio

async def migrate():
    db = DatabaseManager()
    await db.initialize()
    print('Database migrations completed')

asyncio.run(migrate())
"
    
    if [ $? -eq 0 ]; then
        log "Database migrations completed"
    else
        error "Database migrations failed"
        exit 1
    fi
}

# Function to validate environment variables
validate_environment() {
    info "Validating environment variables..."
    
    local required_vars=(
        "SECRET_KEY"
        "DB_HOST"
        "DB_NAME"
        "DB_USER"
        "DB_PASSWORD"
    )
    
    local missing_vars=()
    
    for var in "${required_vars[@]}"; do
        if [ -z "${!var}" ]; then
            missing_vars+=("$var")
        fi
    done
    
    if [ ${#missing_vars[@]} -ne 0 ]; then
        error "Missing required environment variables: ${missing_vars[*]}"
        exit 1
    fi
    
    # Check for default passwords in production
    if [ "$ENVIRONMENT" = "production" ]; then
        if [ "$DB_PASSWORD" = "secure_password" ]; then
            error "Default database password detected in production environment"
            exit 1
        fi
        
        if [ "$SECRET_KEY" = "your-secret-key-here" ]; then
            error "Default secret key detected in production environment"
            exit 1
        fi
    fi
    
    log "Environment validation passed"
}

# Function to setup application directories
setup_directories() {
    info "Setting up application directories..."
    
    local dirs=(
        "/app/logs"
        "/app/reports"
        "/app/data"
        "/app/models"
        "/app/temp"
    )
    
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir"
        chmod 755 "$dir"
    done
    
    log "Application directories created"
}

# Function to start the application
start_application() {
    local mode=${1:-"production"}
    
    case $mode in
        "development")
            info "Starting application in development mode..."
            exec python3 app.py --mode web --debug
            ;;
        "production")
            info "Starting application in production mode..."
            exec gunicorn --config /app/docker/gunicorn.conf.py src.web.app:app
            ;;
        "cli")
            info "Starting application in CLI mode..."
            exec python3 app.py --mode cli
            ;;
        "worker")
            info "Starting background worker..."
            exec python3 -m src.worker
            ;;
        "scheduler")
            info "Starting task scheduler..."
            exec python3 -m src.scheduler
            ;;
        *)
            error "Unknown application mode: $mode"
            exit 1
            ;;
    esac
}

# Main execution
main() {
    log "Starting Metasploit-AI container..."
    
    # Parse command line arguments
    local app_mode="production"
    local skip_checks=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --mode)
                app_mode="$2"
                shift 2
                ;;
            --skip-checks)
                skip_checks=true
                shift
                ;;
            -h|--help)
                echo "Usage: $0 [OPTIONS]"
                echo "Options:"
                echo "  --mode MODE        Application mode (development|production|cli|worker|scheduler)"
                echo "  --skip-checks      Skip service health checks"
                echo "  -h, --help         Show this help message"
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Validate environment
    validate_environment
    
    # Setup directories
    setup_directories
    
    # Skip health checks if requested (useful for development)
    if [ "$skip_checks" != "true" ]; then
        # Wait for dependencies
        if [ -n "$DB_HOST" ]; then
            wait_for_service "$DB_HOST" "${DB_PORT:-5432}" "PostgreSQL" 60
            check_database
        fi
        
        if [ -n "$REDIS_HOST" ]; then
            wait_for_service "$REDIS_HOST" "${REDIS_PORT:-6379}" "Redis" 30
            check_redis
        fi
        
        if [ -n "$MSF_HOST" ]; then
            wait_for_service "$MSF_HOST" "${MSF_PORT:-55552}" "Metasploit RPC" 60
        fi
        
        # Run migrations only for web/production modes
        if [[ "$app_mode" == "production" || "$app_mode" == "development" ]]; then
            run_migrations
        fi
    fi
    
    # Start the application
    start_application "$app_mode"
}

# Handle signals gracefully
trap 'echo "Received shutdown signal, stopping..."; exit 0' SIGTERM SIGINT

# Execute main function
main "$@"
