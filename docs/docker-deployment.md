# Docker Deployment Documentation

## Overview

This document provides comprehensive instructions for deploying Metasploit-AI using Docker containers. The platform supports multiple deployment scenarios including development, production, and testing environments.

## Prerequisites

- Docker Engine 20.10+ or Docker Desktop
- Docker Compose 2.0+
- Minimum 4GB RAM available to Docker
- 10GB+ disk space for images and data

## Quick Start

### Development Environment

1. **Clone and prepare the repository:**
```bash
git clone <repository-url>
cd metasploit-ai
cp .env.example .env
```

2. **Start development stack:**
```bash
docker-compose -f docker-compose.dev.yml up -d
```

3. **Access the application:**
- Web Interface: http://localhost:8080
- API Documentation: http://localhost:8080/api/docs
- Logs: `docker-compose -f docker-compose.dev.yml logs -f`

### Production Environment

1. **Prepare environment:**
```bash
cp .env.example .env
# Edit .env with production values (see Configuration section)
```

2. **Start production stack:**
```bash
docker-compose up -d
```

3. **Verify deployment:**
```bash
docker-compose ps
docker-compose logs app
```

## Architecture

### Container Stack

```
┌─────────────────┐    ┌─────────────────┐
│     Nginx       │────│   Metasploit-AI │
│  (Load Balancer)│    │   Application   │
└─────────────────┘    └─────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   PostgreSQL    │    │      Redis      │    │   Metasploit    │
│   (Database)    │    │     (Cache)     │    │   Framework     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Services

- **app**: Main Metasploit-AI application
- **nginx**: Reverse proxy and load balancer
- **postgres**: Primary database for persistent data
- **redis**: Caching and session storage
- **metasploit**: Metasploit Framework RPC service
- **prometheus**: Metrics collection (production only)
- **grafana**: Monitoring dashboard (production only)

## Configuration

### Environment Variables

Copy `.env.example` to `.env` and customize the following critical settings:

#### Security (Required)
```bash
SECRET_KEY=your-256-bit-secret-key-here
DB_PASSWORD=your-secure-database-password
MSF_PASSWORD=your-metasploit-rpc-password
```

#### Database
```bash
DB_HOST=postgres
DB_NAME=metasploit_ai
DB_USER=msf_user
DB_PASSWORD=secure_password
```

#### Application
```bash
ENVIRONMENT=production
DEBUG=false
LOG_LEVEL=INFO
```

### Production Security Checklist

- [ ] Change all default passwords
- [ ] Generate secure SECRET_KEY (256-bit)
- [ ] Set ENVIRONMENT=production
- [ ] Disable DEBUG mode
- [ ] Configure SSL certificates
- [ ] Set up proper firewall rules
- [ ] Enable audit logging
- [ ] Configure backup strategy

## Deployment Modes

### Development Mode

**Features:**
- Hot code reloading
- Debug mode enabled
- Exposed database ports
- Development tools included

**Command:**
```bash
docker-compose -f docker-compose.dev.yml up -d
```

### Production Mode

**Features:**
- Optimized for performance
- Security hardened
- SSL termination
- Monitoring stack
- Health checks

**Command:**
```bash
docker-compose up -d
```

### Testing Mode

**Features:**
- Isolated test environment
- Mock external services
- Test database

**Command:**
```bash
docker-compose -f docker-compose.test.yml up --abort-on-container-exit
```

## Container Management

### Starting Services
```bash
# Start all services
docker-compose up -d

# Start specific service
docker-compose up -d app

# Start with rebuild
docker-compose up -d --build
```

### Stopping Services
```bash
# Stop all services
docker-compose down

# Stop and remove volumes
docker-compose down -v

# Stop specific service
docker-compose stop app
```

### Scaling Services
```bash
# Scale application instances
docker-compose up -d --scale app=3

# Scale with load balancer update
docker-compose up -d --scale app=3 nginx
```

## Monitoring and Logs

### Viewing Logs
```bash
# View all logs
docker-compose logs

# Follow specific service logs
docker-compose logs -f app

# View last 100 lines
docker-compose logs --tail=100 app
```

### Health Checks
```bash
# Check service status
docker-compose ps

# View health check status
docker inspect metasploit-ai_app_1 | jq '.[0].State.Health'

# Manual health check
curl http://localhost:8080/health
```

### Monitoring Stack (Production)

Access monitoring tools:
- **Prometheus**: http://localhost:9090
- **Grafana**: http://localhost:3000 (admin/admin)

Key metrics:
- Application response times
- Database connection pool
- Memory and CPU usage
- Request rate and errors

## Data Management

### Database Operations

**Backup:**
```bash
# Create backup
docker-compose exec postgres pg_dump -U msf_user metasploit_ai > backup.sql

# Automated backup script
docker-compose exec postgres sh -c 'pg_dump -U $POSTGRES_USER $POSTGRES_DB' > backup-$(date +%Y%m%d).sql
```

**Restore:**
```bash
# Restore from backup
docker-compose exec -T postgres psql -U msf_user metasploit_ai < backup.sql
```

**Database Access:**
```bash
# Connect to database
docker-compose exec postgres psql -U msf_user metasploit_ai

# Run migrations
docker-compose exec app python -c "from src.core.database import DatabaseManager; import asyncio; asyncio.run(DatabaseManager().initialize())"
```

### Volume Management

**Persistent Data:**
- Database: `postgres_data`
- Application logs: `app_logs`
- Generated reports: `app_reports`
- AI models: `app_models`

**Backup Volumes:**
```bash
# Backup volume
docker run --rm -v metasploit-ai_postgres_data:/data -v $(pwd):/backup ubuntu tar czf /backup/postgres_backup.tar.gz /data

# Restore volume
docker run --rm -v metasploit-ai_postgres_data:/data -v $(pwd):/backup ubuntu tar xzf /backup/postgres_backup.tar.gz -C /
```

## Troubleshooting

### Common Issues

**1. Database Connection Failed**
```bash
# Check database status
docker-compose logs postgres

# Verify connection
docker-compose exec app python -c "
from src.core.database import DatabaseManager
import asyncio
asyncio.run(DatabaseManager().test_connection())
"
```

**2. Metasploit RPC Connection Failed**
```bash
# Check Metasploit service
docker-compose logs metasploit

# Test RPC connection
docker-compose exec app python -c "
from src.core.metasploit_client import MetasploitClient
client = MetasploitClient()
print(client.test_connection())
"
```

**3. Memory Issues**
```bash
# Check container memory usage
docker stats

# Increase memory limits in docker-compose.yml
services:
  app:
    deploy:
      resources:
        limits:
          memory: 2G
```

**4. Port Conflicts**
```bash
# Check port usage
netstat -tulpn | grep :8080

# Change ports in docker-compose.yml
ports:
  - "8081:80"  # Change host port
```

### Debug Mode

**Enable debug logging:**
```bash
# Set in .env
DEBUG=true
LOG_LEVEL=DEBUG

# Restart services
docker-compose restart app
```

**Access container shell:**
```bash
# Application container
docker-compose exec app bash

# Database container
docker-compose exec postgres bash

# Run commands inside container
docker-compose exec app python app.py --help
```

### Performance Optimization

**Application Tuning:**
```bash
# Increase worker processes
# In docker/gunicorn.conf.py
workers = 4
worker_connections = 1000
```

**Database Tuning:**
```bash
# PostgreSQL optimization
# Add to docker-compose.yml postgres service
environment:
  - POSTGRES_INITDB_ARGS=--data-checksums
command: >
  postgres
  -c shared_preload_libraries=pg_stat_statements
  -c max_connections=200
  -c shared_buffers=256MB
```

**Redis Optimization:**
```bash
# Redis configuration
# Add to docker-compose.yml redis service
command: >
  redis-server
  --maxmemory 256mb
  --maxmemory-policy allkeys-lru
```

## Security Considerations

### Network Security
- Use Docker networks for service isolation
- Expose only necessary ports
- Configure proper firewall rules
- Use SSL/TLS for external connections

### Container Security
- Run containers as non-root user
- Use read-only file systems where possible
- Scan images for vulnerabilities
- Keep base images updated

### Data Security
- Encrypt sensitive environment variables
- Use Docker secrets for production
- Implement proper backup encryption
- Regular security audits

## Backup and Recovery

### Automated Backup Script
```bash
#!/bin/bash
# backup.sh - Automated backup script

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups"

# Database backup
docker-compose exec -T postgres pg_dump -U msf_user metasploit_ai | gzip > "$BACKUP_DIR/db_$DATE.sql.gz"

# Volume backups
docker run --rm -v metasploit-ai_app_reports:/data -v $BACKUP_DIR:/backup ubuntu tar czf /backup/reports_$DATE.tar.gz /data

# Cleanup old backups (keep last 7 days)
find $BACKUP_DIR -name "*.gz" -mtime +7 -delete

echo "Backup completed: $DATE"
```

### Recovery Procedures

**Full System Recovery:**
1. Stop all services: `docker-compose down`
2. Restore volumes from backup
3. Start services: `docker-compose up -d`
4. Verify functionality

**Database Recovery:**
1. Stop application: `docker-compose stop app`
2. Restore database from backup
3. Run migrations if needed
4. Start application: `docker-compose start app`

## Production Deployment Checklist

- [ ] Environment variables configured
- [ ] SSL certificates installed
- [ ] Firewall rules configured
- [ ] Monitoring stack deployed
- [ ] Backup strategy implemented
- [ ] Health checks configured
- [ ] Log aggregation setup
- [ ] Security scanning completed
- [ ] Performance testing done
- [ ] Documentation updated

## Support and Maintenance

### Regular Maintenance Tasks

**Weekly:**
- Review logs for errors
- Check disk space usage
- Verify backup completion
- Update security patches

**Monthly:**
- Update container images
- Review monitoring metrics
- Test backup recovery
- Security audit

**Quarterly:**
- Performance review
- Capacity planning
- Disaster recovery test
- Documentation update

### Getting Help

- Check logs: `docker-compose logs`
- Review documentation
- Validate configuration
- Test in development environment first

For additional support, refer to the main project documentation or contact the development team.
