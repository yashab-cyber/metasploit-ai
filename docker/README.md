# Metasploit-AI Docker Infrastructure

## Overview

Complete Docker infrastructure for the Metasploit-AI cybersecurity framework, providing containerized deployment for development, testing, and production environments.

## Components

### Core Services
- **Application Container**: Python-based Metasploit-AI framework
- **Database**: PostgreSQL for persistent data storage
- **Cache**: Redis for session management and caching
- **Proxy**: Nginx for load balancing and SSL termination
- **Metasploit**: Containerized Metasploit Framework

### Supporting Services
- **Monitoring**: Prometheus and Grafana for metrics
- **Logging**: Centralized log aggregation
- **Backup**: Automated data backup solutions

## Files Structure

```
docker/
├── Dockerfile              # Multi-stage application container
├── docker-compose.yml      # Production stack
├── docker-compose.dev.yml  # Development environment
├── docker-compose.test.yml # Testing environment
├── entrypoint.sh           # Container initialization script
├── init-db.sql            # Database schema initialization
├── gunicorn.conf.py       # Production WSGI configuration
└── nginx.conf             # Reverse proxy configuration
```

## Quick Start

### Development
```bash
# Start development stack
docker-compose -f docker-compose.dev.yml up -d

# Access application
open http://localhost:8080
```

### Production
```bash
# Configure environment
cp .env.example .env
# Edit .env with production settings

# Deploy production stack
docker-compose up -d

# Monitor deployment
docker-compose logs -f
```

## Configuration

### Environment Variables
- Copy `.env.example` to `.env`
- Customize database credentials
- Set secure secret keys
- Configure external service endpoints

### Security Settings
- Generate strong passwords
- Configure SSL certificates
- Set proper network policies
- Enable audit logging

## Monitoring

### Health Checks
```bash
# Check service status
docker-compose ps

# View application health
curl http://localhost:8080/health
```

### Logs
```bash
# View all logs
docker-compose logs

# Follow specific service
docker-compose logs -f app
```

### Metrics
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000

## Data Persistence

### Volumes
- `postgres_data`: Database storage
- `app_logs`: Application logs
- `app_reports`: Generated reports
- `app_models`: AI model files

### Backup
```bash
# Database backup
docker-compose exec postgres pg_dump -U msf_user metasploit_ai > backup.sql

# Volume backup
docker run --rm -v metasploit-ai_postgres_data:/data -v $(pwd):/backup ubuntu tar czf /backup/backup.tar.gz /data
```

## Scaling

### Horizontal Scaling
```bash
# Scale application instances
docker-compose up -d --scale app=3

# Update load balancer
docker-compose restart nginx
```

### Resource Limits
- Configure memory and CPU limits
- Set appropriate worker processes
- Optimize database connections

## Security

### Network Isolation
- Internal Docker networks
- Minimal port exposure
- Service-to-service communication

### Container Security
- Non-root user execution
- Read-only file systems
- Regular security updates

## Troubleshooting

### Common Issues
1. **Port conflicts**: Change host ports in compose files
2. **Memory issues**: Increase container memory limits
3. **Database connection**: Check credentials and network
4. **SSL errors**: Verify certificate configuration

### Debug Commands
```bash
# Access container shell
docker-compose exec app bash

# Check container logs
docker-compose logs --tail=100 app

# Test database connection
docker-compose exec app python -c "from src.core.database import DatabaseManager; import asyncio; asyncio.run(DatabaseManager().test_connection())"
```

## Maintenance

### Updates
```bash
# Pull latest images
docker-compose pull

# Rebuild and restart
docker-compose up -d --build
```

### Cleanup
```bash
# Remove stopped containers
docker-compose down

# Remove volumes (caution: data loss)
docker-compose down -v

# Clean up images
docker system prune -a
```

## Support

For detailed deployment instructions, see `docs/docker-deployment.md`.

For troubleshooting and advanced configuration, refer to the main project documentation.
