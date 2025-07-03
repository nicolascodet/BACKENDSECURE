# Enterprise Backend Deployment Guide

## Overview

This guide covers the deployment of the enterprise-grade FastAPI backend to Google Cloud Platform using modern DevOps practices, security best practices, and scalable infrastructure.

## Prerequisites

### Required Tools

- **Google Cloud SDK**: Latest version
- **Terraform**: v1.0+ (for infrastructure as code)
- **Docker**: For containerization
- **Git**: For version control

### Required Permissions

- Google Cloud Project Owner or Editor
- Cloud Run Admin
- Cloud Build Editor
- Secret Manager Admin
- IAM Admin

## Quick Start

### 1. Initial Setup

```bash
# Clone the repository
git clone <your-repo-url>
cd enterprise-backend

# Authenticate with Google Cloud
gcloud auth login
gcloud auth application-default login

# Set your project
export GOOGLE_CLOUD_PROJECT=your-project-id
gcloud config set project $GOOGLE_CLOUD_PROJECT
```

### 2. Infrastructure Deployment

```bash
# Navigate to infrastructure directory
cd infrastructure/terraform

# Initialize Terraform
terraform init

# Copy and customize variables
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values

# Deploy infrastructure
terraform plan
terraform apply
```

### 3. Application Deployment

```bash
# Option 1: Using deployment script (recommended)
./deployment/deploy.sh -p your-project-id

# Option 2: Using Cloud Build
gcloud builds submit --config=deployment/cloudbuild.yaml

# Option 3: Manual deployment
gcloud run deploy enterprise-backend \
    --source . \
    --region us-central1 \
    --service-account enterprise-backend-sa@your-project-id.iam.gserviceaccount.com
```

## Configuration

### Environment Variables

The application uses environment variables for configuration. Key variables include:

```bash
# Security Configuration
ENVIRONMENT=production
JWT_SECRET_KEY=<stored-in-secret-manager>
API_KEY_SECRET=<stored-in-secret-manager>
CSRF_SECRET_KEY=<stored-in-secret-manager>

# Authentication
GOOGLE_CLIENT_ID=<oauth-client-id>
GOOGLE_CLIENT_SECRET=<oauth-client-secret>

# Database (if using Cloud SQL)
DATABASE_URL=<connection-string>

# Monitoring
SENTRY_DSN=<sentry-dsn>
```

### Secret Management

All sensitive configuration is stored in Google Secret Manager:

```bash
# Create secrets
gcloud secrets create jwt-secret --data-file=jwt.key
gcloud secrets create api-key-secret --data-file=api.key
gcloud secrets create csrf-secret --data-file=csrf.key

# Grant access to service account
gcloud secrets add-iam-policy-binding jwt-secret \
    --member="serviceAccount:enterprise-backend-sa@your-project-id.iam.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor"
```

## Security Configuration

### Authentication Setup

1. **OAuth 2.0 Configuration**:
   ```bash
   # Run authentication setup script
   ./automation/scripts/setup/setup-authentication.sh your-project-id
   ```

2. **API Key Management**:
   - API keys are automatically generated and stored in Secret Manager
   - Keys are rotated automatically every 90 days
   - Rate limiting is enforced per API key

### Security Headers

The application automatically applies security headers:

- **HSTS**: Force HTTPS connections
- **CSP**: Content Security Policy
- **X-Frame-Options**: Prevent clickjacking
- **X-Content-Type-Options**: Prevent MIME sniffing
- **X-XSS-Protection**: XSS protection

### Rate Limiting

Rate limiting is configured per endpoint type:

- **General API**: 100 requests/minute
- **Authentication**: 5 requests/minute
- **Registration**: 5 requests/minute
- **Protected endpoints**: 50 requests/minute

## Monitoring & Observability

### Health Checks

The application provides comprehensive health endpoints:

```bash
# Basic health check
curl https://your-service-url/health

# Detailed health information
curl https://your-service-url/health/detailed

# Configuration status
curl https://your-service-url/config
```

### Logging

Structured logging is configured with:

- **Log Level**: INFO (production), DEBUG (development)
- **Format**: JSON structured logs
- **Correlation IDs**: Request tracking
- **Security Events**: Authentication, authorization events

### Monitoring Scripts

Run monitoring scripts regularly:

```bash
# System health monitoring
./automation/scripts/monitoring/system-health.sh your-project-id

# Security monitoring
./automation/scripts/security/security-monitor.sh your-project-id

# Database maintenance
./automation/scripts/maintenance/database-maintenance.sh your-project-id
```

## Scaling & Performance

### Auto-scaling Configuration

Cloud Run is configured with:

- **Min Instances**: 0 (cost-effective)
- **Max Instances**: 100 (scalable)
- **CPU**: 2 vCPU per instance
- **Memory**: 2GB per instance
- **Timeout**: 300 seconds

### Performance Optimization

- **Connection Pooling**: Enabled for database connections
- **Caching**: Redis for session and API response caching
- **CDN**: Cloud CDN for static assets
- **Compression**: Gzip compression enabled

## Disaster Recovery

### Backup Strategy

- **Database Backups**: Daily automated backups with 30-day retention
- **Code Backups**: Git repository with multiple remotes
- **Configuration Backups**: Terraform state backed up to Cloud Storage

### Recovery Procedures

1. **Service Recovery**:
   ```bash
   # Rollback to previous version
   gcloud run services update-traffic enterprise-backend \
       --to-revisions=REVISION_NAME=100 \
       --region=us-central1
   ```

2. **Database Recovery**:
   ```bash
   # Restore from backup
   gcloud sql backups restore BACKUP_ID \
       --restore-instance=enterprise-backend-db \
       --backup-instance=enterprise-backend-db
   ```

## Troubleshooting

### Common Issues

1. **Authentication Failures**:
   - Check OAuth 2.0 credentials
   - Verify redirect URLs
   - Check Secret Manager permissions

2. **Performance Issues**:
   - Review Cloud Run logs
   - Check database connection pooling
   - Monitor resource utilization

3. **Security Alerts**:
   - Run security monitoring script
   - Check failed login attempts
   - Review API access patterns

### Log Analysis

```bash
# View recent logs
gcloud run services logs read enterprise-backend \
    --region=us-central1 \
    --limit=100

# Filter error logs
gcloud logging read "
    resource.type=cloud_run_revision AND
    resource.labels.service_name=enterprise-backend AND
    severity>=ERROR
" --limit=50
```

## Maintenance

### Regular Maintenance Tasks

1. **Weekly**:
   - Review security monitoring reports
   - Check system health metrics
   - Update dependencies if needed

2. **Monthly**:
   - Rotate API keys
   - Review access logs
   - Update documentation

3. **Quarterly**:
   - Security audit
   - Performance review
   - Disaster recovery testing

### Maintenance Scripts

```bash
# Database maintenance
./automation/scripts/maintenance/database-maintenance.sh your-project-id

# Security monitoring
./automation/scripts/security/security-monitor.sh your-project-id

# System health check
./automation/scripts/monitoring/system-health.sh your-project-id
```

## Support

For issues and questions:

1. Check the logs using Cloud Console
2. Review the monitoring dashboards
3. Run the health check scripts
4. Consult the API documentation at `/docs`

## Additional Resources

- [Security Configuration Guide](../security/SECURITY_CONFIG.md)
- [Monitoring Setup Guide](../monitoring/MONITORING_SETUP.md)
- [API Documentation](../api/API_REFERENCE.md)
- [Maintenance Procedures](../maintenance/MAINTENANCE_GUIDE.md) 