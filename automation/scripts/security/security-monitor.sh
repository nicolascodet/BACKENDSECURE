#!/bin/bash
# =============================================================================
# ENTERPRISE BACKEND - SECURITY MONITORING SCRIPT
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Configuration
PROJECT_ID="${1:-$GOOGLE_CLOUD_PROJECT}"
SERVICE_NAME="${2:-enterprise-backend}"
REGION="${3:-us-central1}"
HOURS_TO_CHECK="${4:-24}"

if [ -z "$PROJECT_ID" ]; then
    print_error "Usage: $0 <PROJECT_ID> [SERVICE_NAME] [REGION] [HOURS_TO_CHECK]"
    exit 1
fi

print_status "Running security monitoring for project: $PROJECT_ID"
print_status "Service: $SERVICE_NAME, Region: $REGION"
print_status "Checking last $HOURS_TO_CHECK hours"

# Function to check failed login attempts
check_failed_logins() {
    print_status "Checking failed login attempts..."
    
    # Query Cloud Logging for failed login attempts
    FAILED_LOGINS=$(gcloud logging read "
        resource.type=cloud_run_revision AND
        resource.labels.service_name=$SERVICE_NAME AND
        severity>=ERROR AND
        textPayload:\"Failed login attempt\" AND
        timestamp >= \"$(date -u -d "$HOURS_TO_CHECK hours ago" +%Y-%m-%dT%H:%M:%SZ)\"
    " --project="$PROJECT_ID" --format="value(timestamp,textPayload)" --limit=100)
    
    if [ -n "$FAILED_LOGINS" ]; then
        FAILED_COUNT=$(echo "$FAILED_LOGINS" | wc -l)
        print_warning "Found $FAILED_COUNT failed login attempts in the last $HOURS_TO_CHECK hours"
        
        # Check for brute force patterns
        UNIQUE_IPS=$(echo "$FAILED_LOGINS" | grep -o 'IP: [0-9.]*' | sort | uniq -c | sort -nr)
        print_status "Failed login attempts by IP:"
        echo "$UNIQUE_IPS"
        
        # Alert if more than 10 failed attempts from same IP
        HIGH_RISK_IPS=$(echo "$UNIQUE_IPS" | awk '$1 > 10 {print $2}')
        if [ -n "$HIGH_RISK_IPS" ]; then
            print_error "HIGH RISK: Multiple failed login attempts from these IPs:"
            echo "$HIGH_RISK_IPS"
        fi
    else
        print_success "No failed login attempts found"
    fi
}

# Function to check for suspicious API calls
check_suspicious_api_calls() {
    print_status "Checking for suspicious API calls..."
    
    # Query for high rate of requests from single IP
    SUSPICIOUS_REQUESTS=$(gcloud logging read "
        resource.type=cloud_run_revision AND
        resource.labels.service_name=$SERVICE_NAME AND
        httpRequest.remoteIp!=\"\" AND
        timestamp >= \"$(date -u -d "$HOURS_TO_CHECK hours ago" +%Y-%m-%dT%H:%M:%SZ)\"
    " --project="$PROJECT_ID" --format="value(httpRequest.remoteIp)" --limit=10000)
    
    if [ -n "$SUSPICIOUS_REQUESTS" ]; then
        # Count requests per IP
        IP_COUNTS=$(echo "$SUSPICIOUS_REQUESTS" | sort | uniq -c | sort -nr)
        print_status "Top IP addresses by request count:"
        echo "$IP_COUNTS" | head -10
        
        # Alert if more than 1000 requests from same IP
        HIGH_VOLUME_IPS=$(echo "$IP_COUNTS" | awk '$1 > 1000 {print $2 " (" $1 " requests)"}')
        if [ -n "$HIGH_VOLUME_IPS" ]; then
            print_warning "High volume requests from these IPs:"
            echo "$HIGH_VOLUME_IPS"
        fi
    fi
}

# Function to check error rates
check_error_rates() {
    print_status "Checking error rates..."
    
    # Query for 5xx errors
    ERROR_5XX=$(gcloud logging read "
        resource.type=cloud_run_revision AND
        resource.labels.service_name=$SERVICE_NAME AND
        httpRequest.status>=500 AND
        timestamp >= \"$(date -u -d "$HOURS_TO_CHECK hours ago" +%Y-%m-%dT%H:%M:%SZ)\"
    " --project="$PROJECT_ID" --format="value(timestamp,httpRequest.status)" --limit=1000)
    
    if [ -n "$ERROR_5XX" ]; then
        ERROR_COUNT=$(echo "$ERROR_5XX" | wc -l)
        print_warning "Found $ERROR_COUNT 5xx errors in the last $HOURS_TO_CHECK hours"
        
        # Show error distribution
        ERROR_DISTRIBUTION=$(echo "$ERROR_5XX" | awk '{print $2}' | sort | uniq -c | sort -nr)
        print_status "Error distribution:"
        echo "$ERROR_DISTRIBUTION"
    else
        print_success "No 5xx errors found"
    fi
    
    # Query for 4xx errors (potential security probes)
    ERROR_4XX=$(gcloud logging read "
        resource.type=cloud_run_revision AND
        resource.labels.service_name=$SERVICE_NAME AND
        httpRequest.status>=400 AND httpRequest.status<500 AND
        timestamp >= \"$(date -u -d "$HOURS_TO_CHECK hours ago" +%Y-%m-%dT%H:%M:%SZ)\"
    " --project="$PROJECT_ID" --format="value(httpRequest.status,httpRequest.requestUrl)" --limit=1000)
    
    if [ -n "$ERROR_4XX" ]; then
        ERROR_4XX_COUNT=$(echo "$ERROR_4XX" | wc -l)
        print_status "Found $ERROR_4XX_COUNT 4xx errors in the last $HOURS_TO_CHECK hours"
        
        # Check for common attack patterns
        ATTACK_PATTERNS=$(echo "$ERROR_4XX" | grep -i -E "(wp-admin|phpmyadmin|admin|\.php|\.asp|\.jsp|sql|script|exec|eval)" | head -10)
        if [ -n "$ATTACK_PATTERNS" ]; then
            print_warning "Potential attack patterns detected:"
            echo "$ATTACK_PATTERNS"
        fi
    fi
}

# Function to check authentication anomalies
check_auth_anomalies() {
    print_status "Checking authentication anomalies..."
    
    # Query for unusual authentication patterns
    AUTH_LOGS=$(gcloud logging read "
        resource.type=cloud_run_revision AND
        resource.labels.service_name=$SERVICE_NAME AND
        (textPayload:\"Authentication\" OR textPayload:\"Login\" OR textPayload:\"Token\") AND
        timestamp >= \"$(date -u -d "$HOURS_TO_CHECK hours ago" +%Y-%m-%dT%H:%M:%SZ)\"
    " --project="$PROJECT_ID" --format="value(timestamp,textPayload)" --limit=1000)
    
    if [ -n "$AUTH_LOGS" ]; then
        # Check for expired tokens
        EXPIRED_TOKENS=$(echo "$AUTH_LOGS" | grep -i "expired" | wc -l)
        if [ "$EXPIRED_TOKENS" -gt 0 ]; then
            print_warning "Found $EXPIRED_TOKENS expired token attempts"
        fi
        
        # Check for invalid tokens
        INVALID_TOKENS=$(echo "$AUTH_LOGS" | grep -i "invalid" | wc -l)
        if [ "$INVALID_TOKENS" -gt 0 ]; then
            print_warning "Found $INVALID_TOKENS invalid token attempts"
        fi
    fi
}

# Function to check resource usage anomalies
check_resource_anomalies() {
    print_status "Checking resource usage anomalies..."
    
    # Query Cloud Monitoring for high CPU/Memory usage
    HIGH_CPU=$(gcloud monitoring metrics list \
        --filter="metric.type:run.googleapis.com/container/cpu/utilizations" \
        --project="$PROJECT_ID" 2>/dev/null || echo "")
    
    if [ -n "$HIGH_CPU" ]; then
        print_status "CPU monitoring data available"
    else
        print_warning "No CPU monitoring data found"
    fi
    
    # Check for memory usage spikes
    HIGH_MEMORY=$(gcloud monitoring metrics list \
        --filter="metric.type:run.googleapis.com/container/memory/utilizations" \
        --project="$PROJECT_ID" 2>/dev/null || echo "")
    
    if [ -n "$HIGH_MEMORY" ]; then
        print_status "Memory monitoring data available"
    else
        print_warning "No memory monitoring data found"
    fi
}

# Function to check SSL/TLS certificates
check_ssl_certificates() {
    print_status "Checking SSL/TLS certificates..."
    
    # Get service URL
    SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" \
        --region="$REGION" \
        --project="$PROJECT_ID" \
        --format='value(status.url)' 2>/dev/null || echo "")
    
    if [ -n "$SERVICE_URL" ]; then
        DOMAIN=$(echo "$SERVICE_URL" | sed 's|https://||' | sed 's|/.*||')
        
        # Check certificate expiration
        CERT_INFO=$(echo | openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" 2>/dev/null | openssl x509 -noout -dates 2>/dev/null || echo "")
        
        if [ -n "$CERT_INFO" ]; then
            print_success "SSL certificate information retrieved"
            echo "$CERT_INFO"
        else
            print_warning "Unable to retrieve SSL certificate information"
        fi
    else
        print_warning "Unable to retrieve service URL"
    fi
}

# Function to generate security report
generate_security_report() {
    print_status "Generating security report..."
    
    REPORT_FILE="security-report-$(date +%Y%m%d-%H%M%S).txt"
    
    {
        echo "=================================="
        echo "SECURITY MONITORING REPORT"
        echo "=================================="
        echo "Project: $PROJECT_ID"
        echo "Service: $SERVICE_NAME"
        echo "Region: $REGION"
        echo "Report Time: $(date)"
        echo "Period: Last $HOURS_TO_CHECK hours"
        echo "=================================="
        echo ""
    } > "$REPORT_FILE"
    
    print_success "Security report generated: $REPORT_FILE"
}

# Main execution
main() {
    echo "🔐 Enterprise Backend Security Monitoring"
    echo "=========================================="
    echo ""
    
    check_failed_logins
    echo ""
    
    check_suspicious_api_calls
    echo ""
    
    check_error_rates
    echo ""
    
    check_auth_anomalies
    echo ""
    
    check_resource_anomalies
    echo ""
    
    check_ssl_certificates
    echo ""
    
    generate_security_report
    
    print_success "Security monitoring completed!"
}

# Run main function
main
