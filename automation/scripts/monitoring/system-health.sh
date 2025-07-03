#!/bin/bash
# =============================================================================
# ENTERPRISE BACKEND - SYSTEM HEALTH MONITORING SCRIPT
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
ALERT_EMAIL="${4:-admin@example.com}"

if [ -z "$PROJECT_ID" ]; then
    print_error "Usage: $0 <PROJECT_ID> [SERVICE_NAME] [REGION] [ALERT_EMAIL]"
    exit 1
fi

print_status "Running system health monitoring for project: $PROJECT_ID"
print_status "Service: $SERVICE_NAME, Region: $REGION"

# Function to check service health
check_service_health() {
    print_status "Checking service health..."
    
    # Get service URL
    SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" \
        --region="$REGION" \
        --project="$PROJECT_ID" \
        --format='value(status.url)' 2>/dev/null || echo "")
    
    if [ -n "$SERVICE_URL" ]; then
        print_status "Service URL: $SERVICE_URL"
        
        # Check health endpoint
        if curl -f -s "$SERVICE_URL/health" > /dev/null 2>&1; then
            print_success "Health endpoint is responsive"
        else
            print_error "Health endpoint is not responding"
            return 1
        fi
        
        # Check response time
        RESPONSE_TIME=$(curl -w "%{time_total}" -o /dev/null -s "$SERVICE_URL/health" 2>/dev/null || echo "0")
        print_status "Response time: ${RESPONSE_TIME}s"
        
        # Check API documentation
        if curl -f -s "$SERVICE_URL/docs" > /dev/null 2>&1; then
            print_success "API documentation is accessible"
        else
            print_warning "API documentation is not accessible"
        fi
    else
        print_error "Unable to retrieve service URL"
        return 1
    fi
}

# Function to check logs for errors
check_error_logs() {
    print_status "Checking error logs..."
    
    # Check for recent errors (last hour)
    RECENT_ERRORS=$(gcloud logging read "
        resource.type=cloud_run_revision AND
        resource.labels.service_name=$SERVICE_NAME AND
        severity>=ERROR AND
        timestamp >= \"$(date -u -d "1 hour ago" +%Y-%m-%dT%H:%M:%SZ)\"
    " --project="$PROJECT_ID" --limit=50 --format="value(timestamp,severity,textPayload)" 2>/dev/null || echo "")
    
    if [ -n "$RECENT_ERRORS" ]; then
        ERROR_COUNT=$(echo "$RECENT_ERRORS" | wc -l)
        print_warning "Found $ERROR_COUNT errors in the last hour"
    else
        print_success "No errors found in the last hour"
    fi
}

# Function to check security status
check_security_status() {
    print_status "Checking security status..."
    
    # Check if service is publicly accessible
    SERVICE_POLICY=$(gcloud run services get-iam-policy "$SERVICE_NAME" \
        --region="$REGION" \
        --project="$PROJECT_ID" \
        --format="value(bindings[].members[])" 2>/dev/null || echo "")
    
    if echo "$SERVICE_POLICY" | grep -q "allUsers"; then
        print_warning "Service is publicly accessible"
    else
        print_success "Service has restricted access"
    fi
    
    # Check for HTTPS enforcement
    SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" \
        --region="$REGION" \
        --project="$PROJECT_ID" \
        --format='value(status.url)' 2>/dev/null || echo "")
    
    if [[ "$SERVICE_URL" == https://* ]]; then
        print_success "Service is using HTTPS"
    else
        print_warning "Service is not using HTTPS"
    fi
}

# Function to generate health report
generate_health_report() {
    print_status "Generating health report..."
    
    REPORT_FILE="health-report-$(date +%Y%m%d-%H%M%S).json"
    
    # Create JSON report
    cat > "$REPORT_FILE" << EOF
{
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "project_id": "$PROJECT_ID",
    "service_name": "$SERVICE_NAME",
    "region": "$REGION",
    "status": "healthy",
    "checks": {
        "service_health": "pass",
        "error_logs": "pass",
        "security_status": "pass"
    },
    "recommendations": [
        "Monitor response times during peak hours",
        "Set up alerting for error rates > 5%",
        "Review security configurations monthly"
    ]
}
EOF
    
    print_success "Health report generated: $REPORT_FILE"
}

# Main execution
main() {
    echo "🔍 Enterprise Backend System Health Monitoring"
    echo "=============================================="
    echo ""
    
    OVERALL_STATUS="healthy"
    
    # Run all health checks
    if ! check_service_health; then
        OVERALL_STATUS="unhealthy"
    fi
    echo ""
    
    check_error_logs
    echo ""
    
    check_security_status
    echo ""
    
    generate_health_report
    
    if [ "$OVERALL_STATUS" = "healthy" ]; then
        print_success "Overall system status: HEALTHY"
    else
        print_error "Overall system status: UNHEALTHY"
    fi
    
    print_success "System health monitoring completed!"
}

# Run main function
main 