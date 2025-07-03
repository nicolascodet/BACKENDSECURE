#!/bin/bash
# =============================================================================
# ENTERPRISE BACKEND - DATABASE MAINTENANCE SCRIPT
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
INSTANCE_NAME="${2:-enterprise-backend-db}"
BACKUP_RETENTION_DAYS="${3:-30}"
REGION="${4:-us-central1}"

if [ -z "$PROJECT_ID" ]; then
    print_error "Usage: $0 <PROJECT_ID> [INSTANCE_NAME] [BACKUP_RETENTION_DAYS] [REGION]"
    exit 1
fi

print_status "Running database maintenance for project: $PROJECT_ID"
print_status "Instance: $INSTANCE_NAME, Region: $REGION"

# Function to create manual backup
create_manual_backup() {
    print_status "Creating manual backup..."
    
    BACKUP_ID="${INSTANCE_NAME}-manual-$(date +%Y%m%d-%H%M%S)"
    
    if gcloud sql instances describe "$INSTANCE_NAME" --project="$PROJECT_ID" &> /dev/null; then
        gcloud sql backups create \
            --instance="$INSTANCE_NAME" \
            --description="Manual backup created by maintenance script" \
            --project="$PROJECT_ID" \
            --quiet
        
        print_success "Manual backup created successfully"
    else
        print_warning "Database instance $INSTANCE_NAME not found"
    fi
}

# Function to clean up old backups
cleanup_old_backups() {
    print_status "Cleaning up old backups..."
    
    if gcloud sql instances describe "$INSTANCE_NAME" --project="$PROJECT_ID" &> /dev/null; then
        # Get list of backups older than retention period
        CUTOFF_DATE=$(date -d "$BACKUP_RETENTION_DAYS days ago" +%Y-%m-%d)
        
        OLD_BACKUPS=$(gcloud sql backups list \
            --instance="$INSTANCE_NAME" \
            --project="$PROJECT_ID" \
            --format="value(id)" \
            --filter="startTime < '$CUTOFF_DATE'" \
            --limit=50)
        
        if [ -n "$OLD_BACKUPS" ]; then
            BACKUP_COUNT=$(echo "$OLD_BACKUPS" | wc -l)
            print_status "Found $BACKUP_COUNT old backups to clean up"
            
            # Delete old backups
            for backup_id in $OLD_BACKUPS; do
                gcloud sql backups delete "$backup_id" \
                    --instance="$INSTANCE_NAME" \
                    --project="$PROJECT_ID" \
                    --quiet
                print_status "Deleted backup: $backup_id"
            done
            
            print_success "Cleaned up $BACKUP_COUNT old backups"
        else
            print_success "No old backups found to clean up"
        fi
    else
        print_warning "Database instance $INSTANCE_NAME not found"
    fi
}

# Function to check database health
check_database_health() {
    print_status "Checking database health..."
    
    if gcloud sql instances describe "$INSTANCE_NAME" --project="$PROJECT_ID" &> /dev/null; then
        # Get instance details
        INSTANCE_STATUS=$(gcloud sql instances describe "$INSTANCE_NAME" \
            --project="$PROJECT_ID" \
            --format="value(state)")
        
        if [ "$INSTANCE_STATUS" = "RUNNABLE" ]; then
            print_success "Database instance is healthy (RUNNABLE)"
        else
            print_warning "Database instance status: $INSTANCE_STATUS"
        fi
        
        # Check disk usage
        DISK_USAGE=$(gcloud sql instances describe "$INSTANCE_NAME" \
            --project="$PROJECT_ID" \
            --format="value(settings.dataDiskSizeGb)")
        
        print_status "Disk size: ${DISK_USAGE}GB"
        
        # Check backup configuration
        BACKUP_ENABLED=$(gcloud sql instances describe "$INSTANCE_NAME" \
            --project="$PROJECT_ID" \
            --format="value(settings.backupConfiguration.enabled)")
        
        if [ "$BACKUP_ENABLED" = "True" ]; then
            print_success "Automated backups are enabled"
        else
            print_warning "Automated backups are disabled"
        fi
        
        # Check point-in-time recovery
        PITR_ENABLED=$(gcloud sql instances describe "$INSTANCE_NAME" \
            --project="$PROJECT_ID" \
            --format="value(settings.backupConfiguration.pointInTimeRecoveryEnabled)")
        
        if [ "$PITR_ENABLED" = "True" ]; then
            print_success "Point-in-time recovery is enabled"
        else
            print_warning "Point-in-time recovery is disabled"
        fi
    else
        print_warning "Database instance $INSTANCE_NAME not found"
    fi
}

# Function to check database connections
check_database_connections() {
    print_status "Checking database connections..."
    
    if gcloud sql instances describe "$INSTANCE_NAME" --project="$PROJECT_ID" &> /dev/null; then
        # Get connection info
        CONNECTION_NAME=$(gcloud sql instances describe "$INSTANCE_NAME" \
            --project="$PROJECT_ID" \
            --format="value(connectionName)")
        
        print_status "Connection name: $CONNECTION_NAME"
        
        # Check if Cloud SQL Proxy is needed
        IP_CONFIG=$(gcloud sql instances describe "$INSTANCE_NAME" \
            --project="$PROJECT_ID" \
            --format="value(settings.ipConfiguration.ipv4Enabled)")
        
        if [ "$IP_CONFIG" = "True" ]; then
            print_warning "Public IP is enabled - consider using private IP for security"
        else
            print_success "Public IP is disabled - using private network"
        fi
        
        # Check authorized networks
        AUTHORIZED_NETWORKS=$(gcloud sql instances describe "$INSTANCE_NAME" \
            --project="$PROJECT_ID" \
            --format="value(settings.ipConfiguration.authorizedNetworks[].value)" 2>/dev/null || echo "")
        
        if [ -n "$AUTHORIZED_NETWORKS" ]; then
            print_status "Authorized networks:"
            echo "$AUTHORIZED_NETWORKS"
        else
            print_success "No authorized networks configured (using private network)"
        fi
    fi
}

# Function to analyze database performance
analyze_database_performance() {
    print_status "Analyzing database performance..."
    
    if gcloud sql instances describe "$INSTANCE_NAME" --project="$PROJECT_ID" &> /dev/null; then
        # Get instance tier
        INSTANCE_TIER=$(gcloud sql instances describe "$INSTANCE_NAME" \
            --project="$PROJECT_ID" \
            --format="value(settings.tier)")
        
        print_status "Instance tier: $INSTANCE_TIER"
        
        # Get availability type
        AVAILABILITY_TYPE=$(gcloud sql instances describe "$INSTANCE_NAME" \
            --project="$PROJECT_ID" \
            --format="value(settings.availabilityType)")
        
        print_status "Availability type: $AVAILABILITY_TYPE"
        
        # Check if there are any read replicas
        READ_REPLICAS=$(gcloud sql instances list \
            --project="$PROJECT_ID" \
            --filter="masterInstanceName:$INSTANCE_NAME" \
            --format="value(name)" 2>/dev/null || echo "")
        
        if [ -n "$READ_REPLICAS" ]; then
            print_status "Read replicas found:"
            echo "$READ_REPLICAS"
        else
            print_status "No read replicas configured"
        fi
    fi
}

# Function to update database configuration
update_database_configuration() {
    print_status "Checking database configuration..."
    
    if gcloud sql instances describe "$INSTANCE_NAME" --project="$PROJECT_ID" &> /dev/null; then
        # Check database flags
        DATABASE_FLAGS=$(gcloud sql instances describe "$INSTANCE_NAME" \
            --project="$PROJECT_ID" \
            --format="value(settings.databaseFlags[].name,settings.databaseFlags[].value)" 2>/dev/null || echo "")
        
        if [ -n "$DATABASE_FLAGS" ]; then
            print_status "Database flags configured:"
            echo "$DATABASE_FLAGS"
        else
            print_status "No custom database flags configured"
        fi
        
        # Check maintenance window
        MAINTENANCE_WINDOW=$(gcloud sql instances describe "$INSTANCE_NAME" \
            --project="$PROJECT_ID" \
            --format="value(settings.maintenanceWindow.day,settings.maintenanceWindow.hour)" 2>/dev/null || echo "")
        
        if [ -n "$MAINTENANCE_WINDOW" ]; then
            print_status "Maintenance window: $MAINTENANCE_WINDOW"
        else
            print_status "No maintenance window configured"
        fi
    fi
}

# Function to generate maintenance report
generate_maintenance_report() {
    print_status "Generating maintenance report..."
    
    REPORT_FILE="db-maintenance-report-$(date +%Y%m%d-%H%M%S).txt"
    
    {
        echo "=================================="
        echo "DATABASE MAINTENANCE REPORT"
        echo "=================================="
        echo "Project: $PROJECT_ID"
        echo "Instance: $INSTANCE_NAME"
        echo "Region: $REGION"
        echo "Report Time: $(date)"
        echo "Retention Policy: $BACKUP_RETENTION_DAYS days"
        echo "=================================="
        echo ""
        
        if gcloud sql instances describe "$INSTANCE_NAME" --project="$PROJECT_ID" &> /dev/null; then
            echo "Instance Status: $(gcloud sql instances describe "$INSTANCE_NAME" --project="$PROJECT_ID" --format="value(state)")"
            echo "Disk Size: $(gcloud sql instances describe "$INSTANCE_NAME" --project="$PROJECT_ID" --format="value(settings.dataDiskSizeGb)")GB"
            echo "Tier: $(gcloud sql instances describe "$INSTANCE_NAME" --project="$PROJECT_ID" --format="value(settings.tier)")"
            echo "Backup Enabled: $(gcloud sql instances describe "$INSTANCE_NAME" --project="$PROJECT_ID" --format="value(settings.backupConfiguration.enabled)")"
            echo "PITR Enabled: $(gcloud sql instances describe "$INSTANCE_NAME" --project="$PROJECT_ID" --format="value(settings.backupConfiguration.pointInTimeRecoveryEnabled)")"
        else
            echo "Instance not found"
        fi
        
        echo ""
        echo "Maintenance completed at: $(date)"
    } > "$REPORT_FILE"
    
    print_success "Maintenance report generated: $REPORT_FILE"
}

# Main execution
main() {
    echo "🛠️  Enterprise Backend Database Maintenance"
    echo "==========================================="
    echo ""
    
    create_manual_backup
    echo ""
    
    cleanup_old_backups
    echo ""
    
    check_database_health
    echo ""
    
    check_database_connections
    echo ""
    
    analyze_database_performance
    echo ""
    
    update_database_configuration
    echo ""
    
    generate_maintenance_report
    
    print_success "Database maintenance completed!"
}

# Run main function
main
