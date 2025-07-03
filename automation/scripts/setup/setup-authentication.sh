#!/bin/bash
# =============================================================================
# ENTERPRISE BACKEND - AUTHENTICATION SETUP SCRIPT
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

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if project ID is provided
if [ -z "$1" ]; then
    print_error "Usage: $0 <PROJECT_ID>"
    exit 1
fi

PROJECT_ID="$1"

print_status "Setting up authentication for project: $PROJECT_ID"

# 1. Authenticate with Google Cloud
print_status "Authenticating with Google Cloud..."
gcloud auth login --brief
gcloud config set project "$PROJECT_ID"
gcloud auth application-default login

# 2. Enable required APIs
print_status "Enabling required APIs..."
gcloud services enable \
    run.googleapis.com \
    cloudbuild.googleapis.com \
    containerregistry.googleapis.com \
    secretmanager.googleapis.com \
    monitoring.googleapis.com \
    logging.googleapis.com \
    --project="$PROJECT_ID"

# 3. Create service account
print_status "Creating service account..."
SA_NAME="enterprise-backend-sa"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

if ! gcloud iam service-accounts describe "$SA_EMAIL" --project="$PROJECT_ID" &> /dev/null; then
    gcloud iam service-accounts create "$SA_NAME" \
        --display-name="Enterprise Backend Service Account" \
        --description="Service account for enterprise backend application" \
        --project="$PROJECT_ID"
    
    # Grant necessary roles
    for role in "roles/cloudsql.client" "roles/secretmanager.secretAccessor" "roles/monitoring.metricWriter" "roles/logging.logWriter"; do
        gcloud projects add-iam-policy-binding "$PROJECT_ID" \
            --member="serviceAccount:$SA_EMAIL" \
            --role="$role"
    done
    
    print_success "Service account created and configured"
else
    print_status "Service account already exists"
fi

# 4. Create Secret Manager secrets
print_status "Creating Secret Manager secrets..."

# Function to create secret if it doesn't exist
create_secret() {
    local secret_id="$1"
    local secret_value="$2"
    
    if ! gcloud secrets describe "$secret_id" --project="$PROJECT_ID" &> /dev/null; then
        echo -n "$secret_value" | gcloud secrets create "$secret_id" \
            --data-file=- \
            --project="$PROJECT_ID"
        print_success "Created secret: $secret_id"
    else
        print_status "Secret already exists: $secret_id"
    fi
}

# Generate secure secrets
JWT_SECRET=$(openssl rand -base64 32)
API_KEY_SECRET=$(openssl rand -base64 32)
CSRF_SECRET=$(openssl rand -base64 32)
SESSION_SECRET=$(openssl rand -base64 32)

create_secret "jwt-secret" "$JWT_SECRET"
create_secret "api-key-secret" "$API_KEY_SECRET"
create_secret "csrf-secret" "$CSRF_SECRET"
create_secret "session-secret" "$SESSION_SECRET"

# 5. Display OAuth setup instructions
print_status "OAuth 2.0 Setup Instructions:"
echo ""
echo "1. Go to Google Cloud Console OAuth consent screen:"
echo "   https://console.cloud.google.com/apis/credentials/consent?project=$PROJECT_ID"
echo ""
echo "2. Configure OAuth consent screen:"
echo "   - User Type: External (for public apps) or Internal (for organization)"
echo "   - App name: Your Enterprise Backend"
echo "   - User support email: your-email@domain.com"
echo "   - Scopes: email, profile, openid"
echo ""
echo "3. Create OAuth 2.0 credentials:"
echo "   https://console.cloud.google.com/apis/credentials?project=$PROJECT_ID"
echo "   - Click 'Create Credentials' > 'OAuth 2.0 Client IDs'"
echo "   - Application type: Web application"
echo "   - Authorized redirect URIs:"
echo "     - http://localhost:8080/auth/google/callback (for local dev)"
echo "     - https://your-domain.com/auth/google/callback (for production)"
echo ""
echo "4. Download the credentials and save as 'google-oauth-credentials.json'"
echo ""
echo "5. Add the credentials to Secret Manager:"
echo "   gcloud secrets create google-oauth-credentials \\"
echo "     --data-file=google-oauth-credentials.json \\"
echo "     --project=$PROJECT_ID"
echo ""

print_success "Authentication setup completed!"
print_status "Next steps:"
echo "1. Complete OAuth 2.0 setup following the instructions above"
echo "2. Configure your environment variables"
echo "3. Deploy your application"
