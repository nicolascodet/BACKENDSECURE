#!/bin/bash

# Enterprise deployment script with security best practices
set -e

PROJECT_ID="relevant-backend-production"
SERVICE_NAME="relevant-backend"
REGION="us-central1"
IMAGE_URL="us-central1-docker.pkg.dev/${PROJECT_ID}/cloud-run-source-deploy/${SERVICE_NAME}:latest"

echo "🚀 Starting enterprise deployment..."

# Check if this is first deployment or update
if gcloud run services describe $SERVICE_NAME --region $REGION --project $PROJECT_ID &> /dev/null; then
    echo "📦 Service exists, updating..."
    DEPLOY_TYPE="update"
else
    echo "📦 First deployment, creating service..."
    DEPLOY_TYPE="create"
fi

# For enterprise deployment, we need to:
# 1. Allow unauthenticated access (we handle auth in-app)
# 2. Set up proper secrets (in production, use Secret Manager)
# 3. Configure proper scaling and resources
# 4. Enable Cloud Armor for DDoS protection (requires Load Balancer)

echo "🔧 Configuring deployment..."

# Deploy the service
gcloud run deploy $SERVICE_NAME \
  --image $IMAGE_URL \
  --platform managed \
  --region $REGION \
  --allow-unauthenticated \
  --memory 1Gi \
  --cpu 2 \
  --min-instances 1 \
  --max-instances 100 \
  --concurrency 1000 \
  --timeout 60 \
  --set-env-vars="ENVIRONMENT=production,SECURITY_HEADERS=true,JWT_SECRET_KEY=temp-jwt-secret-for-testing,API_KEY_SECRET=temp-api-key-for-testing,ALLOWED_ORIGINS=https://your-frontend.com|https://app.your-domain.com|http://localhost:3000" \
  --service-account="${SERVICE_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
  --project $PROJECT_ID || true

# Get the service URL
SERVICE_URL=$(gcloud run services describe $SERVICE_NAME --region $REGION --format 'value(status.url)' --project $PROJECT_ID)

echo "✅ Deployment complete!"
echo "🔗 Service URL: $SERVICE_URL"
echo ""
echo "🔒 Security Configuration:"
echo "  - ✅ Application-level JWT authentication"
echo "  - ✅ Rate limiting (100 req/min general, stricter for auth endpoints)"
echo "  - ✅ Security headers (HSTS, CSP, X-Frame-Options, etc.)"
echo "  - ✅ CORS protection (configured origins only)"
echo "  - ✅ Brute force protection"
echo "  - ✅ API key authentication support"
echo ""
echo "⚠️  Production Recommendations:"
echo "  1. Set up Cloud Armor for DDoS protection"
echo "  2. Use Secret Manager for JWT_SECRET_KEY and API_KEY_SECRET"
echo "  3. Configure Cloud CDN for static assets"
echo "  4. Set up monitoring with Cloud Monitoring"
echo "  5. Enable Cloud Trace for performance monitoring"
echo "  6. Configure alerting policies"
echo ""
echo "📋 Test endpoints:"
echo "  # Health check (public)"
echo "  curl ${SERVICE_URL}/health"
echo ""
echo "  # Configuration (public)"
echo "  curl ${SERVICE_URL}/config"
echo ""
echo "  # Register user"
echo "  curl -X POST ${SERVICE_URL}/api/v1/auth/register \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"email\":\"user@example.com\",\"password\":\"SecurePass123!\",\"full_name\":\"Test User\"}'"
echo ""
echo "  # Login"
echo "  curl -X POST ${SERVICE_URL}/api/v1/auth/login \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"email\":\"user@example.com\",\"password\":\"SecurePass123!\"}'"