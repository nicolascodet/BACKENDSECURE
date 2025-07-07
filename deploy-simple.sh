#!/bin/bash

# Simple deployment script for Google Cloud Run
set -e

PROJECT_ID="relevant-backend-production"
SERVICE_NAME="relevant-backend"
REGION="us-central1"
IMAGE_URL="us-central1-docker.pkg.dev/${PROJECT_ID}/cloud-run-source-deploy/${SERVICE_NAME}:latest"

echo "🚀 Starting deployment to Google Cloud Run..."

# Build and push the image
echo "📦 Building Docker image with Cloud Build..."
gcloud builds submit --tag $IMAGE_URL --project $PROJECT_ID .

# Deploy to Cloud Run
echo "☁️  Deploying to Cloud Run..."
gcloud run deploy $SERVICE_NAME \
  --image $IMAGE_URL \
  --platform managed \
  --region $REGION \
  --allow-unauthenticated \
  --memory 512Mi \
  --max-instances 10 \
  --set-env-vars="ENVIRONMENT=production,SECURITY_HEADERS=true,JWT_SECRET_KEY=temp-jwt-secret-for-testing,API_KEY_SECRET=temp-api-key-for-testing" \
  --project $PROJECT_ID

# Get the service URL
SERVICE_URL=$(gcloud run services describe $SERVICE_NAME --region $REGION --format 'value(status.url)' --project $PROJECT_ID)

echo "✅ Deployment complete!"
echo "🔗 Service URL: $SERVICE_URL"
echo ""
echo "📋 Test the endpoints:"
echo "  curl ${SERVICE_URL}/health"
echo "  curl ${SERVICE_URL}/config"