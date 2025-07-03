# =============================================================================
# TERRAFORM OUTPUTS - ENTERPRISE BACKEND
# =============================================================================

output "service_url" {
  description = "URL of the deployed Cloud Run service"
  value       = google_cloud_run_service.backend.status[0].url
}

output "service_name" {
  description = "Name of the Cloud Run service"
  value       = google_cloud_run_service.backend.name
}

output "service_account_email" {
  description = "Email of the service account"
  value       = google_service_account.backend_sa.email
}

output "project_id" {
  description = "Google Cloud Project ID"
  value       = var.project_id
}

output "region" {
  description = "Google Cloud Region"
  value       = var.region
}

output "environment" {
  description = "Environment name"
  value       = var.environment
}

# Database outputs (conditional)
output "database_connection_name" {
  description = "Cloud SQL connection name"
  value       = var.enable_database ? google_sql_database_instance.postgres[0].connection_name : null
}

output "database_instance_name" {
  description = "Cloud SQL instance name"
  value       = var.enable_database ? google_sql_database_instance.postgres[0].name : null
}

# Network outputs (conditional)
output "vpc_network_name" {
  description = "VPC network name"
  value       = var.enable_vpc ? google_compute_network.vpc[0].name : null
}

output "vpc_subnet_name" {
  description = "VPC subnet name"
  value       = var.enable_vpc ? google_compute_subnetwork.subnet[0].name : null
}

# Redis outputs (conditional)
output "redis_instance_name" {
  description = "Redis instance name"
  value       = var.enable_redis ? google_redis_instance.cache[0].name : null
}

output "redis_host" {
  description = "Redis host IP"
  value       = var.enable_redis ? google_redis_instance.cache[0].host : null
}

# Secret Manager outputs
output "jwt_secret_name" {
  description = "JWT secret name in Secret Manager"
  value       = google_secret_manager_secret.jwt_secret.secret_id
}

output "api_key_secret_name" {
  description = "API key secret name in Secret Manager"
  value       = google_secret_manager_secret.api_key_secret.secret_id
}

# Security configuration
output "security_configuration" {
  description = "Security configuration summary"
  value = {
    security_headers_enabled = var.security_headers_enabled
    rate_limit_per_minute   = var.rate_limit_per_minute
    max_login_attempts      = var.max_login_attempts
    lockout_duration_minutes = var.lockout_duration_minutes
    jwt_expiration_hours    = var.jwt_expiration_hours
    session_timeout_minutes = var.session_timeout_minutes
  }
}

# Deployment information
output "deployment_commands" {
  description = "Commands to deploy the application"
  value = {
    build_and_deploy = "gcloud run deploy ${var.service_name} --source . --region ${var.region}"
    update_image     = "gcloud run deploy ${var.service_name} --image gcr.io/${var.project_id}/${var.service_name} --region ${var.region}"
    view_logs        = "gcloud run services logs read ${var.service_name} --region ${var.region}"
  }
}

# Monitoring
output "monitoring_dashboard_url" {
  description = "URL to Cloud Run monitoring dashboard"
  value       = "https://console.cloud.google.com/run/detail/${var.region}/${var.service_name}/metrics?project=${var.project_id}"
}

output "alert_policy_name" {
  description = "Name of the created alert policy"
  value       = google_monitoring_alert_policy.high_error_rate.display_name
}
