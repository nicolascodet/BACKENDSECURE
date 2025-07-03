# =============================================================================
# TERRAFORM VARIABLES - ENTERPRISE BACKEND
# =============================================================================

variable "project_id" {
  description = "Google Cloud Project ID"
  type        = string
  validation {
    condition     = length(var.project_id) > 0
    error_message = "Project ID must not be empty."
  }
}

variable "region" {
  description = "Google Cloud Region for resources"
  type        = string
  default     = "us-central1"
  validation {
    condition = contains([
      "us-central1", "us-east1", "us-west1", "us-west2",
      "europe-west1", "europe-west2", "asia-southeast1"
    ], var.region)
    error_message = "Region must be a valid Google Cloud region."
  }
}

variable "environment" {
  description = "Environment name (staging, production, development)"
  type        = string
  default     = "production"
  validation {
    condition     = contains(["staging", "production", "development"], var.environment)
    error_message = "Environment must be staging, production, or development."
  }
}

variable "service_name" {
  description = "Name of the backend service"
  type        = string
  default     = "enterprise-backend"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]*[a-z0-9]$", var.service_name))
    error_message = "Service name must be lowercase, start with letter, and contain only letters, numbers, and hyphens."
  }
}

variable "min_instances" {
  description = "Minimum number of Cloud Run instances"
  type        = number
  default     = 0
}

variable "max_instances" {
  description = "Maximum number of Cloud Run instances"
  type        = number
  default     = 100
}

variable "cpu_limit" {
  description = "CPU limit for Cloud Run instances"
  type        = string
  default     = "2"
}

variable "memory_limit" {
  description = "Memory limit for Cloud Run instances"
  type        = string
  default     = "2Gi"
}

variable "enable_database" {
  description = "Whether to create Cloud SQL database"
  type        = bool
  default     = false
}

variable "enable_redis" {
  description = "Whether to create Redis cache"
  type        = bool
  default     = false
}

variable "enable_vpc" {
  description = "Whether to create VPC network"
  type        = bool
  default     = false
}

variable "database_tier" {
  description = "Cloud SQL database tier"
  type        = string
  default     = "db-f1-micro"
}

variable "redis_memory_gb" {
  description = "Redis memory size in GB"
  type        = number
  default     = 1
}

variable "backup_retention_days" {
  description = "Number of days to retain database backups"
  type        = number
  default     = 7
}

variable "alert_notification_channels" {
  description = "List of notification channels for alerts"
  type        = list(string)
  default     = []
}

variable "cors_allowed_origins" {
  description = "List of allowed CORS origins"
  type        = list(string)
  default     = ["https://your-frontend.com"]
}

variable "security_headers_enabled" {
  description = "Whether to enable security headers"
  type        = bool
  default     = true
}

variable "rate_limit_per_minute" {
  description = "Rate limit per minute for API requests"
  type        = number
  default     = 100
}

variable "max_login_attempts" {
  description = "Maximum login attempts before lockout"
  type        = number
  default     = 5
}

variable "lockout_duration_minutes" {
  description = "Lockout duration in minutes after max failed attempts"
  type        = number
  default     = 15
}

variable "jwt_expiration_hours" {
  description = "JWT token expiration time in hours"
  type        = number
  default     = 24
}

variable "session_timeout_minutes" {
  description = "Session timeout in minutes"
  type        = number
  default     = 30
}
