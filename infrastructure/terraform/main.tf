# =============================================================================
# ENTERPRISE FASTAPI BACKEND - TERRAFORM INFRASTRUCTURE
# =============================================================================

terraform {
  required_version = ">= 1.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
  }
}

# Variables
variable "project_id" {
  description = "Google Cloud Project ID"
  type        = string
}

variable "region" {
  description = "Google Cloud Region"
  type        = string
  default     = "us-central1"
}

variable "environment" {
  description = "Environment (staging/production)"
  type        = string
  default     = "production"
}

variable "service_name" {
  description = "Name of the Cloud Run service"
  type        = string
  default     = "enterprise-backend"
}

# Provider
provider "google" {
  project = var.project_id
  region  = var.region
}

# Enable APIs
resource "google_project_service" "apis" {
  for_each = toset([
    "run.googleapis.com",
    "cloudbuild.googleapis.com",
    "secretmanager.googleapis.com",
    "sql.googleapis.com",
    "redis.googleapis.com",
    "monitoring.googleapis.com",
    "logging.googleapis.com"
  ])
  
  project = var.project_id
  service = each.value
  
  disable_on_destroy = false
}

# Service Account for Cloud Run
resource "google_service_account" "backend_sa" {
  account_id   = "${var.service_name}-sa"
  display_name = "Enterprise Backend Service Account"
  description  = "Service account for enterprise backend application"
}

# IAM roles for service account
resource "google_project_iam_member" "backend_sa_roles" {
  for_each = toset([
    "roles/cloudsql.client",
    "roles/secretmanager.secretAccessor",
    "roles/monitoring.metricWriter",
    "roles/logging.logWriter"
  ])
  
  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.backend_sa.email}"
}

# Cloud Run Service
resource "google_cloud_run_service" "backend" {
  name     = var.service_name
  location = var.region
  
  template {
    metadata {
      annotations = {
        "autoscaling.knative.dev/maxScale"      = "100"
        "run.googleapis.com/cloudsql-instances" = try(google_sql_database_instance.postgres[0].connection_name, "")
        "run.googleapis.com/service-account"    = google_service_account.backend_sa.email
      }
    }
    
    spec {
      containers {
        image = "gcr.io/cloudrun/hello" # Placeholder - will be updated by CI/CD
        
        ports {
          container_port = 8080
        }
        
        resources {
          limits = {
            cpu    = "2"
            memory = "2Gi"
          }
        }
        
        env {
          name  = "ENVIRONMENT"
          value = var.environment
        }
        
        env {
          name  = "GOOGLE_CLOUD_PROJECT"
          value = var.project_id
        }
        
        # Security configuration
        env {
          name  = "SECURITY_HEADERS"
          value = "true"
        }
        
        env {
          name  = "RATE_LIMIT_PER_MINUTE"
          value = "100"
        }
        
        env {
          name  = "MAX_LOGIN_ATTEMPTS"
          value = "5"
        }
        
        env {
          name  = "LOCKOUT_DURATION_MINUTES"
          value = "15"
        }
      }
      
      service_account_name = google_service_account.backend_sa.email
    }
  }
  
  traffic {
    percent         = 100
    latest_revision = true
  }
  
  depends_on = [google_project_service.apis]
}

# IAM for Cloud Run (allow authenticated access)
resource "google_cloud_run_service_iam_member" "authenticated_access" {
  location = google_cloud_run_service.backend.location
  project  = google_cloud_run_service.backend.project
  service  = google_cloud_run_service.backend.name
  role     = "roles/run.invoker"
  member   = "allUsers" # Change to specific users/groups in production
}

# Optional: Cloud SQL PostgreSQL Instance
resource "google_sql_database_instance" "postgres" {
  count           = var.environment == "production" ? 1 : 0
  name            = "${var.service_name}-db-${var.environment}"
  database_version = "POSTGRES_14"
  region          = var.region
  
  settings {
    tier                        = "db-f1-micro"
    availability_type          = "REGIONAL"
    disk_type                  = "PD_SSD"
    disk_size                  = 20
    disk_autoresize           = true
    disk_autoresize_limit     = 100
    
    backup_configuration {
      enabled                        = true
      start_time                    = "03:00"
      point_in_time_recovery_enabled = true
      backup_retention_settings {
        retained_backups = 7
      }
    }
    
    ip_configuration {
      ipv4_enabled = false
      private_network = google_compute_network.vpc[0].self_link
    }
    
    database_flags {
      name  = "log_statement"
      value = "all"
    }
  }
  
  deletion_protection = true
}

# Optional: VPC Network
resource "google_compute_network" "vpc" {
  count                   = var.environment == "production" ? 1 : 0
  name                    = "${var.service_name}-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "subnet" {
  count         = var.environment == "production" ? 1 : 0
  name          = "${var.service_name}-subnet"
  ip_cidr_range = "10.0.0.0/24"
  region        = var.region
  network       = google_compute_network.vpc[0].self_link
}

# Optional: Redis for caching
resource "google_redis_instance" "cache" {
  count          = var.environment == "production" ? 1 : 0
  name           = "${var.service_name}-cache"
  tier           = "BASIC"
  memory_size_gb = 1
  region         = var.region
  
  authorized_network = google_compute_network.vpc[0].self_link
  
  redis_configs = {
    maxmemory-policy = "allkeys-lru"
  }
}

# Secret Manager secrets (empty - to be populated manually)
resource "google_secret_manager_secret" "jwt_secret" {
  secret_id = "${var.service_name}-jwt-secret"
  
  replication {
    automatic = true
  }
}

resource "google_secret_manager_secret" "api_key_secret" {
  secret_id = "${var.service_name}-api-key-secret"
  
  replication {
    automatic = true
  }
}

# Monitoring Alert Policy
resource "google_monitoring_alert_policy" "high_error_rate" {
  display_name = "${var.service_name} High Error Rate"
  combiner     = "OR"
  
  conditions {
    display_name = "High 5xx error rate"
    
    condition_threshold {
      filter          = "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"${var.service_name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0.05
      
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
  
  notification_channels = []
  
  alert_strategy {
    auto_close = "86400s"
  }
}
