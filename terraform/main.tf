terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source = "hashicorp/google"
      version = "~> 6.0"
    }
    random = {
      source = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}
variable "project_id" {
  type = string
}
variable "region" {
  type = string
  default = "us-central1"
}
variable "image" {
  type = string
  default = "us-docker.pkg.dev/cloudrun/container/hello"
}
variable "sandbox_image" {
  type = string
  default = ""
  description = "Image built from sandbox/Dockerfile. When set, the sandbox worker is deployed as its own private Cloud Run service."
}
variable "auth_required" {
  type = bool
  default = true
  description = "Require a Firebase ID token (Google or guest sign-in). Set false only for a throwaway demo."
}
variable "virustotal_api_key" {
  type = string
  default = ""
  sensitive = true
}
variable "telegram_bot_token" {
  type = string
  default = ""
  sensitive = true
}
variable "telegram_bot_username" {
  type = string
  default = ""
}
variable "whatsapp_token" {
  type = string
  default = ""
  sensitive = true
}
variable "whatsapp_app_secret" {
  type = string
  default = ""
  sensitive = true
}
variable "whatsapp_display_number" {
  type = string
  default = ""
}
variable "enable_firestore" {
  type = bool
  default = false
  description = "Must enable Firestore native mode separately if already initialized."
}
variable "create_firestore_database" {
  type = bool
  default = false
  description = "Create the (default) Firestore database only if this project does not already have one."
}
variable "sandbox_url" {
  type = string
  default = ""
  description = "Use an existing worker (for example a dedicated VM) instead of the Cloud Run sandbox service."
}
variable "sandbox_token" {
  type = string
  default = ""
  sensitive = true
  description = "Token for an existing worker given in sandbox_url. The Cloud Run sandbox gets a generated token from Secret Manager instead."
}
variable "firebase_api_key" {
  type = string
  default = ""
}
variable "firebase_auth_domain" {
  type = string
  default = ""
}
variable "firebase_app_id" {
  type = string
  default = ""
}
variable "public_access" {
  type = bool
  default = true
}

provider "google" {
  project = var.project_id
  region = var.region
}

locals {
  deploy_sandbox = var.sandbox_image != ""
  # Optional secrets become Secret Manager entries only when a value is supplied.
  app_secrets = { for k, v in {
    VIRUSTOTAL_API_KEY = var.virustotal_api_key
    TELEGRAM_BOT_TOKEN = var.telegram_bot_token
    WHATSAPP_TOKEN = var.whatsapp_token
    WHATSAPP_APP_SECRET = var.whatsapp_app_secret
  } : k => v if nonsensitive(v != "") }
  services = ["run.googleapis.com", "aiplatform.googleapis.com", "bigquery.googleapis.com", "webrisk.googleapis.com",
    "cloudbuild.googleapis.com", "artifactregistry.googleapis.com", "pubsub.googleapis.com", "firestore.googleapis.com",
    "secretmanager.googleapis.com", "texttospeech.googleapis.com", "storage.googleapis.com"]
}
resource "google_project_service" "enabled" {
  for_each = toset(local.services)
  service = each.key
  disable_on_destroy = false
}

resource "google_artifact_registry_repository" "repo" {
  repository_id = "linkshield"
  location = var.region
  format = "DOCKER"
  depends_on = [google_project_service.enabled]
}
resource "google_service_account" "run" {
  account_id = "linkshield-run"
  display_name = "LinkShield AI backend service"
}
resource "google_project_iam_member" "vertex" {
  project = var.project_id
  role = "roles/aiplatform.user"
  member = "serviceAccount:${google_service_account.run.email}"
}
resource "google_project_iam_member" "bq_job" {
  project = var.project_id
  role = "roles/bigquery.jobUser"
  member = "serviceAccount:${google_service_account.run.email}"
}
resource "google_project_iam_member" "firestore" {
  count = var.enable_firestore ? 1 : 0
  project = var.project_id
  role = "roles/datastore.user"
  member = "serviceAccount:${google_service_account.run.email}"
}
resource "google_bigquery_dataset" "ds" {
  dataset_id = "linkshield"
  location = "US"
  depends_on = [google_project_service.enabled]
}
resource "google_bigquery_dataset_iam_member" "write" {
  dataset_id = google_bigquery_dataset.ds.dataset_id
  role = "roles/bigquery.dataEditor"
  member = "serviceAccount:${google_service_account.run.email}"
}
resource "google_bigquery_table" "claims" {
  dataset_id = google_bigquery_dataset.ds.dataset_id
  table_id = "claims_log"
  deletion_protection = false
  time_partitioning {
    type = "DAY"
    field = "ts"
  }
  schema = jsonencode([
    { name = "ts", type = "TIMESTAMP", mode = "REQUIRED" },
    { name = "claim_id", type = "STRING" }, { name = "claim", type = "STRING" },
    { name = "language", type = "STRING" }, { name = "verdict", type = "STRING" },
    { name = "confidence", type = "FLOAT" }, { name = "grounded", type = "BOOLEAN" },
  ])
}
resource "google_bigquery_table" "scans" {
  dataset_id = google_bigquery_dataset.ds.dataset_id
  table_id = "scan_events"
  deletion_protection = false
  time_partitioning {
    type = "DAY"
    field = "ts"
  }
  schema = jsonencode([
    { name = "ts", type = "TIMESTAMP", mode = "REQUIRED" },
    { name = "scan_id", type = "STRING" }, { name = "url_hash", type = "STRING" },
    { name = "risk_level", type = "STRING" }, { name = "risk_score", type = "INTEGER" },
    { name = "sandbox_status", type = "STRING" }, { name = "webrisk_checked", type = "BOOLEAN" },
    { name = "flag_count", type = "INTEGER" }, { name = "elapsed_ms", type = "INTEGER" },
  ])
}
resource "google_pubsub_topic" "scans" {
  name = "linkshield-scan-events"
  depends_on = [google_project_service.enabled]
}
resource "google_pubsub_topic_iam_member" "publisher" {
  topic = google_pubsub_topic.scans.name
  role = "roles/pubsub.publisher"
  member = "serviceAccount:${google_service_account.run.email}"
}
resource "google_firestore_database" "default" {
  count = var.create_firestore_database ? 1 : 0
  name = "(default)"
  location_id = "us-central1"
  type = "FIRESTORE_NATIVE"
  depends_on = [google_project_service.enabled]
}
resource "google_storage_bucket" "evidence" {
  name = "${var.project_id}-linkshield-evidence"
  location = var.region
  uniform_bucket_level_access = true
  public_access_prevention = "enforced"
  force_destroy = false
  lifecycle_rule {
    condition { age = 1 }
    action { type = "Delete" }
  }
  depends_on = [google_project_service.enabled]
}
resource "google_storage_bucket_iam_member" "evidence" {
  bucket = google_storage_bucket.evidence.name
  role = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.run.email}"
}
# ───────── Secrets ─────────
resource "random_password" "sandbox_token" {
  length = 48
  special = false
}
resource "random_password" "webhook" {
  for_each = toset(["telegram", "whatsapp"])
  length = 40
  special = false
}
resource "google_secret_manager_secret" "sandbox_token" {
  secret_id = "linkshield-sandbox-token"
  replication {
    auto {}
  }
  depends_on = [google_project_service.enabled]
}
resource "google_secret_manager_secret_version" "sandbox_token" {
  secret = google_secret_manager_secret.sandbox_token.id
  secret_data = var.sandbox_token != "" ? var.sandbox_token : random_password.sandbox_token.result
}
resource "google_secret_manager_secret" "app" {
  for_each = toset(keys(local.app_secrets))
  secret_id = "linkshield-${lower(replace(each.key, "_", "-"))}"
  replication {
    auto {}
  }
  depends_on = [google_project_service.enabled]
}
resource "google_secret_manager_secret_version" "app" {
  for_each = toset(keys(local.app_secrets))
  secret = google_secret_manager_secret.app[each.key].id
  secret_data = local.app_secrets[each.key]
}
resource "google_secret_manager_secret_iam_member" "run_sandbox_token" {
  secret_id = google_secret_manager_secret.sandbox_token.id
  role = "roles/secretmanager.secretAccessor"
  member = "serviceAccount:${google_service_account.run.email}"
}
resource "google_secret_manager_secret_iam_member" "run_app" {
  for_each = toset(keys(local.app_secrets))
  secret_id = google_secret_manager_secret.app[each.key].id
  role = "roles/secretmanager.secretAccessor"
  member = "serviceAccount:${google_service_account.run.email}"
}

# ───────── Sandbox worker: its own service and an identity with no access to anything ─────────
resource "google_service_account" "sandbox" {
  account_id = "linkshield-sandbox"
  display_name = "LinkShield sandbox worker (no project roles)"
}
resource "google_secret_manager_secret_iam_member" "sandbox_token" {
  secret_id = google_secret_manager_secret.sandbox_token.id
  role = "roles/secretmanager.secretAccessor"
  member = "serviceAccount:${google_service_account.sandbox.email}"
}
resource "google_cloud_run_v2_service" "sandbox" {
  count = local.deploy_sandbox ? 1 : 0
  name = "linkshield-sandbox"
  location = var.region
  deletion_protection = false
  ingress = "INGRESS_TRAFFIC_ALL" # reachable only with an identity token from the API's service account (see invoker below)
  template {
    service_account = google_service_account.sandbox.email
    execution_environment = "EXECUTION_ENVIRONMENT_GEN2"
    timeout = "120s"
    max_instance_request_concurrency = 2
    scaling {
      min_instance_count = 0
      max_instance_count = 4
    }
    containers {
      image = var.sandbox_image
      ports {
        container_port = 8090
      }
      resources {
        limits = {cpu = "2", memory = "2Gi"}
      }
      env {
        name = "SANDBOX_TOKEN"
        value_source {
          secret_key_ref {
            secret = google_secret_manager_secret.sandbox_token.secret_id
            version = "latest"
          }
        }
      }
    }
  }
  depends_on = [google_secret_manager_secret_version.sandbox_token, google_secret_manager_secret_iam_member.sandbox_token]
}
resource "google_cloud_run_v2_service_iam_member" "sandbox_invoker" {
  count = local.deploy_sandbox ? 1 : 0
  name = google_cloud_run_v2_service.sandbox[0].name
  location = var.region
  role = "roles/run.invoker"
  member = "serviceAccount:${google_service_account.run.email}"
}

resource "google_cloud_run_v2_service" "app" {
  name = "linkshield"
  location = var.region
  deletion_protection = false
  ingress = "INGRESS_TRAFFIC_ALL"
  template {
    service_account = google_service_account.run.email
    timeout = "120s"
    max_instance_request_concurrency = 20
    scaling {
      min_instance_count = 0
      max_instance_count = 5
    }
    containers {
      image = var.image
      resources {
        limits = {cpu = "1", memory = "1Gi"}
        cpu_idle = false  # the bots reply from background tasks after the webhook returns
      }
      env {
        name = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }
      env {
        name = "GOOGLE_CLOUD_LOCATION"
        value = var.region
      }
      env {
        name = "AUTH_REQUIRED"
        value = var.auth_required ? "1" : "0"
      }
      env {
        name = "ENABLE_FIRESTORE"
        value = var.enable_firestore ? "1" : "0"
      }
      env {
        name = "BQ_SCAN_TABLE"
        value = "${var.project_id}.linkshield.scan_events"
      }
      env {
        name = "BQ_TABLE"
        value = "${var.project_id}.linkshield.claims_log"
      }
      env {
        name = "PUBSUB_TOPIC"
        value = google_pubsub_topic.scans.id
      }
      env {
        name = "EVIDENCE_BUCKET"
        value = google_storage_bucket.evidence.name
      }
      env {
        name = "FIREBASE_API_KEY"
        value = var.firebase_api_key
      }
      env {
        name = "FIREBASE_AUTH_DOMAIN"
        value = var.firebase_auth_domain
      }
      env {
        name = "FIREBASE_PROJECT_ID"
        value = var.project_id
      }
      env {
        name = "FIREBASE_APP_ID"
        value = var.firebase_app_id
      }
      env {
        name = "SANDBOX_URL"
        value = var.sandbox_url != "" ? var.sandbox_url : (local.deploy_sandbox ? google_cloud_run_v2_service.sandbox[0].uri : "")
      }
      env {
        name = "SANDBOX_AUDIENCE"
        value = var.sandbox_url == "" && local.deploy_sandbox ? google_cloud_run_v2_service.sandbox[0].uri : ""
      }
      env {
        name = "SANDBOX_TOKEN"
        value_source {
          secret_key_ref {
            secret = google_secret_manager_secret.sandbox_token.secret_id
            version = "latest"
          }
        }
      }
      dynamic "env" {
        for_each = toset(keys(local.app_secrets))
        content {
          name = env.key
          value_source {
            secret_key_ref {
              secret = google_secret_manager_secret.app[env.key].secret_id
              version = "latest"
            }
          }
        }
      }
      env {
        name = "TELEGRAM_BOT_USERNAME"
        value = var.telegram_bot_username
      }
      env {
        name = "TELEGRAM_WEBHOOK_SECRET"
        value = random_password.webhook["telegram"].result
      }
      env {
        name = "WHATSAPP_VERIFY_TOKEN"
        value = random_password.webhook["whatsapp"].result
      }
      env {
        name = "WHATSAPP_DISPLAY_NUMBER"
        value = var.whatsapp_display_number
      }
    }
  }
  depends_on = [google_project_iam_member.vertex, google_bigquery_table.scans, google_secret_manager_secret_version.sandbox_token,
    google_secret_manager_secret_iam_member.run_sandbox_token, google_secret_manager_secret_version.app, google_secret_manager_secret_iam_member.run_app]
}
resource "google_cloud_run_v2_service_iam_member" "public" {
  count = var.public_access ? 1 : 0
  name = google_cloud_run_v2_service.app.name
  location = var.region
  role = "roles/run.invoker"
  member = "allUsers"
}
output "url" { value = google_cloud_run_v2_service.app.uri }
output "artifact_registry" { value = google_artifact_registry_repository.repo.id }
output "scan_topic" { value = google_pubsub_topic.scans.id }
output "evidence_bucket" { value = google_storage_bucket.evidence.name }
output "sandbox_url" { value = local.deploy_sandbox ? google_cloud_run_v2_service.sandbox[0].uri : var.sandbox_url }
output "telegram_webhook_secret" {
  value = random_password.webhook["telegram"].result
  sensitive = true
}
output "whatsapp_verify_token" {
  value = random_password.webhook["whatsapp"].result
  sensitive = true
}
