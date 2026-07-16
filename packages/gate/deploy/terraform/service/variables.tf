variable "name" {
  description = "Kubernetes resource name prefix."
  type        = string
  default     = "emilia-gate-service"

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.name)) && length(var.name) <= 52
    error_message = "name must be a DNS label no longer than 52 characters."
  }
}

variable "namespace" {
  description = "Existing Kubernetes namespace in which to deploy."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.namespace))
    error_message = "namespace must be a Kubernetes DNS label."
  }
}

variable "image" {
  description = "Complete BYOC image reference built from Dockerfile.gate. No official public image is implied. Use a digest in production."
  type        = string

  validation {
    condition     = trimspace(var.image) != "" && !endswith(var.image, ":latest")
    error_message = "image must be an explicit non-latest BYOC image reference."
  }
}

variable "image_pull_policy" {
  description = "Kubernetes image pull policy."
  type        = string
  default     = "IfNotPresent"

  validation {
    condition     = contains(["Always", "IfNotPresent", "Never"], var.image_pull_policy)
    error_message = "image_pull_policy must be Always, IfNotPresent, or Never."
  }
}

variable "image_pull_secrets" {
  description = "Names of existing image pull Secrets."
  type        = list(string)
  default     = []
}

variable "replicas" {
  description = "Gate service replicas. Two is the production-shaped default."
  type        = number
  default     = 2

  validation {
    condition     = var.replicas >= 1 && floor(var.replicas) == var.replicas
    error_message = "replicas must be a positive integer."
  }
}

variable "port" {
  description = "Gate service container and ClusterIP port."
  type        = number
  default     = 8080

  validation {
    condition     = var.port >= 1 && var.port <= 65535
    error_message = "port must be between 1 and 65535."
  }
}

variable "log_level" {
  description = "EP_GATE_LOG_LEVEL passed to the service."
  type        = string
  default     = "info"

  validation {
    condition     = contains(["debug", "info", "warn", "error"], var.log_level)
    error_message = "log_level must be debug, info, warn, or error."
  }
}

variable "configuration_secret_name" {
  description = "Name of an existing Secret containing the operator-owned gate.config.mjs and migrate.mjs modules."
  type        = string

  validation {
    condition     = trimspace(var.configuration_secret_name) != ""
    error_message = "configuration_secret_name is required."
  }
}

variable "configuration_secret_key" {
  description = "Key in configuration_secret_name containing the apps/gate-service ESM config module."
  type        = string
  default     = "gate.config.mjs"
}

variable "migration_script_secret_key" {
  description = "Key in configuration_secret_name containing the idempotent migration module."
  type        = string
  default     = "migrate.mjs"
}

variable "configuration_mount_path" {
  description = "Read-only directory where operator configuration modules are mounted."
  type        = string
  default     = "/app/config"
}

variable "postgres_secret_name" {
  description = "Name of an existing Secret containing the Postgres connection URL. Only the reference is stored by Terraform."
  type        = string

  validation {
    condition     = trimspace(var.postgres_secret_name) != ""
    error_message = "postgres_secret_name is required."
  }
}

variable "postgres_secret_key" {
  description = "Key in postgres_secret_name containing the connection URL."
  type        = string
  default     = "database-url"
}

variable "postgres_env_name" {
  description = "Runtime environment variable populated from the Postgres Secret."
  type        = string
  default     = "DATABASE_URL"
}

variable "migration_postgres_secret_name" {
  description = "Optional existing Secret for a DDL-capable migration role. Null reuses postgres_secret_name."
  type        = string
  default     = null
  nullable    = true
}

variable "migration_postgres_secret_key" {
  description = "Optional key in migration_postgres_secret_name containing the migration URL. Null reuses postgres_secret_key."
  type        = string
  default     = null
  nullable    = true
}

variable "kms_secret_name" {
  description = "Name of an existing Secret containing the service KMS key identifier/config. Only the reference is stored by Terraform."
  type        = string

  validation {
    condition     = trimspace(var.kms_secret_name) != ""
    error_message = "kms_secret_name is required."
  }
}

variable "kms_secret_key" {
  description = "Key in kms_secret_name containing the KMS key identifier/config."
  type        = string
  default     = "kms-key-id"
}

variable "kms_env_name" {
  description = "Runtime environment variable populated from the KMS Secret."
  type        = string
  default     = "EP_KMS_KEY_ID"
}

variable "issuer_roots_secret_name" {
  description = "Name of an existing Secret containing the pinned issuer-root set. Only the reference is stored by Terraform."
  type        = string

  validation {
    condition     = trimspace(var.issuer_roots_secret_name) != ""
    error_message = "issuer_roots_secret_name is required."
  }
}

variable "issuer_roots_secret_key" {
  description = "Key in issuer_roots_secret_name containing the pinned issuer-root set."
  type        = string
  default     = "issuer-roots.json"
}

variable "issuer_roots_env_name" {
  description = "Runtime environment variable populated from the issuer-roots Secret."
  type        = string
  default     = "EP_GATE_ISSUER_ROOTS"
}

variable "extra_env" {
  description = "Additional non-secret literal environment variables. Use external Secret wiring for sensitive values."
  type        = map(string)
  default     = {}
}

variable "migration_enabled" {
  description = "Run the database migration Job before the Deployment. Keep enabled outside controlled recovery operations."
  type        = bool
  default     = true
}

variable "migration_command" {
  description = "Command run by the migration Job."
  type        = list(string)
  default     = ["node", "/app/config/migrate.mjs"]

  validation {
    condition     = length(var.migration_command) > 0
    error_message = "migration_command must contain at least one element."
  }
}

variable "migration_revision" {
  description = "Bump when migration inputs change without changing the image; it is included in the immutable Job name."
  type        = string
  default     = "schema-v1"
}

variable "migration_active_deadline_seconds" {
  description = "Maximum migration Job runtime."
  type        = number
  default     = 600
}

variable "migration_backoff_limit" {
  description = "Migration Job retry limit."
  type        = number
  default     = 3
}

variable "resources" {
  description = "Service container requests and limits."
  type = object({
    requests = map(string)
    limits   = map(string)
  })
  default = {
    requests = {
      cpu    = "100m"
      memory = "128Mi"
    }
    limits = {
      cpu    = "1"
      memory = "512Mi"
    }
  }
}

variable "migration_resources" {
  description = "Migration Job requests and limits."
  type = object({
    requests = map(string)
    limits   = map(string)
  })
  default = {
    requests = {
      cpu    = "50m"
      memory = "64Mi"
    }
    limits = {
      cpu    = "500m"
      memory = "256Mi"
    }
  }
}

variable "pdb_enabled" {
  description = "Create a PodDisruptionBudget for service pods."
  type        = bool
  default     = true
}

variable "pdb_min_available" {
  description = "Minimum service pods available during voluntary disruption."
  type        = string
  default     = "1"
}

variable "network_policy_enabled" {
  description = "Create default-deny and explicit allow NetworkPolicies for gate and migration pods."
  type        = bool
  default     = true
}

variable "allow_same_namespace_ingress" {
  description = "Allow pods in the deployment namespace to reach the gate service port."
  type        = bool
  default     = true
}

variable "dns_namespace_labels" {
  description = "Namespace selector labels for cluster DNS."
  type        = map(string)
  default = {
    "kubernetes.io/metadata.name" = "kube-system"
  }
}

variable "dns_pod_labels" {
  description = "Pod selector labels for cluster DNS."
  type        = map(string)
  default = {
    "k8s-app" = "kube-dns"
  }
}

variable "postgres_port" {
  description = "Postgres egress port."
  type        = number
  default     = 5432
}

variable "postgres_pod_labels" {
  description = "Same-namespace Postgres pod selector. Set to an empty map when using only managed-Postgres CIDRs."
  type        = map(string)
  default = {
    "app.kubernetes.io/name" = "postgresql"
  }
}

variable "postgres_egress_cidrs" {
  description = "Stable managed-Postgres or egress-proxy CIDRs allowed on postgres_port."
  type        = list(string)
  default     = []
}

variable "kms_egress_cidrs" {
  description = "Stable KMS proxy/NAT CIDRs allowed on TCP 443. Standard NetworkPolicy cannot select KMS FQDNs."
  type        = list(string)
  default     = []
}

variable "github_egress_cidrs" {
  description = "Stable GitHub egress-proxy CIDRs allowed on TCP 443. Prefer an FQDN-aware CNI policy over public IP snapshots."
  type        = list(string)
  default     = []
}

variable "siem_egress_cidrs" {
  description = "Stable SIEM egress-proxy CIDRs allowed on TCP 443. Prefer an FQDN-aware CNI policy for SaaS SIEM endpoints."
  type        = list(string)
  default     = []
}

variable "pod_annotations" {
  description = "Additional service pod annotations."
  type        = map(string)
  default     = {}
}

variable "labels" {
  description = "Additional labels added to resources. Do not override selector labels."
  type        = map(string)
  default     = {}
}

variable "node_selector" {
  description = "Service pod node selector."
  type        = map(string)
  default     = {}
}

variable "tolerations" {
  description = "Service pod tolerations in Kubernetes provider shape."
  type = list(object({
    key                = optional(string)
    operator           = optional(string)
    value              = optional(string)
    effect             = optional(string)
    toleration_seconds = optional(number)
  }))
  default = []
}
