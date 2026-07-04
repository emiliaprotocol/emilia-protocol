# SPDX-License-Identifier: Apache-2.0
#
# EMILIA Gate — reference Terraform module (EP-GATE-TF-v1) — inputs.
#
# KEY CUSTODY RULE (non-negotiable): issuer public keys are consumed from an
# EXISTING Kubernetes Secret that the deployer creates and controls. This
# module takes the secret's NAME only. It never accepts key material inline,
# never creates a Secret, and never reads secret data — so no key bytes ever
# enter Terraform state, plan output, or version control via this module.

variable "name" {
  description = "Base name for all resources (Deployment, Service, ConfigMap prefix)."
  type        = string
  default     = "emilia-gate"

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.name)) && length(var.name) <= 53
    error_message = "name must be a DNS-1123 label (lowercase alphanumerics and '-', max 53 chars to leave room for suffixes)."
  }
}

variable "namespace" {
  description = "Kubernetes namespace to deploy into. Must already exist — this module does not create namespaces."
  type        = string
  default     = "default"

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.namespace))
    error_message = "namespace must be a DNS-1123 label."
  }
}

variable "image" {
  description = "Container image for the gate (registry/repo:tag or @digest). BYOC: build and push your own image; pin a digest or exact tag for production — never a floating tag."
  type        = string

  validation {
    condition     = length(trimspace(var.image)) > 0
    error_message = "image is required."
  }
}

variable "image_pull_policy" {
  description = "Kubernetes imagePullPolicy for the gate container."
  type        = string
  default     = "IfNotPresent"

  validation {
    condition     = contains(["Always", "IfNotPresent", "Never"], var.image_pull_policy)
    error_message = "image_pull_policy must be one of Always, IfNotPresent, Never."
  }
}

variable "replicas" {
  description = "Number of gate replicas. Replay defense across >1 replica requires a shared consumption store (see README) — the module deploys the pods either way, but fleet-safety is the deployer's configuration responsibility."
  type        = number
  default     = 2

  validation {
    condition     = var.replicas >= 1 && floor(var.replicas) == var.replicas
    error_message = "replicas must be a whole number >= 1."
  }
}

variable "manifest_json" {
  description = "The action-risk manifest (EP-ACTION-RISK-MANIFEST) as a JSON string — the deny-by-default policy the gate enforces. Rendered into a ConfigMap and mounted read-only. Must parse as JSON and contain an \"actions\" array; an unparseable manifest fails at plan time, not in the cluster."
  type        = string

  validation {
    condition     = can(jsondecode(var.manifest_json)) && can(jsondecode(var.manifest_json).actions)
    error_message = "manifest_json must be valid JSON with an \"actions\" field (EP-ACTION-RISK-MANIFEST shape)."
  }
}

variable "issuer_keys_secret_name" {
  description = "Name of an EXISTING Kubernetes Secret (in the same namespace) holding the pinned issuer public keys the gate trusts. Referenced by name only — key material must NEVER be passed to Terraform. Exposed to the container as EP_GATE_ISSUER_KEYS via a non-optional secretKeyRef: pods do not start without it (fail closed — a gate with no pinned issuers must never come up permissive)."
  type        = string

  validation {
    # DNS-1123 subdomain. This also structurally rejects pasted key material
    # (PEM headers, JSON, base64url with '_') landing in this variable.
    condition     = can(regex("^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$", var.issuer_keys_secret_name)) && length(var.issuer_keys_secret_name) <= 253
    error_message = "issuer_keys_secret_name must be the NAME of an existing Secret (DNS-1123 subdomain). Never inline key material here."
  }
}

variable "issuer_keys_secret_key" {
  description = "Key inside the issuer-keys Secret that holds the pinned keys (a JSON array of base64url SPKI-DER Ed25519 public keys, or a {kid: key} map). Matches the Helm chart's issuerKeys.secretKey."
  type        = string
  default     = "issuer-keys.json"

  validation {
    condition     = length(trimspace(var.issuer_keys_secret_key)) > 0
    error_message = "issuer_keys_secret_key must be non-empty."
  }
}

variable "port" {
  description = "Port the gate HTTP service listens on inside the container (EP_GATE_PORT). Matches the Helm chart's gate.port."
  type        = number
  default     = 8080

  validation {
    condition     = var.port >= 1 && var.port <= 65535
    error_message = "port must be 1-65535."
  }
}

variable "service_port" {
  description = "Port the Service exposes inside the cluster."
  type        = number
  default     = 8080

  validation {
    condition     = var.service_port >= 1 && var.service_port <= 65535
    error_message = "service_port must be 1-65535."
  }
}

variable "service_type" {
  description = "Kubernetes Service type. ClusterIP (default) keeps the gate cluster-internal; anything more exposed is the deployer's explicit choice."
  type        = string
  default     = "ClusterIP"

  validation {
    condition     = contains(["ClusterIP", "NodePort", "LoadBalancer"], var.service_type)
    error_message = "service_type must be one of ClusterIP, NodePort, LoadBalancer."
  }
}

variable "log_level" {
  description = "Gate log verbosity (EP_GATE_LOG_LEVEL)."
  type        = string
  default     = "info"

  validation {
    condition     = contains(["error", "warn", "info", "debug"], var.log_level)
    error_message = "log_level must be one of error, warn, info, debug."
  }
}

variable "evidence_strict" {
  description = "Strict evidence log (EP_GATE_EVIDENCE_STRICT): when true the gate fails CLOSED if a decision record cannot be durably written — it never authorizes an action it cannot account for. Keep true."
  type        = bool
  default     = true
}

variable "metrics_enabled" {
  description = "Sets EP_GATE_METRICS_ENABLED. Scrape wiring (ServiceMonitor etc.) is out of scope for this module — see the Helm chart."
  type        = bool
  default     = false
}

variable "liveness_path" {
  description = "HTTP path for the liveness probe. Set to null to disable."
  type        = string
  default     = "/healthz"
}

variable "readiness_path" {
  description = "HTTP path for the readiness probe. Set to null to disable."
  type        = string
  default     = "/readyz"
}

variable "resources" {
  description = "Container resource requests/limits (Kubernetes quantity strings)."
  type = object({
    requests = map(string)
    limits   = map(string)
  })
  default = {
    requests = { cpu = "100m", memory = "128Mi" }
    limits   = { cpu = "500m", memory = "256Mi" }
  }
}

variable "run_as_user" {
  description = "UID/GID the gate container runs as (must be non-root; the pod security context enforces runAsNonRoot). Matches the Helm chart's default of 10001."
  type        = number
  default     = 10001

  validation {
    condition     = var.run_as_user > 0
    error_message = "run_as_user must be non-zero: the gate never runs as root."
  }
}

variable "read_only_root_filesystem" {
  description = "Mount the container's root filesystem read-only (hardened default). A writable emptyDir is mounted at /tmp for runtime scratch either way."
  type        = bool
  default     = true
}

variable "extra_env" {
  description = "Additional plain-text environment variables for the gate container (e.g. a durable consumption-store URL host/port). Do NOT put secrets here — values in this map land in Terraform state. Reference deployer-managed Secrets instead."
  type        = map(string)
  default     = {}
}

variable "extra_labels" {
  description = "Additional labels merged onto every resource."
  type        = map(string)
  default     = {}
}
