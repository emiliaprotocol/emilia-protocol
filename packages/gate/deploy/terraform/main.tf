# SPDX-License-Identifier: Apache-2.0
#
# EMILIA Gate — reference Terraform module (EP-GATE-TF-v1).
#
# The Terraform sibling of the Helm chart (deploy/helm, EP-GATE-HELM-v1) for
# BYOC installs: the deployer's cluster, the deployer's keys. Same container
# contract as the chart — EP_GATE_* env, the action-risk manifest mounted at
# /etc/emilia-gate/action-risk-manifest.json, pinned issuer keys arriving as
# EP_GATE_ISSUER_KEYS from a Secret the DEPLOYER created. Three resources,
# nothing hidden:
#
#   kubernetes_config_map_v1.manifest — the action-risk manifest (policy);
#   kubernetes_deployment_v1.gate     — the gate pods, hardened defaults
#     (non-root, read-only rootfs, no privilege escalation, all capabilities
#     dropped, no service-account token);
#   kubernetes_service_v1.gate        — cluster-internal Service in front of
#     the pods (ClusterIP by default).
#
# Fail-closed wiring:
#   - the issuer-keys secretKeyRef is NOT optional: if the deployer has not
#     provisioned pinned issuer keys, the pods do not start — a gate without
#     pinned issuers must never come up permissive;
#   - EP_GATE_EVIDENCE_STRICT defaults to true: the gate refuses to authorize
#     an action it cannot durably account for;
#   - the manifest is validated as JSON at plan time (see variables.tf) and a
#     sha256 of it is annotated onto the pod template, so every manifest change
#     rolls the pods — a stale policy can't keep serving silently.

locals {
  module_version = "EP-GATE-TF-v1"

  labels = merge({
    "app.kubernetes.io/name"            = var.name
    "app.kubernetes.io/component"       = "trusted-action-firewall"
    "app.kubernetes.io/part-of"         = "emilia-protocol"
    "emiliaprotocol.ai/module-contract" = local.module_version
    "emiliaprotocol.ai/maturity"        = "experimental"
    "emiliaprotocol.ai/deprecated"      = "true"
    "emiliaprotocol.ai/replacement"     = "emilia-gate-service"
  }, var.extra_labels)

  selector_labels = {
    "app.kubernetes.io/name"      = var.name
    "app.kubernetes.io/component" = "trusted-action-firewall"
  }

  # Same paths as the Helm chart's container contract.
  manifest_mount_dir = "/etc/emilia-gate"
  manifest_file      = "action-risk-manifest.json"

  secret_env_references = concat(
    var.shared_consumption_backend == null ? [] : [var.shared_consumption_backend],
    var.shared_evidence_backend == null ? [] : [var.shared_evidence_backend],
    var.github_token_secret_name == null ? [] : [{
      env_name    = var.github_token_env_name
      secret_name = var.github_token_secret_name
      secret_key  = var.github_token_secret_key
    }],
    [for env_name, reference in var.secret_env : {
      env_name    = env_name
      secret_name = reference.secret_name
      secret_key  = reference.secret_key
    }],
  )
  configurable_env_names = concat(
    [for reference in local.secret_env_references : reference.env_name],
    keys(var.extra_env),
  )
  reserved_env_names = toset([
    "NODE_ENV",
    "EP_GATE_PORT",
    "EP_GATE_LOG_LEVEL",
    "EP_GATE_EVIDENCE_STRICT",
    "EP_GATE_MANIFEST_PATH",
    "EP_GATE_METRICS_ENABLED",
    "EP_GATE_ISSUER_KEYS",
  ])
}

# The policy the gate enforces. Plain ConfigMap: the manifest is deny-by-default
# POLICY, not a secret — auditors should be able to read it in-cluster.
resource "kubernetes_config_map_v1" "manifest" {
  metadata {
    name      = "${var.name}-manifest"
    namespace = var.namespace
    labels    = local.labels
  }

  data = {
    (local.manifest_file) = var.manifest_json
  }
}

resource "kubernetes_deployment_v1" "gate" {
  metadata {
    name      = var.name
    namespace = var.namespace
    labels    = local.labels
  }

  spec {
    replicas = var.replicas

    selector {
      match_labels = local.selector_labels
    }

    template {
      metadata {
        labels = local.labels
        annotations = {
          # Roll the pods whenever the policy changes.
          "emiliaprotocol.ai/manifest-sha256" = sha256(var.manifest_json)
        }
      }

      spec {
        # The gate does not call the Kubernetes API; no token, no ambient authority.
        automount_service_account_token = false

        security_context {
          run_as_non_root = true
          run_as_user     = var.run_as_user
          run_as_group    = var.run_as_user
          fs_group        = var.run_as_user

          seccomp_profile {
            type = "RuntimeDefault"
          }
        }

        container {
          name              = "gate"
          image             = var.image
          image_pull_policy = var.image_pull_policy

          port {
            name           = "http"
            container_port = var.port
            protocol       = "TCP"
          }

          env {
            name  = "NODE_ENV"
            value = "production"
          }

          env {
            name  = "EP_GATE_PORT"
            value = tostring(var.port)
          }

          env {
            name  = "EP_GATE_LOG_LEVEL"
            value = var.log_level
          }

          # Strict evidence log: never authorize an action the gate cannot
          # durably account for.
          env {
            name  = "EP_GATE_EVIDENCE_STRICT"
            value = tostring(var.evidence_strict)
          }

          env {
            name  = "EP_GATE_MANIFEST_PATH"
            value = "${local.manifest_mount_dir}/${local.manifest_file}"
          }

          env {
            name  = "EP_GATE_METRICS_ENABLED"
            value = tostring(var.metrics_enabled)
          }

          # Pinned issuer keys — REFERENCED from an existing Secret, never
          # passed through Terraform. optional=false is the fail-closed
          # switch: no pinned issuers, no pods.
          env {
            name = "EP_GATE_ISSUER_KEYS"
            value_from {
              secret_key_ref {
                name     = var.issuer_keys_secret_name
                key      = var.issuer_keys_secret_key
                optional = false
              }
            }
          }

          dynamic "env" {
            for_each = { for index, reference in local.secret_env_references : tostring(index) => reference }
            content {
              name = env.value.env_name
              value_from {
                secret_key_ref {
                  name     = env.value.secret_name
                  key      = env.value.secret_key
                  optional = false
                }
              }
            }
          }

          dynamic "env" {
            for_each = var.extra_env
            content {
              name  = env.key
              value = env.value
            }
          }

          volume_mount {
            name       = "action-risk-manifest"
            mount_path = local.manifest_mount_dir
            read_only  = true
          }

          # Writable scratch for the runtime; rootfs stays read-only.
          volume_mount {
            name       = "tmp"
            mount_path = "/tmp"
          }

          resources {
            requests = var.resources.requests
            limits   = var.resources.limits
          }

          dynamic "liveness_probe" {
            for_each = var.liveness_path == null ? [] : [var.liveness_path]
            content {
              http_get {
                path = liveness_probe.value
                port = "http"
              }
              initial_delay_seconds = 5
              period_seconds        = 10
              timeout_seconds       = 2
              failure_threshold     = 3
            }
          }

          dynamic "readiness_probe" {
            for_each = var.readiness_path == null ? [] : [var.readiness_path]
            content {
              http_get {
                path = readiness_probe.value
                port = "http"
              }
              initial_delay_seconds = 5
              period_seconds        = 10
              timeout_seconds       = 2
              failure_threshold     = 3
            }
          }

          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem  = var.read_only_root_filesystem

            capabilities {
              drop = ["ALL"]
            }
          }
        }

        volume {
          name = "action-risk-manifest"
          config_map {
            name = kubernetes_config_map_v1.manifest.metadata[0].name
          }
        }

        volume {
          name = "tmp"
          empty_dir {}
        }
      }
    }
  }

  lifecycle {
    precondition {
      condition     = var.replicas == 1 || (var.shared_consumption_backend != null && var.shared_evidence_backend != null)
      error_message = "The deprecated legacy module refuses replicas > 1 without both shared_consumption_backend and shared_evidence_backend Secret references. Prefer terraform/service."
    }
    precondition {
      condition     = length(distinct(local.configurable_env_names)) == length(local.configurable_env_names)
      error_message = "Secret-backed and literal environment variables must not use duplicate names."
    }
    precondition {
      condition     = length(setintersection(toset(local.configurable_env_names), local.reserved_env_names)) == 0
      error_message = "secret_env and extra_env must not override module-managed environment variables."
    }
  }
}

resource "kubernetes_service_v1" "gate" {
  metadata {
    name      = var.name
    namespace = var.namespace
    labels    = local.labels
  }

  spec {
    type     = var.service_type
    selector = local.selector_labels

    port {
      name        = "http"
      port        = var.service_port
      target_port = "http"
      protocol    = "TCP"
    }
  }
}
