locals {
  base_labels = merge({
    "app.kubernetes.io/name"             = var.name
    "app.kubernetes.io/instance"         = var.name
    "app.kubernetes.io/part-of"          = "emilia-gate"
    "app.kubernetes.io/managed-by"       = "terraform"
    "emiliaprotocol.ai/deployment-model" = "byoc"
  }, var.labels)

  service_selector_labels = {
    "app.kubernetes.io/name"      = var.name
    "app.kubernetes.io/instance"  = var.name
    "app.kubernetes.io/component" = "service"
  }

  base_selector_labels = {
    "app.kubernetes.io/name"     = var.name
    "app.kubernetes.io/instance" = var.name
  }

  migration_id = substr(sha256(jsonencode({
    image    = var.image
    command  = var.migration_command
    revision = var.migration_revision
  })), 0, 10)

  https_egress_cidrs = distinct(concat(
    var.kms_egress_cidrs,
    var.github_egress_cidrs,
    var.siem_egress_cidrs,
  ))

  migration_postgres_secret_name = var.migration_postgres_secret_name == null ? "" : var.migration_postgres_secret_name
  migration_postgres_secret_key  = var.migration_postgres_secret_key == null ? "" : var.migration_postgres_secret_key
  migration_credentials_valid = try(
    trimspace(var.migration_postgres_secret_name) != ""
    && trimspace(var.migration_postgres_secret_key) != ""
    && var.migration_postgres_secret_name != var.postgres_secret_name,
    false,
  )

  runtime_secret_env = concat(
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
    [for reference in local.runtime_secret_env : reference.env_name],
    keys(var.extra_env),
  )
  reserved_env_names = toset([
    "NODE_ENV",
    "HOST",
    "PORT",
    "EMILIA_GATE_CONFIG",
    "EP_GATE_PORT",
    "EP_GATE_LOG_LEVEL",
    var.postgres_env_name,
    var.api_token_env_name,
    var.kms_env_name,
    var.issuer_roots_env_name,
  ])
}

resource "kubernetes_service_account_v1" "gate" {
  metadata {
    name      = var.name
    namespace = var.namespace
    labels    = local.base_labels
  }

  automount_service_account_token = false
}

resource "kubernetes_network_policy_v1" "default_deny" {
  count = var.network_policy_enabled ? 1 : 0

  metadata {
    name      = "${var.name}-default-deny"
    namespace = var.namespace
    labels    = local.base_labels
  }

  spec {
    pod_selector {
      match_labels = local.base_selector_labels
    }
    policy_types = ["Ingress", "Egress"]
  }
}

resource "kubernetes_network_policy_v1" "ingress" {
  count = var.network_policy_enabled && var.allow_same_namespace_ingress ? 1 : 0

  metadata {
    name      = "${var.name}-ingress"
    namespace = var.namespace
    labels    = local.base_labels
  }

  spec {
    pod_selector {
      match_labels = local.service_selector_labels
    }

    policy_types = ["Ingress"]

    ingress {
      from {
        pod_selector {}
      }
      ports {
        port     = var.port
        protocol = "TCP"
      }
    }
  }
}

resource "kubernetes_network_policy_v1" "dns" {
  count = var.network_policy_enabled ? 1 : 0

  metadata {
    name      = "${var.name}-dns"
    namespace = var.namespace
    labels    = local.base_labels
  }

  spec {
    pod_selector {
      match_labels = local.base_selector_labels
    }

    policy_types = ["Egress"]

    egress {
      to {
        namespace_selector {
          match_labels = var.dns_namespace_labels
        }
        pod_selector {
          match_labels = var.dns_pod_labels
        }
      }
      ports {
        port     = 53
        protocol = "UDP"
      }
      ports {
        port     = 53
        protocol = "TCP"
      }
    }
  }
}

resource "kubernetes_network_policy_v1" "postgres_pods" {
  count = var.network_policy_enabled && length(var.postgres_pod_labels) > 0 ? 1 : 0

  metadata {
    name      = "${var.name}-postgres-pods"
    namespace = var.namespace
    labels    = local.base_labels
  }

  spec {
    pod_selector {
      match_labels = local.base_selector_labels
    }

    policy_types = ["Egress"]

    egress {
      to {
        pod_selector {
          match_labels = var.postgres_pod_labels
        }
      }
      ports {
        port     = var.postgres_port
        protocol = "TCP"
      }
    }
  }
}

resource "kubernetes_network_policy_v1" "postgres_cidrs" {
  count = var.network_policy_enabled && length(var.postgres_egress_cidrs) > 0 ? 1 : 0

  metadata {
    name      = "${var.name}-postgres-cidrs"
    namespace = var.namespace
    labels    = local.base_labels
  }

  spec {
    pod_selector {
      match_labels = local.base_selector_labels
    }
    policy_types = ["Egress"]

    dynamic "egress" {
      for_each = toset(var.postgres_egress_cidrs)
      content {
        to {
          ip_block {
            cidr = egress.value
          }
        }
        ports {
          port     = var.postgres_port
          protocol = "TCP"
        }
      }
    }
  }
}

resource "kubernetes_network_policy_v1" "https_egress" {
  count = var.network_policy_enabled && length(local.https_egress_cidrs) > 0 ? 1 : 0

  metadata {
    name      = "${var.name}-https-egress"
    namespace = var.namespace
    labels    = local.base_labels
  }

  spec {
    pod_selector {
      match_labels = local.service_selector_labels
    }
    policy_types = ["Egress"]

    dynamic "egress" {
      for_each = toset(local.https_egress_cidrs)
      content {
        to {
          ip_block {
            cidr = egress.value
          }
        }
        ports {
          port     = 443
          protocol = "TCP"
        }
      }
    }
  }
}

resource "kubernetes_job_v1" "migration" {
  count = var.migration_enabled ? 1 : 0

  metadata {
    name      = "${var.name}-migrate-${local.migration_id}"
    namespace = var.namespace
    labels = merge(local.base_labels, {
      "app.kubernetes.io/component" = "migration"
    })
  }

  wait_for_completion = true

  spec {
    active_deadline_seconds = var.migration_active_deadline_seconds
    backoff_limit           = var.migration_backoff_limit

    template {
      metadata {
        labels = merge(local.base_selector_labels, {
          "app.kubernetes.io/component" = "migration"
        })
      }

      spec {
        automount_service_account_token = false
        restart_policy                  = "Never"

        security_context {
          run_as_non_root        = true
          run_as_user            = 10001
          run_as_group           = 10001
          fs_group               = 10001
          fs_group_change_policy = "OnRootMismatch"

          seccomp_profile {
            type = "RuntimeDefault"
          }
        }

        dynamic "image_pull_secrets" {
          for_each = toset(var.image_pull_secrets)
          content {
            name = image_pull_secrets.value
          }
        }

        container {
          name              = "migrate"
          image             = var.image
          image_pull_policy = var.image_pull_policy
          command           = var.migration_command

          env {
            name  = "NODE_ENV"
            value = "production"
          }

          env {
            name  = "EMILIA_GATE_CONFIG"
            value = "${var.configuration_mount_path}/${var.configuration_secret_key}"
          }

          env {
            name = var.postgres_env_name
            value_from {
              secret_key_ref {
                name     = local.migration_postgres_secret_name
                key      = local.migration_postgres_secret_key
                optional = false
              }
            }
          }

          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem  = true

            capabilities {
              drop = ["ALL"]
            }
          }

          resources {
            requests = var.migration_resources.requests
            limits   = var.migration_resources.limits
          }

          volume_mount {
            name       = "tmp"
            mount_path = "/tmp"
          }

          volume_mount {
            name       = "configuration"
            mount_path = var.configuration_mount_path
            read_only  = true
          }
        }

        volume {
          name = "tmp"
          empty_dir {
            size_limit = "32Mi"
          }
        }


        volume {
          name = "configuration"
          secret {
            secret_name  = var.configuration_secret_name
            optional     = false
            default_mode = "0440"

            items {
              key  = var.configuration_secret_key
              path = var.configuration_secret_key
              mode = "0440"
            }
            items {
              key  = var.migration_script_secret_key
              path = var.migration_script_secret_key
              mode = "0440"
            }
          }
        }
      }
    }
  }

  depends_on = [
    kubernetes_network_policy_v1.default_deny,
    kubernetes_network_policy_v1.dns,
    kubernetes_network_policy_v1.postgres_pods,
    kubernetes_network_policy_v1.postgres_cidrs,
  ]

  timeouts {
    create = "15m"
    update = "15m"
  }

  lifecycle {
    precondition {
      condition     = local.migration_credentials_valid
      error_message = "migration_enabled requires a non-empty migration_postgres_secret_name/key, and the migration Secret must differ from postgres_secret_name. Runtime credential fallback is refused."
    }
  }
}

resource "kubernetes_deployment_v1" "gate" {
  metadata {
    name      = var.name
    namespace = var.namespace
    labels    = local.base_labels
  }

  spec {
    replicas               = var.replicas
    revision_history_limit = 3

    strategy {
      type = "RollingUpdate"
      rolling_update {
        max_unavailable = "0"
        max_surge       = "1"
      }
    }

    selector {
      match_labels = local.service_selector_labels
    }

    template {
      metadata {
        labels      = merge(local.base_labels, local.service_selector_labels)
        annotations = var.pod_annotations
      }

      spec {
        service_account_name             = kubernetes_service_account_v1.gate.metadata[0].name
        automount_service_account_token  = false
        termination_grace_period_seconds = 30

        security_context {
          run_as_non_root        = true
          run_as_user            = 10001
          run_as_group           = 10001
          fs_group               = 10001
          fs_group_change_policy = "OnRootMismatch"

          seccomp_profile {
            type = "RuntimeDefault"
          }
        }

        dynamic "image_pull_secrets" {
          for_each = toset(var.image_pull_secrets)
          content {
            name = image_pull_secrets.value
          }
        }

        container {
          name              = "gate-service"
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
            name  = "HOST"
            value = "0.0.0.0"
          }
          env {
            name  = "PORT"
            value = tostring(var.port)
          }
          env {
            name  = "EMILIA_GATE_CONFIG"
            value = "${var.configuration_mount_path}/${var.configuration_secret_key}"
          }
          env {
            name  = "EP_GATE_PORT"
            value = tostring(var.port)
          }
          env {
            name  = "EP_GATE_LOG_LEVEL"
            value = var.log_level
          }

          env {
            name = var.postgres_env_name
            value_from {
              secret_key_ref {
                name     = var.postgres_secret_name
                key      = var.postgres_secret_key
                optional = false
              }
            }
          }
          env {
            name = var.api_token_env_name
            value_from {
              secret_key_ref {
                name     = var.api_token_secret_name
                key      = var.api_token_secret_key
                optional = false
              }
            }
          }
          dynamic "env" {
            for_each = var.kms_secret_name == null ? [] : [var.kms_secret_name]
            content {
              name = var.kms_env_name
              value_from {
                secret_key_ref {
                  name     = env.value
                  key      = var.kms_secret_key
                  optional = false
                }
              }
            }
          }
          env {
            name = var.issuer_roots_env_name
            value_from {
              secret_key_ref {
                name     = var.issuer_roots_secret_name
                key      = var.issuer_roots_secret_key
                optional = false
              }
            }
          }

          dynamic "env" {
            for_each = { for index, reference in local.runtime_secret_env : tostring(index) => reference }
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

          startup_probe {
            http_get {
              path = "/v1/live"
              port = "http"
            }
            period_seconds    = 2
            timeout_seconds   = 2
            failure_threshold = 30
          }

          liveness_probe {
            http_get {
              path = "/v1/live"
              port = "http"
            }
            period_seconds    = 10
            timeout_seconds   = 2
            failure_threshold = 3
          }

          readiness_probe {
            http_get {
              path = "/v1/ready"
              port = "http"
            }
            period_seconds    = 5
            timeout_seconds   = 2
            failure_threshold = 3
          }

          resources {
            requests = var.resources.requests
            limits   = var.resources.limits
          }

          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem  = true

            capabilities {
              drop = ["ALL"]
            }
          }

          volume_mount {
            name       = "tmp"
            mount_path = "/tmp"
          }

          volume_mount {
            name       = "configuration"
            mount_path = var.configuration_mount_path
            read_only  = true
          }
        }

        volume {
          name = "tmp"
          empty_dir {
            size_limit = "64Mi"
          }
        }

        volume {
          name = "configuration"
          secret {
            secret_name  = var.configuration_secret_name
            optional     = false
            default_mode = "0440"

            items {
              key  = var.configuration_secret_key
              path = var.configuration_secret_key
              mode = "0440"
            }
          }
        }

        topology_spread_constraint {
          max_skew           = 1
          topology_key       = "kubernetes.io/hostname"
          when_unsatisfiable = "ScheduleAnyway"

          label_selector {
            match_labels = local.service_selector_labels
          }
        }

        node_selector = var.node_selector

        dynamic "toleration" {
          for_each = var.tolerations
          content {
            key                = toleration.value.key
            operator           = toleration.value.operator
            value              = toleration.value.value
            effect             = toleration.value.effect
            toleration_seconds = toleration.value.toleration_seconds
          }
        }
      }
    }
  }

  depends_on = [kubernetes_job_v1.migration]

  lifecycle {
    precondition {
      condition     = length(distinct(local.configurable_env_names)) == length(local.configurable_env_names)
      error_message = "github_token_secret_name, secret_env, and extra_env must not define duplicate environment variable names."
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
    labels    = local.base_labels
  }

  spec {
    type     = "ClusterIP"
    selector = local.service_selector_labels

    port {
      name        = "http"
      port        = var.port
      target_port = "http"
      protocol    = "TCP"
    }
  }
}

resource "kubernetes_pod_disruption_budget_v1" "gate" {
  count = var.pdb_enabled ? 1 : 0

  metadata {
    name      = var.name
    namespace = var.namespace
    labels    = local.base_labels
  }

  spec {
    min_available = var.pdb_min_available

    selector {
      match_labels = local.service_selector_labels
    }
  }
}
