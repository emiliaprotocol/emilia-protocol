mock_provider "kubernetes" {}

run "valid_distinct_migration_and_secret_env" {
  command = plan

  variables {
    namespace                      = "gate-system"
    image                          = "registry.example.test/security/emilia-gate-service@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    configuration_secret_name      = "gate-configuration"
    postgres_secret_name           = "gate-postgres"
    migration_postgres_secret_name = "gate-postgres-migrate"
    migration_postgres_secret_key  = "database-url"
    api_token_secret_name          = "gate-api-token"
    issuer_roots_secret_name       = "gate-issuer-roots"
    github_token_secret_name       = "gate-github"
    github_token_secret_key        = "token"
    secret_env = {
      SIEM_TOKEN = {
        secret_name = "gate-siem"
        secret_key  = "token"
      }
    }
  }

  assert {
    condition = anytrue([
      for item in kubernetes_deployment_v1.gate.spec[0].template[0].spec[0].container[0].env :
      item.name == "GITHUB_TOKEN"
      && try(item.value_from[0].secret_key_ref[0].name == "gate-github", false)
    ])
    error_message = "GitHub token must render only as a secretKeyRef."
  }

  assert {
    condition = anytrue([
      for item in kubernetes_deployment_v1.gate.spec[0].template[0].spec[0].container[0].env :
      item.name == "SIEM_TOKEN"
      && try(item.value_from[0].secret_key_ref[0].name == "gate-siem", false)
    ])
    error_message = "Generic secret environment input must render as a secretKeyRef."
  }

  assert {
    condition = anytrue([
      for item in kubernetes_job_v1.migration[0].spec[0].template[0].spec[0].container[0].env :
      item.name == "DATABASE_URL"
      && try(item.value_from[0].secret_key_ref[0].name == "gate-postgres-migrate", false)
    ])
    error_message = "Migration Job must use the distinct migration Secret."
  }

  assert {
    condition = (
      kubernetes_deployment_v1.gate.spec[0].template[0].spec[0].container[0].startup_probe[0].http_get[0].path == "/v1/live"
      && kubernetes_deployment_v1.gate.spec[0].template[0].spec[0].container[0].liveness_probe[0].http_get[0].path == "/v1/live"
      && kubernetes_deployment_v1.gate.spec[0].template[0].spec[0].container[0].readiness_probe[0].http_get[0].path == "/v1/ready"
    )
    error_message = "Gate probes must use the service live and ready routes."
  }
}

run "reject_missing_migration_secret" {
  command = plan

  variables {
    namespace                 = "gate-system"
    image                     = "registry.example.test/security/emilia-gate-service@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    configuration_secret_name = "gate-configuration"
    postgres_secret_name      = "gate-postgres"
    api_token_secret_name     = "gate-api-token"
    issuer_roots_secret_name  = "gate-issuer-roots"
  }

  expect_failures = [kubernetes_job_v1.migration]
}

run "reject_equal_migration_secret" {
  command = plan

  variables {
    namespace                      = "gate-system"
    image                          = "registry.example.test/security/emilia-gate-service@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    configuration_secret_name      = "gate-configuration"
    postgres_secret_name           = "gate-postgres"
    migration_postgres_secret_name = "gate-postgres"
    migration_postgres_secret_key  = "database-url"
    api_token_secret_name          = "gate-api-token"
    issuer_roots_secret_name       = "gate-issuer-roots"
  }

  expect_failures = [kubernetes_job_v1.migration]
}

run "allow_disabled_migration_without_secret" {
  command = plan

  variables {
    namespace                 = "gate-system"
    image                     = "registry.example.test/security/emilia-gate-service@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    configuration_secret_name = "gate-configuration"
    postgres_secret_name      = "gate-postgres"
    api_token_secret_name     = "gate-api-token"
    issuer_roots_secret_name  = "gate-issuer-roots"
    migration_enabled         = false
  }

  assert {
    condition     = length(kubernetes_job_v1.migration) == 0
    error_message = "Disabled migrations must not create a Job."
  }
}

run "reject_secret_env_override" {
  command = plan

  variables {
    namespace                      = "gate-system"
    image                          = "registry.example.test/security/emilia-gate-service@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    configuration_secret_name      = "gate-configuration"
    postgres_secret_name           = "gate-postgres"
    migration_postgres_secret_name = "gate-postgres-migrate"
    migration_postgres_secret_key  = "database-url"
    api_token_secret_name          = "gate-api-token"
    issuer_roots_secret_name       = "gate-issuer-roots"
    secret_env = {
      DATABASE_URL = {
        secret_name = "attacker-secret"
        secret_key  = "database-url"
      }
    }
  }

  expect_failures = [kubernetes_deployment_v1.gate]
}
