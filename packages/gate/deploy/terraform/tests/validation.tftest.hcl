mock_provider "kubernetes" {}

run "default_is_single_replica_with_secret_refs" {
  command = plan

  variables {
    image                    = "registry.example.test/security/emilia-gate@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    manifest_json            = "{\"actions\":[]}"
    issuer_keys_secret_name  = "gate-issuer-keys"
    github_token_secret_name = "gate-github"
    secret_env = {
      GENERIC_SECRET = {
        secret_name = "gate-generic"
        secret_key  = "value"
      }
    }
  }

  assert {
    condition     = tostring(kubernetes_deployment_v1.gate.spec[0].replicas) == "1"
    error_message = "Legacy Terraform must default to one replica."
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
      item.name == "GENERIC_SECRET"
      && try(item.value_from[0].secret_key_ref[0].name == "gate-generic", false)
    ])
    error_message = "Generic secret environment input must render as a secretKeyRef."
  }
}

run "reject_unsafe_multi_replica" {
  command = plan

  variables {
    image                   = "registry.example.test/security/emilia-gate@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    manifest_json           = "{\"actions\":[]}"
    issuer_keys_secret_name = "gate-issuer-keys"
    replicas                = 2
  }

  expect_failures = [kubernetes_deployment_v1.gate]
}

run "allow_explicit_shared_backends" {
  command = plan

  variables {
    image                   = "registry.example.test/security/emilia-gate@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    manifest_json           = "{\"actions\":[]}"
    issuer_keys_secret_name = "gate-issuer-keys"
    replicas                = 2
    shared_consumption_backend = {
      env_name    = "EP_GATE_CONSUMPTION_DATABASE_URL"
      secret_name = "gate-consumption"
      secret_key  = "database-url"
    }
    shared_evidence_backend = {
      env_name    = "EP_GATE_EVIDENCE_DATABASE_URL"
      secret_name = "gate-evidence"
      secret_key  = "database-url"
    }
  }

  assert {
    condition = alltrue([
      for expected in ["gate-consumption", "gate-evidence"] : anytrue([
        for item in kubernetes_deployment_v1.gate.spec[0].template[0].spec[0].container[0].env :
        try(item.value_from[0].secret_key_ref[0].name == expected, false)
      ])
    ])
    error_message = "Both shared backend references must render as secretKeyRefs."
  }
}
