# SPDX-License-Identifier: Apache-2.0
#
# EMILIA Gate — reference Terraform module (EP-GATE-TF-v1).
# Provider and core version constraints. The kubernetes provider is the ONLY
# provider this module uses: everything lands in the deployer's own cluster,
# authenticated with the deployer's own credentials. No EMILIA-hosted backend,
# no remote state requirement, no callbacks.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.23.0, < 3.0.0"
    }
  }
}
