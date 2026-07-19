# SPDX-License-Identifier: Apache-2.0
#
# EMILIA Gate — reference Terraform module (EP-GATE-TF-v1) — outputs.

output "module_version" {
  description = "Versioned identifier of this reference module."
  value       = "EP-GATE-TF-v1"
}

output "service_name" {
  description = "Name of the Kubernetes Service fronting the gate."
  value       = kubernetes_service_v1.gate.metadata[0].name
}

output "namespace" {
  description = "Namespace the gate is deployed into."
  value       = kubernetes_service_v1.gate.metadata[0].namespace
}

output "service_endpoint" {
  description = "In-cluster HTTP endpoint of the gate (cluster-DNS form). Point guarded callers at this."
  value       = "http://${kubernetes_service_v1.gate.metadata[0].name}.${kubernetes_service_v1.gate.metadata[0].namespace}.svc.cluster.local:${var.service_port}"
}

output "deployment_name" {
  description = "Name of the gate Deployment."
  value       = kubernetes_deployment_v1.gate.metadata[0].name
}

output "manifest_config_map_name" {
  description = "Name of the ConfigMap carrying the action-risk manifest."
  value       = kubernetes_config_map_v1.manifest.metadata[0].name
}
