output "service_name" {
  description = "ClusterIP Service name."
  value       = kubernetes_service_v1.gate.metadata[0].name
}

output "service_dns" {
  description = "In-cluster DNS name for the Gate service."
  value       = "${kubernetes_service_v1.gate.metadata[0].name}.${var.namespace}.svc"
}

output "deployment_name" {
  description = "Gate Deployment name."
  value       = kubernetes_deployment_v1.gate.metadata[0].name
}

output "migration_job_name" {
  description = "Migration Job name, or null when migrations are disabled."
  value       = var.migration_enabled ? kubernetes_job_v1.migration[0].metadata[0].name : null
}
