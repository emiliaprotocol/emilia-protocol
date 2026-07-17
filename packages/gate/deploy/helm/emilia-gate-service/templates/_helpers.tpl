{{- define "emilia-gate-service.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "emilia-gate-service.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "emilia-gate-service.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "emilia-gate-service.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | quote }}
app.kubernetes.io/name: {{ include "emilia-gate-service.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/part-of: emilia-gate
app.kubernetes.io/managed-by: {{ .Release.Service }}
emiliaprotocol.ai/deployment-model: byoc
{{- end -}}

{{- define "emilia-gate-service.baseSelectorLabels" -}}
app.kubernetes.io/name: {{ include "emilia-gate-service.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "emilia-gate-service.serviceSelectorLabels" -}}
{{ include "emilia-gate-service.baseSelectorLabels" . }}
app.kubernetes.io/component: service
{{- end -}}

{{- define "emilia-gate-service.image" -}}
{{- $repository := required "image.repository is required; build and push Dockerfile.gate to a registry you control" .Values.image.repository -}}
{{- if and .Values.image.tag .Values.image.digest -}}
{{- fail "set exactly one of image.tag or image.digest" -}}
{{- else if .Values.image.digest -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" .Values.image.digest) -}}
{{- fail "image.digest must be sha256:<64 lowercase hex characters>" -}}
{{- end -}}
{{- printf "%s@%s" $repository .Values.image.digest -}}
{{- else if .Values.image.tag -}}
{{- printf "%s:%s" $repository .Values.image.tag -}}
{{- else -}}
{{- fail "set exactly one of image.tag or image.digest; mutable implicit latest is refused" -}}
{{- end -}}
{{- end -}}

{{- define "emilia-gate-service.postgresSecret" -}}
{{- required "secrets.postgres.existingSecret is required; the chart only references existing Secrets" .Values.secrets.postgres.existingSecret -}}
{{- end -}}

{{- define "emilia-gate-service.migrationPostgresSecret" -}}
{{- $runtimeSecret := include "emilia-gate-service.postgresSecret" . -}}
{{- $migrationSecret := required "migrations.postgres.existingSecret is required when migrations.enabled=true; migration credentials never fall back to the runtime Secret" .Values.migrations.postgres.existingSecret -}}
{{- if eq $migrationSecret $runtimeSecret -}}
{{- fail "migrations.postgres.existingSecret must name a Secret distinct from secrets.postgres.existingSecret" -}}
{{- end -}}
{{- $migrationSecret -}}
{{- end -}}

{{- define "emilia-gate-service.migrationPostgresKey" -}}
{{- required "migrations.postgres.key is required when migrations.enabled=true" .Values.migrations.postgres.key -}}
{{- end -}}

{{- define "emilia-gate-service.configurationSecret" -}}
{{- required "configuration.existingSecret is required; apps/gate-service requires an operator-owned gate.config.mjs" .Values.configuration.existingSecret -}}
{{- end -}}

{{- define "emilia-gate-service.apiTokenSecret" -}}
{{- required "secrets.apiToken.existingSecret is required; action routes require operator authentication" .Values.secrets.apiToken.existingSecret -}}
{{- end -}}

{{- define "emilia-gate-service.kmsSecret" -}}
{{- .Values.secrets.kms.existingSecret -}}
{{- end -}}

{{- define "emilia-gate-service.issuerRootsSecret" -}}
{{- required "secrets.issuerRoots.existingSecret is required; the chart only references existing Secrets" .Values.secrets.issuerRoots.existingSecret -}}
{{- end -}}
