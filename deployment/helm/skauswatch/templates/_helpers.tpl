{{/*
Expand the name of the chart.
*/}}
{{- define "skauswatch.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "skauswatch.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "skauswatch.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "skauswatch.labels" -}}
helm.sh/chart: {{ include "skauswatch.chart" . }}
{{ include "skauswatch.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: skauswatch
{{- end }}

{{/*
Selector labels
*/}}
{{- define "skauswatch.selectorLabels" -}}
app.kubernetes.io/name: {{ include "skauswatch.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Component labels for manager
*/}}
{{- define "skauswatch.manager.labels" -}}
{{ include "skauswatch.labels" . }}
app.kubernetes.io/component: manager
{{- end }}

{{/*
Component labels for PKI server
*/}}
{{- define "skauswatch.pki-server.labels" -}}
{{ include "skauswatch.labels" . }}
app.kubernetes.io/component: pki-server
{{- end }}

{{/*
Component labels for SSH CA
*/}}
{{- define "skauswatch.ssh-ca.labels" -}}
{{ include "skauswatch.labels" . }}
app.kubernetes.io/component: ssh-ca
{{- end }}

{{/*
Component labels for AAA Monitor
*/}}
{{- define "skauswatch.aaa-monitor.labels" -}}
{{ include "skauswatch.labels" . }}
app.kubernetes.io/component: aaa-monitor
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "skauswatch.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "skauswatch.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Generate the image name
*/}}
{{- define "skauswatch.image" -}}
{{- $registry := .Values.global.imageRegistry | default .Values.image.registry -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s/%s:%s" $registry .component $tag -}}
{{- end }}

{{/*
Storage class helper
*/}}
{{- define "skauswatch.storageClass" -}}
{{- $storageClass := .Values.global.storageClass | default .Values.persistence.storageClass -}}
{{- if $storageClass }}
storageClassName: {{ $storageClass | quote }}
{{- end }}
{{- end }}

{{/*
Security context for pods
*/}}
{{- define "skauswatch.podSecurityContext" -}}
runAsNonRoot: {{ .Values.security.securityContext.runAsNonRoot }}
runAsUser: {{ .Values.security.securityContext.runAsUser }}
runAsGroup: {{ .Values.security.securityContext.runAsGroup }}
fsGroup: {{ .Values.security.securityContext.fsGroup }}
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{/*
Security context for containers
*/}}
{{- define "skauswatch.containerSecurityContext" -}}
allowPrivilegeEscalation: {{ .Values.security.containerSecurityContext.allowPrivilegeEscalation }}
readOnlyRootFilesystem: {{ .Values.security.containerSecurityContext.readOnlyRootFilesystem }}
capabilities:
  drop:
  {{- range .Values.security.containerSecurityContext.capabilities.drop }}
  - {{ . }}
  {{- end }}
{{- end }}

{{/*
Database URL helper
*/}}
{{- define "skauswatch.databaseUrl" -}}
{{- if .Values.postgresql.enabled }}
postgresql://{{ .Values.postgresql.auth.username }}:{{ .Values.postgresql.auth.password }}@{{ .Release.Name }}-postgresql:5432/{{ .Values.postgresql.auth.database }}
{{- else }}
{{- required "External database URL required when postgresql.enabled is false" .Values.externalDatabase.url }}
{{- end }}
{{- end }}

{{/*
Redis URL helper
*/}}
{{- define "skauswatch.redisUrl" -}}
{{- if .Values.redis.enabled }}
redis://:{{ .Values.redis.auth.password }}@{{ .Release.Name }}-redis-master:6379
{{- else }}
{{- required "External Redis URL required when redis.enabled is false" .Values.externalRedis.url }}
{{- end }}
{{- end }}