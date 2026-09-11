{{/*
Expand the name of the chart.
*/}}
{{- define "skauswatch-svc-ingest.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "skauswatch-svc-ingest.fullname" -}}
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
Name of the Secret this chart consumes. If .Values.existingSecret is set,
use that pre-provisioned Secret/ExternalSecret (e.g. synced from svc-vault
with the ingest mTLS/token material, alongside db-user/db-pass/
jwt-verify-key/license-key) instead of the chart-managed one below --
templates/secret.yaml is not rendered in that case.
*/}}
{{- define "skauswatch-svc-ingest.secretName" -}}
{{- .Values.existingSecret | default (printf "%s-secret" (include "skauswatch-svc-ingest.fullname" .)) }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "skauswatch-svc-ingest.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels shared by every object in this chart.
*/}}
{{- define "skauswatch-svc-ingest.labels" -}}
helm.sh/chart: {{ include "skauswatch-svc-ingest.chart" . }}
{{ include "skauswatch-svc-ingest.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Chart-wide selector labels (no component) -- used by objects that span
BOTH the receiver and writer Deployments (ConfigMap, Secret, TracingPolicy
exec-allowlist, which allowlists the one binary both modes share).
*/}}
{{- define "skauswatch-svc-ingest.selectorLabels" -}}
app.kubernetes.io/name: {{ include "skauswatch-svc-ingest.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Receiver component fullname -- "<fullname>-receiver". Separate Deployment
name so receiver/writer scale independently (services/svc-ingest/src/
bootstrap.rs).
*/}}
{{- define "skauswatch-svc-ingest.receiver.fullname" -}}
{{- printf "%s-receiver" (include "skauswatch-svc-ingest.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Receiver component selector labels -- adds app.kubernetes.io/component so
the receiver and writer Deployments never share a pod selector (and a
Service/CiliumNetworkPolicy scoped to one never accidentally matches the
other's pods).
*/}}
{{- define "skauswatch-svc-ingest.receiver.selectorLabels" -}}
{{ include "skauswatch-svc-ingest.selectorLabels" . }}
app.kubernetes.io/component: receiver
{{- end }}

{{/*
Receiver component labels (common + selector + component).
*/}}
{{- define "skauswatch-svc-ingest.receiver.labels" -}}
{{ include "skauswatch-svc-ingest.labels" . }}
app.kubernetes.io/component: receiver
{{- end }}

{{/*
Writer component fullname -- "<fullname>-writer".
*/}}
{{- define "skauswatch-svc-ingest.writer.fullname" -}}
{{- printf "%s-writer" (include "skauswatch-svc-ingest.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Writer component selector labels.
*/}}
{{- define "skauswatch-svc-ingest.writer.selectorLabels" -}}
{{ include "skauswatch-svc-ingest.selectorLabels" . }}
app.kubernetes.io/component: writer
{{- end }}

{{/*
Writer component labels (common + selector + component).
*/}}
{{- define "skauswatch-svc-ingest.writer.labels" -}}
{{ include "skauswatch-svc-ingest.labels" . }}
app.kubernetes.io/component: writer
{{- end }}

{{/*
Full image reference -- shared by both receiver and writer (one binary,
`serve --mode receiver|writer` selects behavior). Production pins by
SHA256 digest (tag starts with "sha256:") -> "repo@sha256:...". Alpha/
beta/gamma use a mutable tag -> "repo:tag".
*/}}
{{- define "skauswatch-svc-ingest.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion }}
{{- if hasPrefix "sha256:" $tag }}
{{- printf "%s@%s" .Values.image.repository $tag }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository $tag }}
{{- end }}
{{- end }}
