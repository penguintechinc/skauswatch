{{/*
Expand the name of the chart.
*/}}
{{- define "skauswatch-endpoint-agent.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "skauswatch-endpoint-agent.fullname" -}}
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
Name of the Secret this chart consumes. If .Values.existingSecret is
set, use that pre-provisioned Secret/ExternalSecret instead of the
chart-managed one (templates/secret.yaml is not rendered in that case).
*/}}
{{- define "skauswatch-endpoint-agent.secretName" -}}
{{- .Values.existingSecret | default (printf "%s-secret" (include "skauswatch-endpoint-agent.fullname" .)) }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "skauswatch-endpoint-agent.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "skauswatch-endpoint-agent.labels" -}}
helm.sh/chart: {{ include "skauswatch-endpoint-agent.chart" . }}
{{ include "skauswatch-endpoint-agent.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "skauswatch-endpoint-agent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "skauswatch-endpoint-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "skauswatch-endpoint-agent.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "skauswatch-endpoint-agent.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Full image reference. Production pins by SHA256 digest (tag starts with
"sha256:") -> "repo@sha256:...". Alpha/beta/gamma use a mutable tag ->
"repo:tag".
*/}}
{{- define "skauswatch-endpoint-agent.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion }}
{{- if hasPrefix "sha256:" $tag }}
{{- printf "%s@%s" .Values.image.repository $tag }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository $tag }}
{{- end }}
{{- end }}
