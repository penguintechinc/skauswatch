{{/*
Expand the name of the chart.
*/}}
{{- define "skauswatch-sshca.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "skauswatch-sshca.fullname" -}}
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
{{- define "skauswatch-sshca.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "skauswatch-sshca.labels" -}}
helm.sh/chart: {{ include "skauswatch-sshca.chart" . }}
{{ include "skauswatch-sshca.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "skauswatch-sshca.selectorLabels" -}}
app.kubernetes.io/name: {{ include "skauswatch-sshca.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "skauswatch-sshca.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "skauswatch-sshca.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Full image reference. Production pins by SHA256 digest (tag starts with
"sha256:") -> "repo@sha256:...". Alpha/beta/gamma use a mutable tag ->
"repo:tag".
*/}}
{{- define "skauswatch-sshca.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion }}
{{- if hasPrefix "sha256:" $tag }}
{{- printf "%s@%s" .Values.image.repository $tag }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository $tag }}
{{- end }}
{{- end }}
