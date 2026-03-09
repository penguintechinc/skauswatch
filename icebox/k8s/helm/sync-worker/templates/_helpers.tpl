{{/*
Expand the name of the chart.
*/}}
{{- define "icebox-sync-worker.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "icebox-sync-worker.fullname" -}}
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
Common labels
*/}}
{{- define "icebox-sync-worker.labels" -}}
helm.sh/chart: {{ include "icebox-sync-worker.name" . }}-{{ .Chart.Version | replace "+" "_" }}
{{ include "icebox-sync-worker.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: sync-worker
app.kubernetes.io/part-of: icebox
{{- end }}

{{/*
Selector labels
*/}}
{{- define "icebox-sync-worker.selectorLabels" -}}
app.kubernetes.io/name: {{ include "icebox-sync-worker.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
