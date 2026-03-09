{{- define "icebox-pki-server.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "icebox-pki-server.fullname" -}}
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

{{- define "icebox-pki-server.labels" -}}
helm.sh/chart: {{ include "icebox-pki-server.name" . }}-{{ .Chart.Version | replace "+" "_" }}
{{ include "icebox-pki-server.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: pki-server
app.kubernetes.io/part-of: icebox
{{- end }}

{{- define "icebox-pki-server.selectorLabels" -}}
app.kubernetes.io/name: {{ include "icebox-pki-server.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
