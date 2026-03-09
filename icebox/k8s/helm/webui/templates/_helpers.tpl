{{- define "icebox-webui.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "icebox-webui.fullname" -}}
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

{{- define "icebox-webui.labels" -}}
helm.sh/chart: {{ include "icebox-webui.name" . }}-{{ .Chart.Version | replace "+" "_" }}
{{ include "icebox-webui.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: webui
app.kubernetes.io/part-of: icebox
{{- end }}

{{- define "icebox-webui.selectorLabels" -}}
app.kubernetes.io/name: {{ include "icebox-webui.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
