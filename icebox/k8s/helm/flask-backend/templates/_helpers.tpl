{{/*
Expand the name of the chart.
*/}}
{{- define "icebox-flask-backend.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "icebox-flask-backend.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "icebox-flask-backend.labels" -}}
helm.sh/chart: {{ include "icebox-flask-backend.name" . }}-{{ .Chart.Version }}
app.kubernetes.io/name: {{ include "icebox-flask-backend.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: flask-backend
app.kubernetes.io/part-of: icebox
{{- end }}

{{/*
Selector labels
*/}}
{{- define "icebox-flask-backend.selectorLabels" -}}
app.kubernetes.io/name: {{ include "icebox-flask-backend.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
