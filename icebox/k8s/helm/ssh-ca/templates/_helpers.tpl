{{- define "icebox-ssh-ca.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "icebox-ssh-ca.fullname" -}}
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

{{- define "icebox-ssh-ca.labels" -}}
helm.sh/chart: {{ include "icebox-ssh-ca.name" . }}-{{ .Chart.Version | replace "+" "_" }}
{{ include "icebox-ssh-ca.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: ssh-ca
app.kubernetes.io/part-of: icebox
{{- end }}

{{- define "icebox-ssh-ca.selectorLabels" -}}
app.kubernetes.io/name: {{ include "icebox-ssh-ca.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
