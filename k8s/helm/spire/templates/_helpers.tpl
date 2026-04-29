{{/*
Expand the name of the chart.
*/}}
{{- define "skauswatch-spire.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "skauswatch-spire.fullname" -}}
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
{{- define "skauswatch-spire.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "skauswatch-spire.labels" -}}
helm.sh/chart: {{ include "skauswatch-spire.chart" . }}
{{ include "skauswatch-spire.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "skauswatch-spire.selectorLabels" -}}
app.kubernetes.io/name: {{ include "skauswatch-spire.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use for server
*/}}
{{- define "skauswatch-spire.serverServiceAccountName" -}}
{{- if .Values.spire.server.serviceAccount.create }}
{{- default (printf "%s-server" (include "skauswatch-spire.fullname" .)) .Values.spire.server.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.spire.server.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the service account to use for agent
*/}}
{{- define "skauswatch-spire.agentServiceAccountName" -}}
{{- if .Values.spire.agent.serviceAccount.create }}
{{- default (printf "%s-agent" (include "skauswatch-spire.fullname" .)) .Values.spire.agent.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.spire.agent.serviceAccount.name }}
{{- end }}
{{- end }}
