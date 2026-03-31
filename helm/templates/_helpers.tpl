{{/*
Expand the name of the chart.
*/}}
{{- define "mcp-honeypot.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
Truncated to 63 characters because Kubernetes name fields are limited.
*/}}
{{- define "mcp-honeypot.fullname" -}}
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
Common labels applied to all resources.
*/}}
{{- define "mcp-honeypot.labels" -}}
helm.sh/chart: {{ include "mcp-honeypot.name" . }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{ include "mcp-honeypot.selectorLabels" . }}
{{- end }}

{{/*
Selector labels (used in both metadata.labels and spec.selector.matchLabels).
*/}}
{{- define "mcp-honeypot.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mcp-honeypot.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Component-scoped selector labels.
Usage: {{ include "mcp-honeypot.componentLabels" (dict "component" "honeypot" "root" .) }}
*/}}
{{- define "mcp-honeypot.componentLabels" -}}
{{ include "mcp-honeypot.selectorLabels" .root }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
Component-scoped full labels (common + component).
Usage: {{ include "mcp-honeypot.componentFullLabels" (dict "component" "honeypot" "root" .) }}
*/}}
{{- define "mcp-honeypot.componentFullLabels" -}}
{{ include "mcp-honeypot.labels" .root }}
app.kubernetes.io/component: {{ .component }}
{{- end }}
