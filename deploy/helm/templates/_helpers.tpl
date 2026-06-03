"""Helm chart helpers template."""
{{- define "ddos.name" -}}
{{ .Chart.Name }}
{{- end }}

{{- define "ddos.fullname" -}}
{{ .Release.Name }}-{{ .Chart.Name }}
{{- end }}

{{- define "ddos.labels" -}}
app.kubernetes.io/name: {{ include "ddos.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}
