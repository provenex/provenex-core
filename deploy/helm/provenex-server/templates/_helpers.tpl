{{/*
Common helpers — name, fullname, labels, selectorLabels.
Standard Helm chart boilerplate; kept short so the rest of the chart
stays readable.
*/}}

{{- define "provenex-server.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{- define "provenex-server.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end }}

{{- define "provenex-server.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "provenex-server.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "provenex-server.selectorLabels" -}}
app.kubernetes.io/name: {{ include "provenex-server.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "provenex-server.envFromSecrets" -}}
- name: PROVENEX_SIGNING_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ .Values.secrets.name }}
      key: {{ .Values.secrets.indexHmacKey }}
{{- if .Values.secrets.receiptEd25519Key }}
- name: PROVENEX_RECEIPT_PRIVATE_KEY_FILE
  value: /run/secrets/provenex/{{ .Values.secrets.receiptEd25519Key }}
{{- else if .Values.secrets.receiptHmacKey }}
- name: PROVENEX_RECEIPT_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ .Values.secrets.name }}
      key: {{ .Values.secrets.receiptHmacKey }}
{{- end }}
- name: PROVENEX_DATABASE_DSN
  valueFrom:
    secretKeyRef:
      name: {{ include "provenex-server.dsnSecret" . }}
      key: dsn
{{- end }}

{{- define "provenex-server.dsnSecret" -}}
{{- if .Values.externalDsnSecret }}
{{- .Values.externalDsnSecret }}
{{- else -}}
{{ include "provenex-server.fullname" . }}-bundled-dsn
{{- end -}}
{{- end }}
