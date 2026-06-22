{{/*
Expand the name of the chart.
*/}}
{{- define "assayward-webhook.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this.
If release name contains chart name it will be used as a full name.
*/}}
{{- define "assayward-webhook.fullname" -}}
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
Create chart label value: <chart-name>-<chart-version>.
*/}}
{{- define "assayward-webhook.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to every resource.
*/}}
{{- define "assayward-webhook.labels" -}}
helm.sh/chart: {{ include "assayward-webhook.chart" . }}
{{ include "assayward-webhook.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels used by Deployments/Services.
*/}}
{{- define "assayward-webhook.selectorLabels" -}}
app.kubernetes.io/name: {{ include "assayward-webhook.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Service-account name.
*/}}
{{- define "assayward-webhook.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "assayward-webhook.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
TLS Secret name.
*/}}
{{- define "assayward-webhook.tlsSecretName" -}}
{{- printf "%s-tls" (include "assayward-webhook.fullname" .) }}
{{- end }}

{{/*
Service DNS names used as TLS SANs.
*/}}
{{- define "assayward-webhook.serviceDNS" -}}
{{- $fullname := include "assayward-webhook.fullname" . }}
{{- $ns := .Release.Namespace }}
{{- printf "%s.%s.svc" $fullname $ns }}
{{- end }}

{{/*
Full cluster-local service DNS.
*/}}
{{- define "assayward-webhook.serviceClusterDNS" -}}
{{- $fullname := include "assayward-webhook.fullname" . }}
{{- $ns := .Release.Namespace }}
{{- printf "%s.%s.svc.cluster.local" $fullname $ns }}
{{- end }}

{{/*
Image tag: use .Values.image.tag when set; fall back to appVersion.
*/}}
{{- define "assayward-webhook.imageTag" -}}
{{- .Values.image.tag | default .Chart.AppVersion }}
{{- end }}

{{/*
ConfigMap name for policy/trust roots.
*/}}
{{- define "assayward-webhook.configmapName" -}}
{{- printf "%s-config" (include "assayward-webhook.fullname" .) }}
{{- end }}
