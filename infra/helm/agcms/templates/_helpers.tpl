{{/*
Expand the name of the chart.
*/}}
{{- define "agcms.name" -}}
{{- default .Chart.Name .Values.global.releaseName | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Namespace the chart deploys into.
*/}}
{{- define "agcms.namespace" -}}
{{- default .Release.Namespace .Values.global.namespace -}}
{{- end -}}

{{/*
Fully qualified app name: release-name + chart-name, DNS-1123 safe.
*/}}
{{- define "agcms.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "agcms.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Standard labels applied to every resource.
*/}}
{{- define "agcms.labels" -}}
app.kubernetes.io/name: {{ include "agcms.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{/*
Per-service selector labels. Call with $svcName.
*/}}
{{- define "agcms.selectorLabels" -}}
app.kubernetes.io/name: {{ include "agcms.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .svcName }}
{{- end -}}

{{/*
Service account name.
*/}}
{{- define "agcms.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "agcms.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Image reference: registry + repo + tag.
Call with (dict "svc" <svcValues> "root" $).
*/}}
{{- define "agcms.image" -}}
{{- $reg := .root.Values.image.registry -}}
{{- $tag := default .root.Values.image.tag (hasKey .svc "tag" | ternary .svc.tag "") -}}
{{- printf "%s/%s:%s" $reg .svc.image $tag -}}
{{- end -}}
