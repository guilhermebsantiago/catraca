{{/* The chart name, or nameOverride. */}}
{{- define "catraca.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* The name of the release's objects, or fullnameOverride. */}}
{{- define "catraca.fullname" -}}
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

{{- define "catraca.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "catraca.labels" -}}
helm.sh/chart: {{ include "catraca.chart" . }}
{{ include "catraca.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{- define "catraca.selectorLabels" -}}
app.kubernetes.io/name: {{ include "catraca.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "catraca.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "catraca.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* The Secret the tokens, feedback secrets and DSNs come from. */}}
{{- define "catraca.secretName" -}}
{{- default (include "catraca.fullname" .) .Values.secret.name }}
{{- end }}

{{- define "catraca.rulesConfigMapName" -}}
{{- default (printf "%s-rules" (include "catraca.fullname" .)) .Values.rules.existingConfigMap }}
{{- end }}

{{/* The image: repository, then @digest or :tag (by default v + appVersion). */}}
{{- define "catraca.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (default (printf "v%s" .Chart.AppVersion) .Values.image.tag) }}
{{- end }}
{{- end }}

{{/* Where the pod mounts the configuration and the ruleset. */}}
{{- define "catraca.configDir" -}}/etc/catraca/config{{- end }}
{{- define "catraca.rulesDir" -}}/etc/catraca/rules{{- end }}

{{/*
The configuration file: .Values.config, with the fields the chart owns set
from the chart's values, so the ports and paths always match the pod's.
*/}}
{{- define "catraca.config" -}}
{{- $config := deepCopy (.Values.config | default dict) }}
{{- $server := get $config "server" | default dict }}
{{- $_ := set $server "listen" (printf ":%d" (int .Values.ports.http)) }}
{{- $_ := set $server "admin_addr" (printf ":%d" (int .Values.ports.admin)) }}
{{- $_ := set $config "server" $server }}
{{- $rules := get $config "rules" | default dict }}
{{- $_ := set $rules "path" (printf "%s/%s" (include "catraca.rulesDir" .) .Values.rules.key) }}
{{- $_ := set $config "rules" $rules }}
{{- toYaml $config }}
{{- end }}

{{/* More than one pod at a time, now or once the HPA scales out. */}}
{{- define "catraca.multiReplica" -}}
{{- if or (gt (int .Values.replicaCount) 1) .Values.autoscaling.enabled }}true{{ end }}
{{- end }}
