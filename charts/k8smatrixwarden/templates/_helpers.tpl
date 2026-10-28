{{- define "k8smw.name" -}}{{ .Release.Name }}-k8smatrixwarden{{- end -}}
{{- define "k8smw.labels" -}}
app.kubernetes.io/name: k8smatrixwarden
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
