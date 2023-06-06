variable "tags-{{.MachineName}}" {
  type = map(string)
{{ if .Tags }}
  default = {
  {{ range $key, $value := .Tags }}
   {{ $key }} = "{{ $value }}"
  {{ end }}
  }
{{ else }}
  default = {}
{{ end }}
}
