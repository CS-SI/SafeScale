terraform {
    required_version = "{{ .Terraformer.Config.Release }}"
{{- if .Terraformer.Config.RequiredProviders }}
    required_providers {
{{-   range $k, $i := .Terraformer.Config.RequiredProviders }}
        {{ $k }} = {
            source  = "{{ $i.Source }}"
            version = "{{ $i.Version }}"
        }
{{-   end }}
    }
{{- end }}

{{ if .ConsulBackendConfig }}
    {{ .ConsulBackendConfig }}
{{ end }}
}

{{ .ProviderDeclaration }}

{{- if .Resources }}
{{-   range $i := .Resources }}
{{      $i }}
{{-   end }}
{{- end }}
