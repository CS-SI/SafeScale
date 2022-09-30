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

{{- if .Terraformer.Config.ConsulBackend.Use }}
    {{    or .ConsulBackendConfig "" }}
{{- end }}
}

{{ .ProviderDeclaration }}

{{- if .Terraformer.Config.ConsulBackend.Use }}
{{    or "" .ConsulBackendData }}
{{- end }}

{{- if .Resources }}
{{-   range $i := .Resources }}
{{      $i }}
{{-   end }}
{{- end }}
