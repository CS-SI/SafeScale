resource "openstack_blockstorage_volume_v2" "{{ .Resource.Name }}" {
    provider    = openstack.ovh
    name        = "{{ .Resource.Name }}"
    description = "{{ .Resource.Description }}"
    size        = {{ .Resource.Size }}
    region      = "{{ .Provider.Authentication.Region }}"
    tenant_id   = "{{ .Provider.Authentication.TenantID }}"

    tags = {
{{ for $t, $v := range .Resource.Tags }}
        {{ $t }} = "{{ $v }}"
{{ end }}
    }

    lifecycle {
{{- if not .Extra.MarkedForDestroy }}
        prevent_destroy = true
{{ end }}
    }
}

output "volume_{{ .Resource.Name }}_id" {
    value = "${openstack_blockstorage_volume_v2.{{ .Resource.Name }}.id}"
}
