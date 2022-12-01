resource "openstack_networking_network_v2" "{{ .Resource.Name }}" {
    provider              = openstack.ovh
    name                  = "{{ .Resource.Name }}"
    admin_state_up        = true
    port_security_enabled = true
    shared                = false
    tenant_id             = "{{ .Provider.Authentication.TenantID }}"
    region                = "{{ .Provider.Authentication.Region }}"

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

output "network_{{ .Resource.Name }}_id" {
    value = "${openstack_networking_network_v2.{{ .Resource.Name }}.id}"
}
