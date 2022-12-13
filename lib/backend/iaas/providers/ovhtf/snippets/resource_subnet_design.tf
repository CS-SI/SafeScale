resource "openstack_networking_subnet_v2" "{{ .Resource.Name }}" {
    provider                = openstack.ovh
    name                    = "{{ .Resource.Name }}"
    network_id              = "{{ .Resource.Network }}"
    cidr                    = "{{ .Resource.CIDR }}"
    ip_version              = {{ eq .Resource.IPVersion 6 | ternary 6 4 }}
    region                  = "{{ .Provider.Authentication.Region }}"
    enable_dhcp             = true

    lifecycle {
{{- if and (not .Extra.MarkedForCreation) (not .Extra.MarkedForDestruction) }}
        prevent_destroy = true
{{- end }}
    }
}

output "subnet_{{ .Resource.Name }}_id" {
    value = "${openstack_networking_subnet_v2.{{ .Resource.Name }}.id}"
}

{{- if .Provider.Configuration.UseLayer3Networking }}
resource "openstack_networking_router_v2" "{{ .Resource.Name }}" {
    provider                = openstack.ovh
    name                    = "{{ .Resource.Name }}"
    external_network_id     = "{{ .Provider.Configuration.ProviderNetworkID }}"
    tenant_id               = "{{ .Provider.Authentication.TenantID }}"
    region                  = "{{ .Provider.Authentication.Region }}"

    lifecycle {
{{- if and (not .Extra.MarkedForCreation) (not .Extra.MarkedForDestruction) }}
        prevent_destroy = true
{{- end }}
    }
}

resource "openstack_networking_router_interface_v2" "router_interface_1" {
    router_id = "${openstack_networking_router_v2.{{ .Resource.Name }}.id}"
    subnet_id = "${openstack_networking_subnet_v2.{{ .Resource.Name }}.id}"

    lifecycle {
{{- if and (not .Extra.MarkedForCreation) (not .Extra.MarkedForDestruction) }}
        prevent_destroy = true
{{- end }}
    }
}

output "router_{{ .Resource.Name }}_id" {
    value = "${openstack_networking_router_v2.{{ .Resource.Name }}.id}"
}
{{- end }}

