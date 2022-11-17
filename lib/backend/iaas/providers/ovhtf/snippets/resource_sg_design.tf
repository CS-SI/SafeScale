resource "openstack_networking_secgroup_v2" "{{ .Resource.Name }}" {
    provider                = openstack.ovh
    name                    = "{{ .Resource.Name }}"
    region                  = "{{ .Provider.Authentication.Region }}"
    description             = "{{ .Resource.Description }}"
    tenant_id               = "{{ .Provider.Authentication.TenantID }}"
    delete_default_rules    = true
}

output "sg_{{ .Resource.Name }}_id" {
    value                   = ["${openstack_networking_secgroup_v2.{{ .Resource.Name }}.id}"]
}

{{- range $k, $v := .Resource.Rules }}
resource "openstack_networking_secgroup_rule_v2" "{{ .Resource.Name }}-rule-{{ $k }}" {
    provider                = openstack.ovh
    description             = "{{ $v.Description }}
    direction               = "{{ $v.Direction }}
    ethertype               = "{{ $v.EtherType }}"
    protocol                = "{{ $v.Protocol }}"
    port_range_min          = {{ $v.PortFrom }}
    port_range_max          = {{ or $v.PortTo 0 }}
    remote_ip_prefix        = "{{ $v.Remote }}"
    tenant_id               = "{{ or .Provider.Authentication.TenantId .Provider.Authentication.TenantName }}"
    security_group_id       = ${openstack_networking_secgroup_v2.{{ .Resource.Name }}.id}
}

output "sg_{{ .Resource.Name }}_rule_{{ $k }}_id" {
    value = "${openstack_networking_secgroup_rule_v2.{{ .Resource.Name }}-rule-{{ $k }}.id}"]
}
{{ end }}
