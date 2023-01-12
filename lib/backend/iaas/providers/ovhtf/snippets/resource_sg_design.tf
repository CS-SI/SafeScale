{{- if not .Extra.MarkedForDestruction }}
resource "openstack_networking_secgroup_v2" "{{ .Resource.Name }}" {
    provider                = openstack.ovh
    name                    = "{{ .Resource.Name }}"
    region                  = "{{ .Provider.Authentication.Region }}"
    description             = "{{ .Resource.Description }}"
    tenant_id               = "{{ .Provider.Authentication.TenantID }}"
    delete_default_rules    = true

    lifecycle {
{{-   if not .Extra.MarkedForCreation }}
        prevent_destroy = true
{{-   end }}
    }
}

output "sg_{{ .Resource.Name }}" {
    value = "${openstack_networking_secgroup_v2.{{ .Resource.Name }}}"
    sensitive = true
}
output "sg_{{ .Resource.Name }}_id" {
    value = "${openstack_networking_secgroup_v2.{{ .Resource.Name }}.id}"
}

{{-   $rsc := .Resource }}
{{-   $tenantId := .Provider.Authentication.TenantID }}
{{-   $tenantName := .Provider.Authentication.TenantName }}
{{-   $extra := .Extra }}
{{-   range $k, $v := $rsc.Rules }}
{{-     $target := "" }}
{{-     if eq $v.Direction 1 }}
{{-       $target = $v.Sources }}
{{-     else if eq $v.Direction 2 }}
{{-       $target = $v.Targets }}
{{-     end }}
{{-     range $i, $t := $target }}
{{-       $target_keyword := "remote_group_id"}}
{{-       if regexMatch `^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})|([0-9A-Fa-f]{0,4}:){2,7}([0-9A-Fa-f]{0,4})` $t }}
{{-         $target_keyword = "remote_ip_prefix" }}
{{-       end }}
resource "openstack_networking_secgroup_rule_v2" "{{ $rsc.Name }}_rule_{{ $k }}_{{ $i }}" {
    provider                = openstack.ovh
    description             = "{{ $v.Description }}"
    direction               = "{{ $v.Direction }}"
    ethertype               = "{{ $v.EtherType }}"
    protocol                = "{{ $v.Protocol }}"
    port_range_min          = {{ $v.PortFrom }}
    port_range_max          = {{ or $v.PortTo $v.PortFrom }}
    {{ $target_keyword }}   = "{{ $t }}"
    tenant_id               = "{{ or $tenantId $tenantName }}"
    security_group_id       = "${openstack_networking_secgroup_v2.{{ $rsc.Name }}.id}"

    lifecycle {
{{-       if not $extra.MarkedForCreation }}
        prevent_destroy = true
{{-       end }}
    }
}

output "sg_{{ $rsc.Name }}_rule_{{ $k }}_{{ $i }}_id" {
    value = "${openstack_networking_secgroup_rule_v2.{{ $rsc.Name }}_rule_{{ $k }}_{{ $i }}.id}"
}
{{-     end }}
{{-   end }}
{{- end }}
