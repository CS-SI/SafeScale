{{- $extra := .Extra }}
{{- if not $extra.MarkedForDestruction }}
{{-   $rsc := .Resource }}
{{-   $provider := .Provider }}
{{-   range $v := $extra.Request.Subnets }}
resource "openstack_networking_port_v2" "nic_{{ $rsc.Name }}_{{ $v.Name }}" {
	provider           = openstack.ovh
	name               = "nic-{{ $rsc.Name }}-{{ $v.Name }}"
	network_id         = "{{ $v.Network }}"
	admin_state_up     = true
	region             = "{{ $provider.Authentication.Region }}"
    # security_group_ids = var.request.ports[count.index].SecurityGroupIDs
	fixed_ip {
		subnet_id = "{{ $v.ID }}"
	}

	lifecycle {
{{-     if not $extra.MarkedForCreation }}
		prevent_destroy = true
{{-     end }}
	}
}
{{-   end }}

resource "openstack_compute_instance_v2" "{{ $rsc.Name }}" {
	provider          = openstack.ovh
	name              = "{{ $rsc.Name }}"
	flavor_name       = "{{ $extra.Request.TemplateRef }}"
	image_id          = "{{ $rsc.Sizing.ImageID }}"
{{-   if gt (len $extra.Request.SecurityGroupByID) 0 }}
{{-      $sep := "" }}
	security_groups   = [ {{- range $k, $v := $extra.Request.SecurityGroupByID }}{{ $sep }}"{{ $v }}"{{ $sep = ", " }}{{- end }} ]
{{-   else }}
	security_groups   = [ "default" ]
{{-   end }}
	region            = "{{ $provider.Authentication.Region }}"
	availability_zone = "{{ $extra.AvailabilityZone }}"
{{-   if eq $extra.WantedHostState "started" }}
	power_state       = "active"
{{-   else if eq $extra.WantedHostState "stopped" }}
	power_state       = "shutoff"
{{-   end }}

{{-   if or $rsc.Networking.IsGateway $extra.Request.PublicIP }}
	network {
		name = "Ext-Net"
	}
{{-   end }}
{{-   range $v := $extra.Request.Subnets }}
	network {
		port = "${openstack_networking_port_v2.nic_{{ $rsc.Name }}_{{ $v.Name }}.id}"
	}
{{-   end }}

    block_device {
		uuid                  = "{{ $rsc.Sizing.ImageID }}"
		source_type           = "image"
		destination_type      = "local"
		volume_size           = {{ $rsc.Sizing.DiskSize }}
		boot_index            = 0
		delete_on_termination = true
	}

	user_data = "${file("{{ $rsc.Name }}_userdata")}"

	metadata = {
{{-   range $t, $v := $rsc.Tags }}
		{{ $t }} = "{{ $v }}"
{{-   end }}
	}

	lifecycle {
		ignore_changes = [block_device, user_data]
{{-   if not $extra.MarkedForCreation }}
		prevent_destroy = true
{{-   end }}
	}
}

output "host_{{ $rsc.Name }}" {
	value = "${openstack_compute_instance_v2.{{ $rsc.Name }}}"
	sensitive = true
}
# output "host_{{ $rsc.Name }}_id" {
# 	value = "${openstack_compute_instance_v2.{{ $rsc.Name }}.id}"
# }
# output "host_{{ $rsc.Name}}_networks" {
# 	value = "${openstack_compute_instance_v2.{{ $rsc.Name }}.network.*}"
# }
{{- end }}
