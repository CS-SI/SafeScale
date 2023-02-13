{{- if not .Extra.MarkedForDestruction }}
{{-   $extra := .Extra }}
{{-   $rsc := .Resource }}
{{-   $provider := .Provider }}
{{-   $region := $provider.Authentication.Region }}
{{-   $template := $extra.Template }}
{{-   $image := $extra.Image }}
{{-   $disksize := $extra.DiskSize }}
{{-   $publicip := default $extra.PublicIP false }}
{{-   $az := default $extra.AvailabilityZone "nova" }}
{{-   if hasField $extra "Subnets" }}
{{-     range $k, $v := $extra.Subnets }}
resource "openstack_networking_port_v2" "nic_{{ $rsc.Name }}_{{ $v.Name }}" {
	provider       = openstack.ovh
	name           = "nic-{{ $rsc.Name }}-{{ $v.Name }}"
	network_id     = "{{ $v.Network }}"
	admin_state_up = true
	region         = "{{ $region }}"

	fixed_ip {
		subnet_id = "{{ $v.ID }}"
	}
}
{{-     end }}
{{-   end }}

resource "openstack_compute_instance_v2" "{{ $rsc.Name }}" {
	provider          = openstack.ovh
	name              = "{{ $rsc.Name }}"
	flavor_name       = "{{ $template }}"
	image_id          = "{{ $image }}"

{{-   if gt (len $extra.SecurityGroupByID) 0 }}
{{-      $sep := "" }}
	security_groups   = [ {{- range $k, $v := $extra.SecurityGroupByID }}{{ $sep }}"{{ $v }}"{{ $sep = ", " }}{{- end }} ]
{{/*{{-   else }}
	security_groups   = [ "default" ]*/}}
{{-   end }}
	region            = "{{ $region }}"
	availability_zone = "{{ $az }}"
{{-   if eq $extra.WantedHostState "started" }}
	power_state       = "active"
{{-   else if eq $extra.WantedHostState "stopped" }}
	power_state       = "shutoff"
{{-   end }}

{{-   if $publicip }}
	network {
		name = "Ext-Net"
	}
{{-   end }}
{{-   range $k, $v := $extra.Subnets }}
	network {
		port = "${openstack_networking_port_v2.nic_{{ $rsc.Name }}_{{ $v.Name }}.id}"
	}
{{-   end }}

	block_device {
		uuid                  = "{{ $image }}"
		source_type           = "image"
		destination_type      = "local"
		volume_size           = {{ $disksize }}
		boot_index            = 0
		delete_on_termination = true
	}

{{- if $extra.MarkedForCreation }}
	user_data = "${file("{{ $rsc.Name }}_userdata")}"
{{- end }}

	metadata = {
{{-   range $t, $v := $rsc.Tags }}
		{{ $t }} = "{{ $v }}"
{{-   end }}
	}

	lifecycle {
		ignore_changes = [block_device, user_data, flavor_name, image_id, availability_zone]
	}
}

output "host_{{ $rsc.Name }}" {
	value = "${openstack_compute_instance_v2.{{ $rsc.Name }}}"
	sensitive = true
}

{{ end }}
