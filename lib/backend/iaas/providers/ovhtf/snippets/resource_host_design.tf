{{- if not .Extra.MarkedForDestruction }}
{{-   $extra := .Extra }}
{{-   $rsc := .Resource }}
{{-   $provider := .Provider }}
{{-   $template := "" }}
{{-   $image := "" }}
{{-   $disksize := 0 }}
{{-   $publicip := false }}
{{-   $az := "nova" }}
{{-   $region := "" }}
{{-   if hasField $provider "Authentication" }}
{{-     $region = $provider.Authentication.Region }}
{{-   end }}
{{-   if hasField $extra "Request" }}
{{-     $template = $extra.Request.TemplateRef }}
{{-     $publicip = default $extra.Request.PublicIP false }}
{{-   end  }}
{{-   if hasField $rsc "Sizing" }}
{{-     $image = $rsc.Sizing.ImageID }}
{{-     $disksize = $rsc.Sizing.DiskSize }}
{{-   end }}
{{-   if hasField $rsc "Networking" }}
{{-     $publicip = or $publicip $rsc.Networking.IsGateway }}
{{-   end }}
{{-   if hasField $extra "AvailabilityZone" }}
{{-     $az = $extra.AvailabilityZone }}
{{-   end }}
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

	lifecycle {
{{-       if not $extra.MarkedForCreation }}
		prevent_destroy = true
{{-       end }}
	}
}
{{-     end }}
{{-   end }}

resource "openstack_compute_instance_v2" "{{ $rsc.Name }}" {
	provider          = openstack.ovh
	name              = "{{ $rsc.Name }}"
{{-   if $template }}
	flavor_name       = "{{ $template }}"
{{-   end }}
{{-   if $image }}
	image_id          = "{{ $image }}"
{{-   end }}

{{-   if gt (len $extra.SecurityGroupByID) 0 }}
{{-      $sep := "" }}
	security_groups   = [ {{- range $k, $v := $extra.SecurityGroupByID }}{{ $sep }}"{{ $v }}"{{ $sep = ", " }}{{- end }} ]
{{-   else }}
	security_groups   = [ "default" ]
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

{{-   if gt $disksize 0 }}
	block_device {
		uuid                  = "{{ $image }}"
		source_type           = "image"
		destination_type      = "local"
		volume_size           = {{ $disksize }}
		boot_index            = 0
		delete_on_termination = true
	}
{{-   end }}

{{- if $extra.MarkedForCreation }}
	user_data = "${file("{{ $rsc.Name }}_userdata")}"
{{- end }}

	metadata = {
{{-   range $t, $v := $rsc.Tags }}
		{{ $t }} = "{{ $v }}"
{{-   end }}
	}

	lifecycle {
		ignore_changes = [block_device, user_data]
	}
}

output "host_{{ $rsc.Name }}" {
	value = "${openstack_compute_instance_v2.{{ $rsc.Name }}}"
	sensitive = true
}

{{ end }}
