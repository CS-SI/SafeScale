provider "openstack" {
    auth_url    = "{{ .Provider.Authentication.IdentityEndpoint }}"	# "${var.tenant.objectstorage.AuthURL}"
    domain_name = "default"
    tenant_id   = "{{ .Provider.Authentication.TenantID }}" 		# "${var.tenant.identity.ApplicationKey}"
    tenant_name = "{{ .Provider.Authentication.TenantName }}"		# "SAFESCALE-TEST"
    user_name   = "{{ .Provider.Authentication.Username }}" 		# "${var.tenant.identity.OpenstackID}"
    password    = "{{ .Provider.Authentication.Password }}"			# "${var.tenant.identity.OpenstackPassword}"
    alias       = "ovh"												# Un alias
    region      = "{{ .Provider.Authentication.Region }}"			# "${var.tenant.compute.Region}"
}

provider "ovh" {
    alias    = "openstack"
    endpoint = "ovh-eu"
}
