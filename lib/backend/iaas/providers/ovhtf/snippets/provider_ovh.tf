provider "openstack" {
	auth_url    = "{{ .Provider.Authentication.IdentityEndpoint }}"
	domain_name = "default"
	tenant_id   = "{{ .Provider.Authentication.TenantID }}"
	tenant_name = "{{ .Provider.Authentication.TenantName }}"
	user_name   = "{{ .Provider.Authentication.Username }}"
	password    = "{{ .Provider.Authentication.Password }}"
	region      = "{{ .Provider.Authentication.Region }}"
	alias       = "ovh"
}

provider "ovh" {
	alias    = "ovh"
	endpoint = "ovh-eu"
}
