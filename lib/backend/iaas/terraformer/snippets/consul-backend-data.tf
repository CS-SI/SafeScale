data "terraform_remote_state" "consul-state" {
	backend = "consul"
	config = {
		address = "{{ .Consul.Server }}"
		path = "{{ .Consul.Prefix }}"
	}
}
