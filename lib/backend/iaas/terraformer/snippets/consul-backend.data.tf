data "terraform_remote_state" "consul-state" {
	backend = "consul"
	config = {
		path = "{{ .Terraformer.Config.Consul.Backend.Prefix }}"
	}
}
