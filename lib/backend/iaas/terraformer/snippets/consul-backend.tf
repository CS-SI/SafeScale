backend "consul" {
	address		 = "{{ .Terraformer.Config.Consul.Backend.Server }}"
	scheme		 = "https"	#FIXME: do we need to parameterize this?
	path		 = "{{ .Terraformer.Config.Consul.Backend.Prefix }}"
	gzip		 = false	#FIXME:  We'll see if this setting should change to true
	# 'access_token' voluntarily not placed here to avoir security risk, will use env var to provide token
}
