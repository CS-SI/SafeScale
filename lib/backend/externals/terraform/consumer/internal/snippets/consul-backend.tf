	backend "consul" {
		address		 = "{{ .Consul.Server }}"
		scheme		 = "http"	#FIXME: do we need to parameterize this?
		path		 = "{{ .Consul.Prefix }}"
		lock         = true
		gzip		 = false	#FIXME:  We'll see if this setting should change to true
		# 'access_token' voluntarily not placed here to avoid security risk, will use env var to provide token
	}
