{{ if and .ConsulBackend .ConsulBackend.Use }}
backend "consul" {
	address		 = "{{ .ConsulBackend.Server }}"
	scheme		 = "https"	#FIXME: do we need to parameterize this?
	path		 = "{{ .ConsulBackend.Path }}"
	gzip		 = false	#FIXME:  We'll see if this setting should change to true
	# 'access_token' voluntarily not placed here to avoir security risk, will use env var to provide token
}
{{ end }}
