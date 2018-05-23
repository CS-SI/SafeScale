#!/usr/bin/env bash
#
# Deploys a DCOS bootstrap/upgrade server with minimum requirements
#
# This script has to be executed on the bootstrap/upgrade server

{{.IncludeInstallCommons}}

# Install DCOS environment
mkdir -p /usr/local/dcos/genconf
cd /usr/local/dcos

cat >genconf/config.yaml <<- EOF
---
bootstrap_url: http://{{.BootstrapIP}}:{{.BootstrapPort}}
cluster_name: {{.ClusterName}}
exhibitor_storage_backend: static
master_discovery: static
ip_detect_public_filename: genconf/ip-detect
master_list:
{{range .MasterIPs}}- {{.}}{{end}}
{{if .DNSServerIPs}}
resolvers:
{{range .DNSServerIPs}}- {{.}}{{end}}
{{end}}
use_proxy: 'false'
#use_proxy: 'true'
#http_proxy: http://{{.HTTPProxyHost}}:{{.HTTPProxyPort}}
#https_proxy: https://{{.HTTPSProxyHost}}:{{.HTTPSProxyPortr}}
#no_proxy:
#- 'foo.bar.com'
#- '.baz.com'
EOF

cat >genconf/ip-detect <<- EOF
#!/usr/bin/env bash
curl ipinfo.io/ip
EOF
chmod a+rx genconf/ip-detect

# Download if needed the file dcos_generate_config.sh and executes it
[ ! -f dcos_generate_config.sh ] && wget -q https://downloads.dcos.io/dcos/stable/{{.DCOSVersion}}/dcos_generate_config.sh
if [ -f dcos_generate_config.sh ]; then
    bash dcos_generate_config.sh && docker run -d -p 80:80 -v $PWD/genconf/serve:/usr/share/nginx/html:ro nginx >/dev/null && exit 0
fi

# Reaching this point, something wrong happened
exit 1
