#!/usr/bin/env bash
# Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

########################################
# Prepares reverse proxy for guacamole #
########################################

mkdir /var/tmp/proxy.image
cd /var/tmp/proxy.image

cat >startup.sh <<-'EOF'
#!/bin/bash

# start up supervisord, all daemons should launched by supervisord.
exec /usr/bin/supervisord -c /opt/safescale/supervisord.conf
EOF

cat >start_apache2.sh <<-'EOF'
#!/usr/bin/env bash

. /etc/apache2/envvars

# Creates self-signed certificate if it doesn't exist yet
if [ ! -f /etc/ssl/private/ssl-cert-safescale-selfsigned.key ]; then
    HOSTNAME=$(hostname -s)
    openssl req  -x509 -newkey rsa:4096 -sha256 -nodes -days 3650 \
                -subj "/C=FR/ST=Haute-Garonne/L=Toulouse/O=CS-SI/CN=$HOSTNAME/" \
                -keyout /etc/ssl/private/ssl-cert-safescale-selfsigned.key \
                -out /etc/ssl/certs/ssl-cert-safescale-selfsigned.crt
    chmod ug+r,o-r /etc/ssl/private/ssl-cert-safescale-selfsigned.key /etc/ssl/certs/ssl-cert-safescale-selfsigned.crt
    chgrp www-data /etc/ssl/private/ssl-cert-safescale-selfsigned.key /etc/ssl/certs/ssl-cert-safescale-selfsigned.crt
fi

# Creates apache site configuration from template
sed -e "s/##HOSTNAME##/$HOSTNAME/g" /etc/apache2/sites-available/default.conf.tmpl >/etc/apache2/sites-available/000-default.conf
a2ensite 000-default.conf

# Make sure Apache will start no matter what.
rm -f /var/run/apache2/apache2.pid &>/dev/null

exec /usr/sbin/apache2ctl -D FOREGROUND
EOF

cat >supervisord.conf <<-'EOF'
[supervisord]
nodaemon=true
logfile=/var/log/supervisord.log
# With log level debug, the supervisord log file will record the stderr/stdout
# output of its child processes and extended info info about process state
# changes
loglevel=debug
# Prevent supervisord from clearing any existing AUTO child log files at
# startup time. Useful for debugging.
nocleanup=true

[unix_http_server]
file=/var/run/supervisor.sock
chmod=0700

[rpcinterface:supervisor]
supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface

[supervisorctl]
serverurl=unix:////var/run/supervisor.sock
username=admin

[program:crond]
priority=10
directory=/
command=/usr/sbin/cron -f
user=root
autostart=true
autorestart=true
stopsignal=QUIT

[program:rsyslog]
priority=11
directory=/
command=/etc/init.d/rsyslog start
user=root
autostart=true
autorestart=true
stopsignal=QUIT

[program:apache2]
priority=20
command=/opt/safescale/start_apache2.sh
user=root
autostart=true
autorestart=true
stopsignal=QUIT
EOF

cat >www-default.conf.tmpl <<-'EOF'
ServerSignature Off
ServerTokens Prod

ServerSignature Off
ServerTokens Prod

<VirtualHost *:443>
{{- if ne .DNSDomain "" }}
    ServerName {{ .ClusterName }}-proxy.{{ .DNSDomain }}
    ServerAlias {{ .ClusterName }}-proxy
{{- else }}
    ServerName {{ .ClusterName }}-proxy
{{- end }}

    #ServerAdmin admin@rus-copernicus.eu
    #
    # LogLevel: Control the number of messages logged to the error_log.
    # Possible values include: debug, info, notice, warn, error, crit,
    # alert, emerg.
    #
    LogLevel warn

    <IfModule log_config_module>
        #
        # The following directives define some format nicknames for use with
        # a CustomLog directive (see below).
        #
        LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
        LogFormat "%h %l %u %t \"%r\" %>s %b" common

        <IfModule logio_module>
          # You need to enable mod_logio.c to use %I and %O
          LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %I %O" combinedio
        </IfModule>

        #
        # The location and format of the access logfile (Common Logfile Format).
        # If you do not define any access logfiles within a <VirtualHost>
        # container, they will be logged here.  Contrariwise, if you *do*
        # define per-<VirtualHost> access logfiles, transactions will be
        # logged therein and *not* in this file.
        #
        ErrorLog ${APACHE_LOG_DIR}/ssl-error.log
        CustomLog ${APACHE_LOG_DIR}/ssl-access.log combined

        #
        # If you prefer a logfile with access, agent, and referer information
        # (Combined Logfile Format) you can use the following directive.
        #
        #CustomLog "logs/access_log" combined
    </IfModule>

    # SSL Config
    SSLEngine on
    # Improved security (disable SSL due to vulerabilities)
    # http://www.it-connect.fr/configurer-le-ssl-avec-apache-2%EF%BB%BF/
    SSLProtocol -ALL +TLSv1 +TLSv1.1 +TLSv1.2
    SSLHonorCipherOrder On
    SSLCipherSuite ECDHE-RSA-AES128-SHA256:AES128-GCM-SHA256:HIGH:!MD5:!aNULL:!EDH:!RC4
    SSLCertificateKeyFile /etc/ssl/private/ssl-cert-safescale-selfsigned.key
    SSLCertificateFile /etc/ssl/certs/ssl-cert-safescale-selfsigned.crt
    # MSIE 7 and newer should be able to use keepalive
    BrowserMatch "MSIE [2-6]" nokeepalive ssl-unclean-shutdown \
        downgrade-1.0 force-response-1.0
    BrowserMatch "MSIE [17-9]" ssl-unclean-shutdown

    # General proxy config
    ProxyRequests Off
    SSLProxyEngine On

{{- $len := len .MasterIPs -}}
{{- if gt $len 0 }}
    <Proxy "balancer://http-masters">
  {{- range $idx, $ip := .MasterIPs }}
        BalancerMember "http://{{ $ip }}:9080/guacamole" route={{ inc $idx }}
  {{- end }}
    </Proxy>
    <Proxy "balancer://ws-masters">
  {{- range $idx, $ip := .MasterIPs }}
        BalancerMember "ws://{{ $ip }}:9080/guacamole/websocket-tunnel" route={{ inc $idx }}
  {{- end }}
    </Proxy>
    <Location />
        Order allow,deny
        Allow from all
        ProxyPass "balancer://http-masters/ flushpackets=on stickysession=JSESSIONID|jsessionid scolonpathdelim=On
        ProxyPassReverse "balancer://http-masters"
        ProxyPassReverseCookiePath /guacamole/ /
    </Location>
    <Location /websocket-tunnel>
        Order allow,deny
        Allow from all
        ProxyPass "balancer://ws-masters" stickysession=JSESSIONID|jsessionid
        ProxyPassReverse "balancer://ws-masters"
    </Location>

  {{- range $idx, $ip := .MasterIPs }}
    <Location /master-{{ inc $idx }}/>
        Order allow,deny
        Allow from all
        ProxyPass http://{{ $ip }}:9080/guacamole/ flushpackets=on
        ProxyPassReverse http://{{ $ip }}:9080/guacamole/
        ProxyPassReverseCookiePath /guacamole/ /
    </Location>
    <Location /master-{{ inc $idx }}/websocket-tunnel>
        Order allow,deny
        Allow from all
        ProxyPass ws://{{ $ip }}:9080/guacamole/websocket-tunnel
        ProxyPassReverse ws://{{ $ip }}:9080/guacamole/websocket-tunnel
    </Location>
  {{- end }}
{{ end }}

</VirtualHost>
EOF

cat >mod_security.conf <<-'EOF'
# -- Rule engine initialization ----------------------------------------------

# Enable ModSecurity, attaching it to every transaction. Use detection
# only to start with, because that minimises the chances of post-installation
# disruption.
#
SecRuleEngine DetectionOnly


# -- Request body handling ---------------------------------------------------

# Allow ModSecurity to access request bodies. If you don't, ModSecurity
# won't be able to see any POST parameters, which opens a large security
# hole for attackers to exploit.
#
SecRequestBodyAccess On


# Enable XML request body parser.
# Initiate XML Processor in case of xml content-type
#
SecRule REQUEST_HEADERS:Content-Type "text/xml" \
     "id:'200000',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"

# Enable JSON request body parser.
# Initiate JSON Processor in case of JSON content-type; change accordingly
# if your application does not use 'application/json'
#
SecRule REQUEST_HEADERS:Content-Type "application/json" \
     "id:'200001',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"

# Maximum request body size we will accept for buffering. If you support
# file uploads then the value given on the first line has to be as large
# as the largest file you are willing to accept. The second value refers
# to the size of data, with files excluded. You want to keep that value as
# low as practical.
#
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072

# Store up to 128 KB of request body data in memory. When the multipart
# parser reachers this limit, it will start using your hard disk for
# storage. That is slow, but unavoidable.
#
SecRequestBodyInMemoryLimit 131072

# What do do if the request body size is above our configured limit.
# Keep in mind that this setting will automatically be set to ProcessPartial
# when SecRuleEngine is set to DetectionOnly mode in order to minimize
# disruptions when initially deploying ModSecurity.
#
SecRequestBodyLimitAction Reject

# Verify that we've correctly processed the request body.
# As a rule of thumb, when failing to process a request body
# you should reject the request (when deployed in blocking mode)
# or log a high-severity alert (when deployed in detection-only mode).
#
SecRule REQBODY_ERROR "!@eq 0" \
"id:'200002', phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',logdata:'%{reqbody_error_msg}',severity:2"

# By default be strict with what we accept in the multipart/form-data
# request body. If the rule below proves to be too strict for your
# environment consider changing it to detection-only. You are encouraged
# _not_ to remove it altogether.
#
SecRule MULTIPART_STRICT_ERROR "!@eq 0" \
"id:'200003',phase:2,t:none,log,deny,status:400, \
msg:'Multipart request body failed strict validation: \
PE %{REQBODY_PROCESSOR_ERROR}, \
BQ %{MULTIPART_BOUNDARY_QUOTED}, \
BW %{MULTIPART_BOUNDARY_WHITESPACE}, \
DB %{MULTIPART_DATA_BEFORE}, \
DA %{MULTIPART_DATA_AFTER}, \
HF %{MULTIPART_HEADER_FOLDING}, \
LF %{MULTIPART_LF_LINE}, \
SM %{MULTIPART_MISSING_SEMICOLON}, \
IQ %{MULTIPART_INVALID_QUOTING}, \
IP %{MULTIPART_INVALID_PART}, \
IH %{MULTIPART_INVALID_HEADER_FOLDING}, \
FL %{MULTIPART_FILE_LIMIT_EXCEEDED}'"

# Did we see anything that might be a boundary?
#
SecRule MULTIPART_UNMATCHED_BOUNDARY "!@eq 0" \
"id:'200004',phase:2,t:none,log,deny,msg:'Multipart parser detected a possible unmatched boundary.'"

# PCRE Tuning
# We want to avoid a potential RegEx DoS condition
#
SecPcreMatchLimit 1000
SecPcreMatchLimitRecursion 1000

# Some internal errors will set flags in TX and we will need to look for these.
# All of these are prefixed with "MSC_".  The following flags currently exist:
#
# MSC_PCRE_LIMITS_EXCEEDED: PCRE match limits were exceeded.
#
SecRule TX:/^MSC_/ "!@streq 0" \
        "id:'200005',phase:2,t:none,deny,msg:'ModSecurity internal error flagged: %{MATCHED_VAR_NAME}'"


# -- Response body handling --------------------------------------------------

# Allow ModSecurity to access response bodies.
# You should have this directive enabled in order to identify errors
# and data leakage issues.
#
# Do keep in mind that enabling this directive does increases both
# memory consumption and response latency.
#
SecResponseBodyAccess On

# Which response MIME types do you want to inspect? You should adjust the
# configuration below to catch documents but avoid static files
# (e.g., images and archives).
#
SecResponseBodyMimeType text/plain text/html text/xml

# Buffer response bodies of up to 512 KB in length.
SecResponseBodyLimit 524288

# What happens when we encounter a response body larger than the configured
# limit? By default, we process what we have and let the rest through.
# That's somewhat less secure, but does not break any legitimate pages.
#
SecResponseBodyLimitAction ProcessPartial


# -- Filesystem configuration ------------------------------------------------

# The location where ModSecurity stores temporary files (for example, when
# it needs to handle a file upload that is larger than the configured limit).
#
# This default setting is chosen due to all systems have /tmp available however,
# this is less than ideal. It is recommended that you specify a location that's private.
#
SecTmpDir /tmp/

# The location where ModSecurity will keep its persistent data.  This default setting
# is chosen due to all systems have /tmp available however, it
# too should be updated to a place that other users can't access.
#
SecDataDir /tmp/

# -- Audit log configuration -------------------------------------------------

# Log the transactions that are marked by a rule, as well as those that
# trigger a server error (determined by a 5xx or 4xx, excluding 404,
# level response status codes).
#
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"

# Log everything we know about a transaction.
SecAuditLogParts ABIJDEFHZ

# Use a single file for logging. This is much easier to look at, but
# assumes that you will use the audit log only ocassionally.
#
SecAuditLogType Serial
SecAuditLog /var/log/apache2/modsec_audit.log

# Specify the path for concurrent audit logging.
#SecAuditLogStorageDir /opt/modsecurity/var/audit/


# -- Miscellaneous -----------------------------------------------------------

# Use the most commonly used application/x-www-form-urlencoded parameter
# separator. There's probably only one application somewhere that uses
# something else so don't expect to change this value.
#
SecArgumentSeparator &

# Settle on version 0 (zero) cookies, as that is what most applications
# use. Using an incorrect cookie version may open your installation to
# evasion attacks (against the rules that examine named cookies).
#
SecCookieFormat 0

# Specify your Unicode Code Point.
# This mapping is used by the t:urlDecodeUni transformation function
# to properly map encoded data to your language. Properly setting
# these directives helps to reduce false positives and negatives.
#
SecUnicodeMapFile unicode.mapping 20127

# Improve the quality of ModSecurity by sharing information about your
# current ModSecurity version and dependencies versions.
# The following information will be shared: ModSecurity version,
# Web Server version, APR version, PCRE version, Lua version, Libxml2
# version, Anonymous unique id for host.
SecStatusEngine On
EOF

cat >logrotate-apache2.conf <<-'EOF'
/var/log/apache2/*error.log
/var/log/apache2/*access.log {
        daily
        missingok
        rotate 7
        compress
        delaycompress
        notifempty
        create 640 root adm
        sharedscripts
        prerotate
            if [ -d /etc/logrotate.d/httpd-prerotate ]; then \
                run-parts /etc/logrotate.d/httpd-prerotate; \
            fi;
        endscript
}

/var/log/apache2/modsec_audit.log {
        daily
        missingok
        rotate 7
        compress
        delaycompress
        notifempty
        create 640 root adm
        sharedscripts
        postrotate
            if /etc/init.d/apache2 status > /dev/null ; then \
                /etc/init.d/apache2 reload > /dev/null; \
            fi;
        endscript
}
EOF

cat >mod_evasive.conf <<-'EOF'
LoadModule evasive20_module modules/mod_evasive24.so
<IfModule mod_evasive20.c>
    DOSHashTableSize    3097
    DOSPageCount        30
    DOSSiteCount        50
    DOSPageInterval     5
    DOSSiteInterval     1
    DOSBlockingPeriod   10

    #DOSEmailNotify      admin@rus-copernicus.eu
    #DOSSystemCommand    "su - someuser -c '/sbin/... %s ...'"
    DOSLogDir           "/var/log/apache2/"
</IfModule>
EOF

cat >Dockerfile <<-'EOF'
FROM debian:sid-slim AS Builder
LABEL maintainer "CS SI"

ENV DEBIAN_FRONTEND noninteractive

# Install Apache2
RUN apt update -y \
 && apt install -y apache2 libapache2-mod-security2 libapache2-mod-evasive logrotate openssl curl supervisor rsyslog
#RUN add-apt-repository -y ppa:certbot/certbot \
# && apt-get update \
# && apt-get install -y python-certbot-apache
RUN a2enmod proxy \
 && a2enmod proxy_http \
 && a2enmod proxy_wstunnel \
 && a2enmod proxy_balancer \
 && a2enmod proxy_connect \
 && a2enmod ssl \
 && a2enmod headers \
 && a2enmod rewrite

# Apache stuff
ADD mod_security.conf /etc/apache2/conf.d/mod_security.conf
ADD mod_evasive.conf /etc/apache2/conf.d/mod_evasive.conf
ADD www-default.conf.tmpl /etc/apache2/sites-available/default.conf.tmpl
RUN mkdir -p /etc/ssl/private /etc/ssl/certs

# logrotate stuff
ADD logrotate-apache2.conf/ /etc/logrotate.d/apache2.conf
RUN sed -i 's/su root syslog/su root adm/' /etc/logrotate.conf

# Add startup script
RUN mkdir /opt/safescale
WORKDIR /opt/safescale
ADD startup.sh .
ADD start_apache2.sh .
ADD supervisord.conf .
RUN chmod 755 /opt/safescale/*.sh

RUN apt-get autoremove -y \
 && apt-get autoclean -y \
 && rm -rf /var/cache/apt/archives/*

EXPOSE 80
EXPOSE 443

ENTRYPOINT ["/opt/safescale/startup.sh"]
EOF

docker build -t proxy:latest . && \
docker image save proxy:latest | pigz -c9 >/usr/local/dcos/genconf/serve/docker/proxy.tar.gz &&
cd .. && rm -rf proxy.image
