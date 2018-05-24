# Prepares docker images needed to the deployment
#
# This script has to be executed on the bootstrap/upgrade server

mkdir /usr/local/dcos/genconf/serve/docker

######################################
# Prepares guacamole docker instance #
######################################

GUACAMOLE_VERSION=0.9.14
GUACAMOLE_URL=http://apache.org/dyn/closer.cgi?action=download&filename=guacamole/${GUACAMOLE_VERSION}
mkdir /tmp/guacamole.image

cat >/tmp/guacamole.image/startup.sh <<-EOF
#!/bin/bash

# start up supervisord, all daemons should launched by supervisord.
exec /usr/bin/supervisord -c /opt/supervisord.conf
EOF

cat >/tmp/guacamole.image/logback.xml <<-EOF
<configuration>
    <!-- Appender for debugging -->
    <appender name="GUAC-DEBUG" class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
            <pattern>%d{HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n</pattern>
        </encoder>
    </appender>
    <!-- Appender for debugging in a file-->
    <appender name="GUAC-DEBUG_FILE" class="ch.qos.logback.core.FileAppender">
        <file>/var/log/guacd.log</file>
        <encoder>
            <pattern>%d{HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n</pattern>
        </encoder>
    </appender>
    <!-- Log at DEBUG level -->
    <root level="debug">
        <appender-ref ref="GUAC-DEBUG"/>
        <appender-ref ref="GUAC-DEBUG_FILE"/>
    </root>
</configuration>
EOF

cat >/tmp/guacamole.image/user-mapping.xml <<-EOF
<user-mapping>
    <authorize username="cladm" password="{{ .Password }}">

        <!-- First authorized connection -->
        <connection name="front_vnc">
            <protocol>vnc</protocol>
            <param name="hostname">{{ .Hostname }}</param>
            <param name="port">5900</param>
            <param name="enable-sftp">true</param>
            <param name="sftp-username">cladm</param>
            <param name="sftp-password">{{ .Password }}</param>
            <param name="sftp-directory">/home/cladm/Desktop</param>
            <param name="sftp-root-directory">/home/cladm</param>
            <param name="sftp-server-alive-interval">60</param>
            <param name="color-depth">16</param>
            <!--<param name="encodings">zrle ultra copyrect hextile zlib corre rre raw</param>-->
        </connection>
    </authorize>
</user-mapping>
EOF

cat >/tmp/guacamole.image/Dockerfile <<-EOF
FROM debian:sid-slim AS Builder
LABEL maintainer "CS SI"

ENV DEBIAN_FRONTEND noninteractive

# ----------------
# Needed packages
# ----------------
RUN apt-get update -y \
 && apt-get upgrade -y \
 && apt-get install -y \
        build-essential \
        gcc-6 \
        libcairo2-dev \
        libjpeg62-turbo \
        libossp-uuid-dev \
        libpng-dev \
        libvncserver-dev \
        libssh2-1-dev \
        libssl-dev \
        libwebp-dev \
        wget

# Guacamole
WORKDIR /usr/local/src
ADD ${GUACAMOLE_URL}/source/guacamole-server-${GUACAMOLE_VERSION}.tar.gz ./
RUN tar -zxvf guacamole-server-${GUACAMOLE_VERSION}.tar.gz -C . >/dev/null

RUN cd guacamole-server-${GUACAMOLE_VERSION} \
 && CC=gcc-6 ./configure --prefix=/usr --with-init-dir=/etc/init.d  \
 && make \
 && make DESTDIR=/usr/local/dist install

#------------------------- DIST phase -------------------------

FROM tomcat:8.5-jre8-slim
LABEL maintainer "CS SI"

ENV DEBIAN_FRONTEND noninteractive

# -----------------
# Needed packages
# -----------------
RUN apt update -y \
 && apt upgrade -y \
 && apt install -y \
        libcairo2 \
        libjpeg62-turbo \
        libossp-uuid16 \
        libpng16-16 \
        libvncclient1 \
        libssh2-1 \
        libssl1.1 \
        libwebp6 \
        procps \
        net-tools \
        supervisor

COPY --from=Builder /usr/local/dist /

# -----------------
# Install Guacamole
# -----------------
# Tomcat
WORKDIR /usr/local/tomcat
RUN rm -rf ./webapps/{examples,doc,ROOT}
ADD ${GUACAMOLE_URL}/binary/guacamole-${GUACAMOLE_VERSION}.war ./webapps/guacamole.war
ADD tomcat-users.xml ./conf/

WORKDIR /root
RUN mkdir .guacamole
ADD user-mapping.xml .guacamole/
ADD logback.xml .guacamole/
ENV GUACAMOLE_HOME /root/.guacamole

mkdir /opt/safescale
WORKDIR /opt/safescale
ADD startup.sh ./
RUN chmod u+x startup.sh
ADD supervisord.conf ./

RUN apt autoremove -y \
 && apt autoclean -y \
 && rm -rf /var/lib/apt/*

# Tomcat Guacamole
EXPOSE 8080

# Tomcat
EXPOSE 8009

ENTRYPOINT ["/opt/safescale/startup.sh"]
EOF
docker build -t guacamole:latest /tmp/guacamole.image

docker save guacamole:latest | pigz /usr/local/dcos/genconf/serve/docker/guacamole.tar.gz
#rm -rf /tmp/guacamole.image

########################################
# Prepares reverse proxy for guacamole #
########################################

mkdir /tmp/proxy.image

cat >/tmp/proxy.image/startup.sh <<-EOF
#!/bin/bash

function update_file {
    # Take two files in arguments : first must be docker default conf file, second must be the file used
    # If file $1 is newer than file $2
    if [ -f $2 ] && [ $1 -nt $2 ]
    then
        CHECKSUM_DOCKER_FILE=`md5sum $1 | tr -s ' ' | cut -d ' ' -f1`
        CHECKSUM_CONF_FILE=`md5sum $2 | tr -s ' ' | cut -d ' ' -f1`
        if [ "${CHECKSUM_DOCKER_FILE}" != "${CHECKSUM_CONF_FILE}" ]
        then
            # File has been updated => we save the old conf file and replace it by docker
            DATE=`date +%Y-%m-%d-%H-%M-%S`
            mv $2 $2-${DATE}.confsave
            cp $1 $2
        fi
    else
        if [ ! -f $2 ]
        then
            # File doesn't exist => we create it from default conf file
            cp $1 $2
        fi
    fi
}

function update_conf {
    # Take two folders in arguments : first must be docker default conf folder, second must be used folder containing same conf files
    for file in `ls $1`
    do
        if [ -f $1/${file} ]
        then
            update_file $1/${file} $2/${file}
        fi
    done
}

# Path to default conf stored inside docker during build
DATA_DOCKER_CONF=/data/docker-conf
# Update conf file (only if conf file stored during build is more recent than current used file)
update_conf ${DATA_DOCKER_CONF}/apache2-conf/ /apache2-conf/
update_conf ${DATA_DOCKER_CONF}/Key/ /certificate/
update_conf ${DATA_DOCKER_CONF}/logrotate.d/ /etc/logrotate.d/
update_conf ${DATA_DOCKER_CONF}/sites-available/ /etc/apache2/sites-available/

# If needed we change conf using requested domain name
if [ ! -z ${DOMAIN_NAME+x} ] && [ "${DOMAIN_NAME}" != "" ]
then
    echo "Starting proxy on domain : ${DOMAIN_NAME}"
    # Create all needed files
    if [ "${DOMAIN_NAME}" != "${DEFAULT_DOMAIN_NAME}" ]
    then
        #Rename apache conf files
        update_file ${DATA_DOCKER_CONF}/sites-available/${DEFAULT_DOMAIN_NAME}.conf /etc/apache2/sites-available/${DOMAIN_NAME}.conf

    fi
else
    echo "Starting proxy on default domain : ${DEFAULT_DOMAIN_NAME}"
    DOMAIN_NAME=${DEFAULT_DOMAIN_NAME}
fi

# Replace template tags by domain name
sed -i -e "s#%%DOMAIN_NAME%%#${DOMAIN_NAME}#g" /etc/apache2/sites-available/000-default.conf
sed -i -e "s#%%DOMAIN_NAME%%#${DOMAIN_NAME}#g" /etc/apache2/sites-available/${DOMAIN_NAME}.conf

a2dissite ${DEFAULT_DOMAIN_NAME}.conf
a2ensite ${DOMAIN_NAME}.conf

# Make sure Apache will start no matter what.
rm -f /var/run/apache2/apache2.pid &>/dev/null

# start up supervisord, all daemons should launched by supervisord.
exec /usr/bin/supervisord -c /opt/supervisord.conf
EOF

cat >/tmp/proxy.image/supervisord.conf <<-EOF
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
directory=/
command=/usr/sbin/apache2ctl -D FOREGROUND
user=www-data
autostart=true
autorestart=true
stopsignal=QUIT
EOF

cat >/tmp/guacamole.image/Dockerfile <<-EOF
FROM debian:sid-slim AS Builder
LABEL maintainer "CS SI"

ENV DEBIAN_FRONTEND noninteractive

# Install Apache2 and Shibboleth
RUN apt-get update -y \
 && apt-get install -y apache2 python3-software-properties software-properties-common libapache2-modsecurity libapache2-mod-evasive logrotate
RUN add-apt-repository -y ppa:certbot/certbot \
 && apt-get update \
 && apt-get install -y python-certbot-apache
RUN a2enmod proxy \
 && a2enmod proxy_http \
 && a2enmod proxy_wstunnel \
 && a2enmod ssl \
 && a2enmod headers \
 && a2enmod rewrite

# Volume Creation
# Apache Conf
VOLUME /apache2-conf
# Certificate
VOLUME /certificate

# Create link to apache2 conf file
WORKDIR /etc/modsecurity/
# Remove conf file (they will be linked to the dockerfile volume)
RUN ln -s /apache2-conf/modsecurity.conf
WORKDIR /etc/apache2/mods-available
RUN rm -rf evasive.conf
RUN ln -s /apache2-conf/evasive.conf

# Add startup script
RUN mkdir /opt/safescale
WORKDIR /opt/safescale
ADD startup.sh .
ADD generateCertAndKeys.sh .
RUN chmod 755 /opt/safescale/*.sh

# Store default conf files in /data/docker-conf/
# This conf will update used conf file if more recent (see Scripts/startup.sh)
RUN mkdir -p /data/docker-conf/apache2-conf/
ADD ./apache2-conf/ /data/docker-conf/apache2-conf/
RUN mkdir -p /data/docker-conf/Key/
ADD ./Key/ /data/docker-conf/Key/
RUN mkdir -p /data/docker-conf/logrotate.d/
ADD ./logrotate.d/ /data/docker-conf/logrotate.d/
RUN mkdir -p /data/docker-conf/sites-available/
ADD ./sites-available/ /data/docker-conf/sites-available/

# Change group so that logrotate can run without the syslog group
RUN sed -i 's/su root syslog/su root adm/' /etc/logrotate.conf

EXPOSE 80
EXPOSE 443

ENTRYPOINT ["/opt/safescale/startup.sh"]
EOF
docker build -t proxy:latest /tmp/proxy.image

docker save proxy:latest | pigz /usr/local/dcos/genconf/serve/docker/proxy.tar.gz || exit 1
#rm -rf /tmp/proxy.image

############################################################
# docker-compose file to starts guacamole+proxy containers #
############################################################

cat >/usr/local/dcos/genconf/serve/docker/docker-compose.yml <<-EOF
version: '3'

services:
    guacamole:
        container_name: guacamole
        hostname: guacamole
        image: guacamole:latest
        networks:
            default:

    proxy:
        container_name: proxy
        hostname: proxy
        image: proxy:latest
        ports:
            - 443:443
        networks:
            default:

networks:
    default:
        driver: bridge

EOF

################
# Some cleanup #
################

docker image prune -f
