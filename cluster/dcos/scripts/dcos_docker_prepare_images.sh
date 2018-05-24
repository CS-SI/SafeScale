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

# start up supervisord, all daemons should launched by supervisord.
exec /usr/bin/supervisord -c /opt/safescale/supervisord.conf
EOF

cat >/tmp/proxy.image/supervisord.conf <<-EOF
[supervisord]
nodaemon=true

[unix_http_server]
file=/var/run/supervisor.sock
chmod=0700

[rpcinterface:supervisor]
supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface

[supervisorctl]
serverurl=unix:////var/run/supervisor.sock
username=admin

[program:guacd]
priority=200
directory=/
command=/usr/sbin/guacd -f
user=root
autostart=true
autorestart=true
stopsignal=QUIT

[program:tomcat]
priority=201
directory=/
command=/usr/local/tomcat/bin/catalina.sh run
user=root
autostart=true
autorestart=true
stopsignal=QUIT
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
