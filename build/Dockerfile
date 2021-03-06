FROM ubuntu:bionic
LABEL maintainer="CS SI"
ARG http_proxy=""
ARG https_proxy=""
ARG LC_ALL=C.UTF-8
ARG LANG=C.UTF-8
ENV DEBIAN_FRONTEND noninteractive
ENV BUILD_ENV docker
ARG BRANCH_NAME
ARG GOVERSION=1.16.2
ARG PROTOVERSION=3.6.1

# -----------------
# Standard packages
# -----------------
RUN apt-get update -y \
&& apt-get install -y --allow-unauthenticated \
locales \
sudo \
locate \
build-essential \
make \
wget \
curl \
unzip \
vim \
git \
jq \
iproute2 \
iputils-ping \
openssh-server \
python3.6 \
python3-pip \
&& apt-get autoclean -y \
&& apt-get autoremove -y \
&& rm -rf /var/lib/apt/lists/*

RUN apt-get install -y locales
# Set the locale
RUN sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && locale-gen
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8
RUN python3 -c "print('testing UTF8: 👌')"

WORKDIR /tmp

# ----------------------
# Install GO
# ----------------------
RUN wget https://dl.google.com/go/go$GOVERSION.linux-amd64.tar.gz \
&& tar -C /usr/local -xzf go$GOVERSION.linux-amd64.tar.gz
ENV PATH $PATH:/usr/local/go/bin:/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RUN rm /tmp/go$GOVERSION.linux-amd64.tar.gz

# ----------------------
# Install Protoc (Version 3.6.1 by default)
# ----------------------
RUN wget https://github.com/google/protobuf/releases/download/v$PROTOVERSION/protoc-$PROTOVERSION-linux-x86_64.zip \
&& unzip -d /usr/local/protoc protoc-$PROTOVERSION-linux-x86_64.zip \
&& ln -s /usr/local/protoc/bin/protoc /usr/local/bin
RUN rm /tmp/protoc-$PROTOVERSION-linux-x86_64.zip

ENV SHELL /bin/bash
ENV GOPATH /go
COPY build-safescale.sh /opt/build-safescale.sh

CMD sleep 5

COPY marker /dev/null

RUN cd /opt && ./build-safescale.sh
