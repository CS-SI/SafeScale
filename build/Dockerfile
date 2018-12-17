#FROM golang:1.10
FROM ubuntu:artful
LABEL maintainer="CS SI"
ARG http_proxy=
ARG https_proxy=
ARG LC_ALL=C.UTF-8
ARG LANG=C.UTF-8
ENV DEBIAN_FRONTEND noninteractive

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
unzip \
vim \
git \
python3.6 \
python3-pip \
&& apt-get autoclean -y \
&& apt-get autoremove -y \
&& rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

# ----------------------
# Install GO 1.10
# ----------------------
RUN wget https://dl.google.com/go/go1.10.3.linux-amd64.tar.gz \
&& tar -C /usr/local -xzf go1.10.3.linux-amd64.tar.gz 
ENV PATH $PATH:/usr/local/go/bin:/go/bin
RUN rm /tmp/go1.10.3.linux-amd64.tar.gz

# ----------------------
# Install Protoc
# ----------------------
RUN wget https://github.com/google/protobuf/releases/download/v3.6.0/protoc-3.6.0-linux-x86_64.zip \
&& unzip -d /usr/local/protoc protoc-3.6.0-linux-x86_64.zip \
&& ln -s /usr/local/protoc/bin/protoc /usr/local/bin
RUN rm /tmp/protoc-3.6.0-linux-x86_64.zip

ENV SHELL /bin/bash
ENV GOPATH /go
COPY build-safescale.sh /opt/build-safescale.sh

ENTRYPOINT ["/opt/build-safescale.sh"]
