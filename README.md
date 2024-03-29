# SafeScale: Infrastructure and Platform as Code tool

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/CS-SI/SafeScale/blob/master/LICENSE)
[![Version](https://img.shields.io/github/release/CS-SI/SafeScale.svg)](https://github.com/CS-SI/SafeScale/releases/latest)
![Downloads](https://img.shields.io/github/downloads/CS-SI/SafeScale/total)

![Contributors](https://img.shields.io/github/contributors/CS-SI/SafeScale)
![Forks](https://img.shields.io/github/forks/CS-SI/SafeScale?style=flat)
![Stars](https://img.shields.io/github/stars/CS-SI/SafeScale)

[![Go Report Card](https://goreportcard.com/badge/github.com/CS-SI/SafeScale/v22)](https://goreportcard.com/report/github.com/CS-SI/SafeScale/v22)
![Go Versions](https://img.shields.io/badge/go-1.18%2C1.19-brightgreen)
![CodeSizeInBytes](https://img.shields.io/github/languages/code-size/CS-SI/SafeScale)

[![Packages Documentation](https://img.shields.io/badge/go-documentation-blue.svg?label=packages)](https://pkg.go.dev/github.com/CS-SI/SafeScale/v22/lib)

SafeScale is an Infrastructure and Platform as Code tool.

## Table of content
  - [Description](#description)
    - [SafeScale Infra](#safescale-infra)
    - [SafeScale Platform](#safescale-platform)
  - [Available features](#available-features)
  - [Contributing](#contributing)
  - [License](#license)

## Description
SafeScale offers an APIs and a CLI tools to deploy versatile computing clusters that span multiple Clouds. These APIs and CLIs are divided in 2 service layers:

- SafeScale Infra to manage Cloud infrastructure (IaaS - Infrastructure as a Service)
- SafeScale Platform to manage Cloud computing platforms (PaaS - Platform as a Service)

### SafeScale Infra

SafeScale Infra offers an API to completely abstract the IaaS services offered by Cloud platforms providers.
It allows to:

- Create / Destroy private networks, Create routers, Manage firewall
- Create / Destroy hosts,
- Create / Destroy block and object storage,
- Mount / Unmount object storage as file system,
- Create / Destroy shares, Connect / Disconnect host to/from shares,
- Create / Destroy clusters
- Add / Remove "features" (software components) on hosts and clusters

SafeScale Infra provides a complete abstraction overlay over underlying IaaS APIs to mask their heterogeneity.

### SafeScale Platform

Safescale Platform provides PaaS (Platform as a Service) capabilities:
- deploy a standard cluster
- deploy a specific cluster, deployment commands are executed in parallel to improve the speed

Platform can deploy a standard cluster with minimal features:
- cluster management environment: BOH (Bunch Of Hosts, ie cluster without workload orchestrator like Kubernetes), K8S (with Kubernetes)
- one or two gateways, including :
  - a reverse proxy (Kong) with only SSH and HTTPS access allowed by default
  - an internal load balancer over the cluster
- the remote desktop

For example the following command creates a Kubernetes cluster named `k8s-cluster`using `Normal`complexity (3 masters and 3 nodes):

```
$ safescale cluster create --flavor k8s --complexity Normal k8s-cluster
```

Supplemental software and/or configurations can be installed in 3 ways on SafeScale Hosts or Clusters:
- using ssh command (the old and manual way):
  ```
  $ safescale ssh run -c "apt install nginx" my-host
  ```
- using "SafeScale `Feature`", that can be seen as the "ansible" for SafeScale:

  ```
  $ safescale cluster feature add mycluster ntpclient
  ```
- and using ansible, which is the PREFERRED method to install your software in a SafeScale cluster:
  installing a simple script:
  ```
  $ safescale cluster ansible playbook my-cluster my-ansible-script.yml
  ```

  where my-ansible-script.yml is something like:
```yml
---
- hosts: nodes
  tasks:
    - name: Install golang
      become: yes
      apt:
        pkg:
          - golang
          - bison

```

  or a more complex one (put all your files in a .zip)
  ```
  $ safescale cluster ansible playbook my-cluster my-zipped-scripts.zip
  ```

A "SafeScale `Feature`" is a file in YAML format that describes the operations to check/add/remove software and/or configuration on a target (Host or Cluster).

A `Feature` can describe operations using bash snippets.

Additionally, a `Feature` is able to apply:
- reverse proxy rules

## Available features
SafeScale is currently under active development and does not yet offer all the abilities planned. However, we are already publishing it with the following ones:

  - SafeScale Infra:
    - Create / Destroy private networks
    - Create / Destroy hosts,
    - Create / Destroy block and object storage,
    - Mount object storage on file system,
    - Create Shares, Connect/disconnect host to share,
    - Create / Update/Destroy Security Groups,
      
  - SafeScale Platform:
    - Create / Destroy clusters composed of a network, servers and services
      currently supported:
        - BOH = Bunch Of Hosts (without any cluster management layer)
        - Kubernetes
    - Add / Remove "features" on host and clusters


 - Supported Cloud providers:
    - OVH Public Cloud
    - FlexibleEngine
    - CloudFerro
    - Generic OpenStack
    - AWS
    - GCP (Google Cloud Platform)
    - Outscale
    - Azure (Work In Progress)


## Contributing

We are looking for new contributors.

If you wish to contribute you can [fork the project](https://help.github.com/forking/), make your changes, commit to your repository, and then [create a pull request](https://help.github.com/articles/creating-a-pull-request-from-a-fork/). The development team can then review your contribution and commit it upstream as appropriate.

As much as possible, try following these guides:
- [godoc documentation tool formalism](https://blog.golang.org/godoc-documenting-go-code).
- [Go style guide](https://github.com/golang/go/wiki/CodeReviewComments)
- [Effective Go](https://golang.org/doc/effective_go)

For bugs and feature requests, [please create an issue](https://github.com/CS-SI/SafeScale/issues/new/choose).

## Build
  [See Build file](doc/build/BUILDING.md)

## Usage
  [See Usage file](doc/USAGE.md)

## License

SafeScale is distributed by [CS Systemes d'Information](http://csgroup.eu) under the [Apache License, Version 2.0](LICENSE). Please see the [third-party notices](NOTICE) file for additional copyright notices and license terms applicable to portions of the software.
