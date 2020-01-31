# SafeScale: multicloud management platform

SafeScale is an Infrastructure and Platform as a Code tool.

## Table of content
  - [Description](#description)
    - [SafeScale Infra](#safescale-safescale)
    - [SafeScale Platform](#safescale-platform)
    - [SafeScale Security](#safescale-security)
  - [Currently available features](#currently-available-features)
  - [Contributing](#contributing)
  - [License](#license)

## Description
SafeScale offers an API and a CLI tools to deploy versatile computing clusters that span multiple Clouds. These APIs and CLIs are divided in 3 service layers:

- SafeScale Infra to manage Cloud infrastructure
- SafeScale Platform to manage Cloud computing platforms (aka clusters)
- SafeScale Security to secure user environments

![SafeScale](doc/img/SafeScale.png "SafeScale")

### SafeScale Infra

SafeScale Infra offers an API to completely abstract the IaaS services offered by Cloud platforms providers.
It allows to:

- Create / Destroy private networks, Create routers
- Create / Destroy hosts,
- Create / Destroy block and object storage,
- Mount / Unmount object storage as file system,
- Create / Destroy shares, Connect / Disconnect host to/from shares,
- Create / Destroy clusters
- Add / Remove "features" (software components) on hosts and clusters

![SafeScale Infra](doc/img/SafeScale_Infra.png "SafeScale Infra")

SafeScale Infra provides a complete abstraction overlay over underlying IaaS APIs to mask their heterogeneity.

### SafeScale Platform

The concept of SafeScale Platform revolves around the offer of an API to create on-demand computing platforms. These platforms are built to be highly versatile providing all necessary building blocks to create a cutting-edge, production grade, scalable and highly available services: Micro service orchestration, Big Data and HPC computing frameworks, large scale data management, AI training and inference frameworks.

The innovative aspects of the platforms lies in their capacity to offer a combined usage of a large variety of frameworks and technologies without having to manage resources allocation (Node, RAM, CPU, and GPU), and allows the combined usage of various computing and service management frameworks which greatly simplifies the porting of in-house applications to the Cloud.
It is also important to precise that platforms are not static, they can be scaled up and down on-demand or automatically to adapt to load fluctuations and thus to optimize IT costs.

### SafeScale Security

SafeScale Security ensures that no unapproved external access is granted:
- On network level, SafeScale Security relies on Kong, an open source generic proxy, to be put in between user and service. Kong intercepts user requests and service responses and executes plugins to empower any API. In the current state, SafeScale Security proxy relies on 3 Kong plugins:
  - Dynamic SSL plugin to encrypt traffic between the user and the protected service
  - Open ID plugin to connect the Identity and Access Management server, KeyCloak
  - UDP Log plugin to connect the Log management system, Logstash
- On service level, SafeScale Security proposes an optional use of Keycloak, an Open Source Identity and Access Management (IAM), that can provide access control by itself or using third-party directories.

The hosts acting as gateways are secured using firewalld with a default rule being "DENY EVERYTHING" from Internet. Only SSH access are allowed by default, and HTTPS port (443) if Kong is not disabled. At the time being, there is no firewall rule for the hosts inside the subnet of the platform,but firewalld is installed, just in case.

The design of a SafeScale Security gateway can be depicted as below:

![SafeScale Security](doc/img/SafeScale_Security.png "SafeScale Security")

Note: the log part is not yet available...

## Currently available features

SafeScale is currently under active development and does not yet offer all the features planned. However, we are already publishing it with the following features:

- SafeScale Infra:
  - Create / Destroy private networks
  - Create / Destroy hosts,
  - Create / Destroy block and object storage,
  - Mount object storage on file system,
  - Create Shares, Connect/disconnect host to share,
  - Add / Remove "features" on host
  - Support Cloud providers:
    - OVH Public Cloud
    - FlexibleEngine
    - OpenTelekom
    - CloudFerro
    - Generic OpenStack
    - local provider (unstable, not compiled by default)
    - GCP (Google Cloud Platform)
    - AWS: under development

- Safescale Platform:
  - Create / Destroy clusters composed of a network, servers and services
    cluster management layer currently supported:
      - Kubernetes cluster
      - Swarm cluster
      - BOH = Bunch Of Hosts (without any cluster management layer)
  - Install default services (everything being deactivable):
    - remote desktop based on Guacamole (available from Web browser)
    - reverse proxy to control Internet access
    - ntp servers and clients
  - Add / Remove "features" on host and clusters
  - Expand/Shrink the "size" of the cluster (number of workers)

- SafeScale Security:
  - Secured gateways using Kong
  - IAM using Keycloak (optional)
  - Kubernetes Hardening (by default but deactivable)
  - firewalld everywhere (regardless of the chosen Linux distribution)

## Contributing

We are strongly interested by new contributions.

If you wish to contribute you can [fork the project](https://help.github.com/forking/), make your changes, commit to your repository, and then [create a pull request](https://help.github.com/articles/creating-a-pull-request-from-a-fork/). The development team can then review your contribution and commit it upstream as appropriate.

For bugs and feature requests, [please create an issue](../../issues/new).

## Build
  [See Build file](doc/build/BUILDING.md)

## Usage
  [See Usage file](doc/USAGE.md)

## License

SafeScale is distributed by [CS Systemes d'Information](http://www.c-s.fr) under the [Apache License, Version 2.0](LICENSE). Please see the [third-party notices](NOTICE) file for additional copyright notices and license terms applicable to portions of the software.
