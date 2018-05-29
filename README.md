# SafeScale: multicloud management platform

SafeScale is an Infrastructure and Platform as a Code tool.

## Description
SafeScale offers an APIs and a CLI tools to deploy versatile computing clusters that span multiple Clouds. These APIs and CLIs are divided in 3 service layers:

* SafeScale Broker to manage Cloud infrastructure
* SafeScale Perform to manage Cloud computing platforms
* SafeScale Security to secure user environments

![SafeScale](img/SafeScale.png "SafeScale")

### SafeScale Broker

SafeScale Broker offers an API to completely abstract the IaaS services offered by Cloud platforms providers.
It allows to:

* Create / Destroy private networks, Create routers, Manage firewall
* Create/Destroy Virtual Machine (VM),
* Create / Destroy block and object storage,
* Mount object storage on file system,
* Create NAS, Connect/disconnect VM to NAS,
* Access VM Web Desktop.

![SafeScale Broker](img/SafeScale_Broker.png "SafeScale Broker")
SafeScale Broker provides a complete abstraction overlay over underlying IaaS APIs to mask their heterogeneity.

### SafeScale Perform

The concept of SafeScale Perform revolves around the offer of an API to create on-demand computing platforms. These platforms are built to by highly versatile providing all necessary building blocks to create a cutting-edge, production grade, scalable and highly available services: Micro service orchestration, Big Data and HPC computing frameworks, large scale data management, AI training and inference frameworks.
![SafeScale Perform](img/SafeScale_Perform.png "SafeScale Perform")
The innovative aspect of SafeScale Perform platforms lies in their capacity to offer a combined usage of a large variety of frameworks and technologies without having to manage resources allocation (Node, RAM, CPU, and GPU).
SafeScale Perform platforms resource management is centralized by Apache Mesos which guarantees a fair and efficient distribution of resources for all components hosted by the platform. This particularity enables SafeScale users to run concurrently services and compute loads of data without worrying about their partitioning over the nodes of the cluster and thus significantly accelerate the implementation of complex distributed services.
A corollary of the centralized resource management system is that it allows the combined usage of various computing and service management frameworks which greatly simplifies the porting of in-house applications to the Cloud.
It is also important to precise that SafeScale Perform platforms are not static, they can be up-scale and down scaled on-demand or automatically to adapt to load fluctuations and thus to optimize IT costs.

### SafeScale Security

SafeScale Security is a Web API and a Web Portal to create on-demand security gateways to protect Web services along 5 axes: Encryption, Authentication, Authorization, Auditability and Intrusion detection.
SafeScale Security relies on Kong, an open source generic proxy to be put in between user and service. Kong intercepts user requests and service responses and executes plugins to empower any API. To build a SafeScale Security gateway 3 plugins are used: 
* Dynamic SSL plugin to encrypt traffic between the user and the service protected
* Open ID plugin to connect the Identity and Access Management server, KeyCloak
* UDP Log plugin to connect the Log management system, Logstash
The design of a SafeScale Security gateway can be depicted as bellow:
![SafeScale Security](img/SafeScale_Security.png "SafeScale Security")

## Features available 
SafeScale is currently under development and does not yet offer all the features planned. However, we are already releasing it with the following features:
* SafeScale Broker:
  * Create / Destroy private networks
  * Create/Destroy Virtual Machine (VM),
  * Create / Destroy block and object storage,
  * Mount object storage on file system,
  * Create NAS, Connect/disconnect VM to NAS,
  
* Providers addressed:
  * OVH
  * FlexibleEngine
  * CloudWatt
  * AWS