# SafeScale: Features

Features allow user to install various tools on a single host or a cluster.

The engine analyzes the feature .yaml file and cuts the action in steps. It tries to parallelize as much as possible the execution of these steps.<br>
For example, when all the masters of a cluster are targeted, the engine executes each step on all hosts in parallel.

## Embededd Features

Here is a list of features that are embedded with Safescale :

feature | description | specificities
----- | ----- | -----
`apache-ignite` |  Install apache ignite on all the devices of a cluster   |  Only available for clusters
`docker` |  Install docker     | -
`docker-compose` |  Install docker-compose   | -
`filebeat` |  Install filebeat who send logs to a remote Logstash    |  Need parameters: <br>`LogstashSocket="IP_logstash:PORT_logstash"` 
`helm` |   Install helm packet manager  |  Only available on a kubernetes flavored cluster (or a dcos with kubernetes installed)
`kubernetes` |  Install and configure a kubernetes cluster   |  Only available for clusters
`metricbeat` |  Install metricbeat who send metrics to a remote Elasticsearch/Kibana   | Need parameters: <br> `KibanaSocket="IP_kibana:PORT_kibana"` <br> `ElasticsearchSocket="IP_elasticsearch:PORT_elasticsearch "`
`nvidiadocker` |  Install nvidia-docker, allowing nvidia driver to works in a docker container   |  On a cluster it will only be applied to nodes
`proxycache-client` |  Install a squid proxyCache client    |  Only available for hosts 
`proxycache-server` |  Install a squid proxyCache server    |  Only available for hosts
`remotedesktop` |  Install a remotedesktop using guacamole with tigerVNC and xfce desktop   |  On a cluster a remote desktop will be installed on all masters <br>Need parameters: <br> `Username="existing_user"` <br> `Password="user_password"`
`reverseproxy` |  Install a kong reverse proxy  | Only available for hosts (usually a gateway)
`spark` |  Install and configure a spark cluster   |  Only available on a kubernetes or dcos flavored cluster

_Note_: the `reverseproxy` feature is automatically installed on the gateway when a network is created by SafeScale (included a host acting as a gateway for the network).

## How to install a feature

[cf. Usage](USAGE.md)

## How to write a feature

In addition to _embedded features_ listed above, Safescale will look for _external features_ in folders : 
*	$HOME/.safescale/features
*	$HOME/.config/safescale/features
*	/etc/safescale/features

Each .yaml file in one of these folder will be treated as a feature.

_Note 1_: Any _external feature_ named as an _embedded feature_ will take precedence over the _embedded feature_.
_Note 2_: it's possible to use subfolder(s) inside ```features``` folder, by including the relative path from ```features``` in the name of the feature.

### Feature.yaml file

Features are provided as a yaml file which is detailing where, how and which code should be exectuted to check installation, install or remove the tool
The file have to follow this struture.

```
---
feature:
    suitableFor:
        host: <false | true>
        cluster: <false | all | boh | dcos | k8s | ohpc | swarm>
    requirements:
        features:
            - feature1
            - ...
    parameters:
        - mandatory_parameter1
        - ...
    install:
        <apt | bash | dcos | dnf | yum>:
            check:
                pace: step1_name[,...]
                steps:
                    step1_name:
                        targets:
                            hosts: <true (default) | false>
                            masters: <none (default) | one | all>
                            nodes: <none (default) | one | all>
                            gateways: <none (default) | one | all>
                        run: |
                            script_to_execute
                    ... and so on ...
            add:
                pace: step1_name,step2_name[,...]
                steps:
                    step1_name:
                        serial: <true | false>
                        wallTime: time_in_sec
                        targets:
                            hosts: <true (default) | false>
                            masters: <none (default) | one | all>
                            nodes: <none (default) | one | all>
                            gateways: <none (default) | one | all>
                        run: |
                            script_to_execute
                    step2_name:
                        serial: <true | false>
                        wallTime: time_in_sec
                        targets:
                            hosts: <true (default) | false>
                            masters: <none (default) | one | all>
                            nodes: <none (default) | one | all>
                            gateways: <none (default) | one | all>
                        run: |
                            script_to_execute
                    ... and so on ...

            remove:
                pace: step1_name[,...]
                steps:
                    step1_name:
                        targets:
                            hosts: <true (default) | false>
                            masters: <none (default) | one | all>
                            nodes: <none (default) | one | all>
                            gateways: <none (default) | one | all>
                        run: |
                            script_to_execute
                    ... and so on ...

    proxy:
        rules:
            - name: rule_name_1
              type: <service | route | upstream >
              targets:
                  hosts: <true (default) | false>
                  masters: <none (default) | one | all>
                  nodes: <none (default) | one | all>
                  gateways: <none (default) | one | all>
              content: |
                  {
                      "param1": "value1",
                      "param2": "value2"
                  }

            - name: rule_name_2
              type: <service | route | upstream >
              targets:
                  hosts: <true (default) | false>
                  masters: <none (default) | one | all>
                  nodes: <none (default) | one | all>
                  gateways: <none (default) | one | all>
              content: |
                  {
                      "param1": "value1",
                      "param2": "value2"
                  }
            ... and so on ...
...
```

key | description | subkeys | values | mandatory
----- | ----- | ----- | ----- | -----
`suitableFor`    | Describe where the feature could be installed | host <br> cluster | - | True
host    |  Allow the feature to be installed on a single host  | - | true <br> false | True
cluster    |  Allow the feature to be installed on a cluster flavor   | - |  false (can't be installed on any flavor)<br> any (can be installed on any flavor)<br> boh <br> dcos <br> k8s <br> ohpc <br> swarm <br> *Multiples flavors can be allowed separated with a comma; ex: (swarm,boh)* | True
`requirements`   | Describe requirements for the feature to works properly | features <br> clusterSizing | - | False
features    | Features who should be installed before to start   | -  |  feature_list | False
clusterSizing    | ? |  ? | ? | False
`parameters` | List of parameters mandatory to launch the feature installation | - | parameter_list | False
`install` | Describe how to install the feature | apt <br> bash <br> dcos <br> dnf <br> yum <br> *You can specify how to install the feature with any combinaison of installation methods, just by creating a new subkey for each method* | - | True
apt <br> bash <br> dcos <br> dnf <br> yum | Describe how to install the feature for a specific method | check <br> add <br> remove | - | True
check    | Describe the process to check if the feature is already installed <br> runs should all exit with 0 if the feature is installed | pace <br> steps | - | True
add    | Describe the process to install the feature <br> runs should all return 0 if the installation works well | pace <br> steps | - | True 
remove    | Describe the process to remove the feature <br> runs should all return 0 if the suppression works well | pace <br> steps | - | True 
pace | List the steps needed to achieve the check/add/remove | - | step_list <br> *Separated by commas, they will be executed in the provided order* | True
steps | Each steps subkey will be a step | step <br> *There could be any number of step but they have to be registerd in pace to be taken in account* | - | True
step<br>*Step real name could be anything* | A sub task of check/add/remove | wallTime <br> targets <br> run | - | True
serial | Allow the step to be executed on all targets in parallel | - | true (default) <br> false | False
wallTime | Timeout of the step (in minutes) | - | timeoutValue | False
targets | Where shoud the step be executed | hosts <br> masters <br> nodes <br> gateways | - | True
hosts | Should the step be executed on a single host | - | false (will not be executed) <br> yes (will be executed) | True
gateways | Shoud the step be executed on gateway(s) | - | none (will not be executed on gateways; default) <br> one (will be executed on only one, the same on all steps) <br> all (will be executed on all gateways) | False
masters <br> nodes | Shoud the step be executed on cluster masters/nodes | - | none (will not be executed; default) <br> one (will be executed on only one, the same on all steps) <br> all (will be executed on all) | True
run | Script to execute remotely on the target(s) by the chosen method <br> An exit code different from 0 will be considered as a failure | - | script <br> *The script will be extended by preset functions and templated parameters, [cf. Install-step-run](###Install-step-run)* | True
`proxy` | Describe the reverse-proxy modifications needed by the feature | rules | - | False
rules  | Describe the reverse-proxy rules needed by the features | - | List_of_rule | True
rule | Decribe a reverse-proxy rule | name <br> type <br> targets <br> content | - | True
name | The rule name | - | rule_name | True
type | The kind of rule to apply | - | service (https://docs.konghq.com/1.0.x/admin-api/#service-object) <br> route (https://docs.konghq.com/1.0.x/admin-api/#route-object) <br> upstream (https://docs.konghq.com/1.0.x/admin-api/#upstream-object) | True
targets | Where shoud the step be executed | hosts <br> masters <br> privateNodes <br> publicNodes | - | True
hosts | Shoud the step be executed on a single host | - | false (will not be executed) <br> yes (will be executed) | True
masters <br> privateNodes <br> publicNodes | Shoud the step be executed on cluster masters/privateNodes/publicNodes | - | none (will not be executed) <br> one (will be executed on only one, the same | True 
content | Parameters of the rule, they will depend of the rule type | - | json repesentation of a map with param_name as key and param_value as value <br> *The script will be extanded by templated parameters, [cf. Proxy-rule-content](###Proxy-rule-content)* | True


### Install-step-run

Each install step has a run field describing the commands who will be executed on the targeted host (the execution method will depend of the chosen installer). If a step exits with a return code different from 0, the step will be considered failed and the following steps will not be executed.<br>
Several templated parameters are useable (using GO text template syntax) : 
*   `{{.Username}}` : the name of the default user of the targeted host/cluster
*   `{{.Hostname}}` : the hostname of the current targeted host (keep in mind at the lower level, each step is applied on all hosts targeted)
*   `{{.HostIP}}`   : the IP of the current targeted host
*   `{{.GatewayIP}}` : The private IP of the gateway
*   `{{.PublicIP}}` : the public IP of the gateway
*   `{{._parameter_}}` : parameter given to the feature

Several embedded functions are available to be use in scripts (cf. system/scripts/bash_library.sh in SafeScale code)

### Proxy-rule-content

A feature has the ability to configure the Reverse Proxy installed by default on the gateway of a SafeScale network. This Reverse Proxy is using Kong.<br>
3 types of rules are proposed, and can use the same templated parameters describe above.<br>
In addition, each rule of type `service` will define a parameter named as the rule name, to allow to reference it in rule of type `route` (which must appear after the referenced service).

#### rule type `upstream`

This type of rule allows to define the backend(s) of a service in Reverse Proxy. The content follows what Kong is wanting.

Example:
```
- name: upstream
  type: upstream
  targets:
      masters: all
  content: |
      {
          "name": "k8s-CPs",
          "target": "{{.HostIP}}:6443",
          "weight": 100
      }
```

In this example, we configure the reverse proxy to create an upstream named _k8s-CPs_ (Kubernetes Control Planes), adding
{{.HostIP}}:6443 as a backend to it. The use of `masters: all` in the `targets` make this rule loops all the masters and
execute the same configuration, for each master, where {{.HostIP}} is the master IP address.<br>
The result is an upstream corresponding to as many backends as there are masters that will be targetable by a service.

_Note_: The use of `upstream` in optional, if you have only one target that can respond. In this case, everything could be
set directly in a `service`.

#### rule type `service`

This type of rule allows to define a Reverse Proxy service that will forward requests to an upstream (containing backend(s)).

Example :
```
- name: guacamole
    type: service
    targets:
        hosts: true
        masters: all
    content: |
        {
            "name": "remotedesktop_{{.Hostname}}",
            "url": "http://{{.HostIP}}:9080/guacamole/"
        }
```

In this example, we define a service in Reverse Proxy named `guacamole`, that will forward traffic to URL provided. Here we do this for all
masters that have to propose a remote desktop.

_Note_: this example will induce the creation of a parameter called `guacamole`, like the name of the service, containing the id of the accepted rule. This parameter will be used in the `route` rule example below.


#### rule type `route`
A kong route aims to link a service to a public url.

Example : 
```
- name: remotedesktop
    type: route
    targets:
        hosts: true
        masters: all
    content: |
        {
            "paths": ["/remotedesktop/{{.Hostname}}"],
            "service": { "id": "{{.guacamole}}" }
        }
```

In this example, we make the Reverse Proxy to react to an URL of /remotedesktop/<host name>, which will forward traffic
to service id `guacamole`.

_Note_: In the examples from `service` and `route` paragraphs, we used the same `masters: all` parameter as targets ; the feature engine ensures that the
dynamically defined service parameters are consistent between all the masters, otherwise it may mess the configuration.
