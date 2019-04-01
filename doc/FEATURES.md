# SafeScale: Features

Features allow user to install various tools on a single host or a cluster.


## Available Features

All the features provided nativly by safescale

feature | description | specificities
----- | ----- | -----
`apache-ignite` |  Install apache ignite on all the devices of a cluster   |  Only available for clusters
`docker` |  Install docker     | -
`docker-compose` |  Install docker-compose   | -
`filebeat` |  Install filebeat who send logs to a remote Logstash    |  Need parameters: <br>`LogstashSocket="IP_logstash:PORT_logstash"` 
`helm` |   Install helm packet manager  |  Only available on a kubernetes flavored cluster (or a dcos with kubernetes installed)
`kubernetes` |  Install and configure a kubernetes cluster   |  Only available for clusters
`metricbeat` |  Install metricbeat who send metrics to a remote Elasticsearch/Kibana   | Need parameters: <br> `KibanaSocket="IP_kibana:PORT_kibana "` <br> `ElasticsearchSocket="IP_elasticsearch:PORT_elasticsearch "`
`mpich-build` |   ?  |  ?
`mpich-ospkg` |   ?  |  ?
`nvidiadocker` |  Install nvidia-docker, allowing nvidia driver to works in a docker container   |  On a cluster it will only be applied to nodes
`ohpc-slurm-master` | ?    |  ?
`ohpc-slurm-node` |  ?   |  ?
`proxycache-client` |  Install a squid proxyCache client    |  Only available for hosts 
`proxycache-server` |  Install a squid proxyCache server    |  Only available for hosts
`remotedesktop` |  Install a remotedesktop using guacamole with tigerVNC and xfce desktop   |  On a cluster a remote desktop will be installed on all masters <br>Need parameters: <br> `Username="existing_user"` <br> `Password="user_password"`
`reverseproxy` |  Install a kong reverse proxy  | Only available for hosts (usually a gateway)
`spark` |  Install and configure a spark cluster   |  Only available on a kubernetes or dcos flavored cluster


## How to install a feature

[cf. Usage](USAGE.md)

## How to write a feature

Safescale will look for foreign features in folders : 
*	$HOME/.safescale/features
*	$HOME/.config/safescale/features
*	/etc/safescale/features

Each .yaml file in one of these folder will be treated as standard feature

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
        <ansible | apt | bash | dcos | dnf | helm | yum >:
            check:
                pace: step1_name,...
                steps:
                    step1_name:
                        targets:
                            hosts: <true | false>
                            masters: <none | one | all>
                            privateNodes: <none | one | all>
                            publicNodes: <none | one | all> 
                        run: |
                            script_to_execute

            add:
                pace: step1_name,step2_name,...
                steps:
                    step1_name:
                        serial: <true | false>
                        wallTime: time_in_sec
                        targets:
                            hosts: <true | false>
                            masters: <none | one | all>
                            privateNodes: <none | one | all>
                            publicNodes: <none | one | all> 
                        run: |
                            script_to_execute
                    step2_name:
                        serial: <true | false>
                        wallTime: time_in_sec
                        targets:
                            hosts: <true | false>
                            masters: <none | one | all>
                            privateNodes: <none | one | all>
                            publicNodes: <none | one | all> 
                        run: |
                            script_to_execute

            remove:
                pace: step1_name,...
                steps:
                    step1_name:
                        targets:
                            hosts: <true | false>
                            masters: <none | one | all>
                            privateNodes: <none | one | all>
                            publicNodes: <none | one | all> 
                        run: |
                            script_to_execute


    proxy:
        rules:
            - name: rule_name_1
              type: <service | route | upstream >
              targets:
                  hosts: <true | false>
                  masters: <none | one | all>
                  privateNodes: <none | one | all>
                  publicNodes: <none | one | all> 
              content: | (service example)
                  {
                      "param1": "value1",
                      "param2": "value2"
                  }

            - name: rule_name_2
              type: <service | route | upstream >
              targets:
                  hosts: <true | false>
                  masters: <none | one | all>
                  privateNodes: <none | one | all>
                  publicNodes: <none | one | all> 
              content: | (service example)
                  {
                      "param1": "value1",
                      "param2": "value2"
                  }
            ...
...
```

key | description | subkeys | values | mandatory
----- | ----- | ----- | ----- | -----
`suitableFor`    | Describe where the feature could be installed | host <br> cluster | - | True
host    |  Allow the feature to be installed on a single host  | - | true <br> false | True
cluster    |  Allow the feature to be installed on a cluster flavor   | - |  false (can not be installed on any flavor)<br> any (can be installed on any flavor)<br> boh <br> dcos <br> k8s <br> ohpc <br> swarm <br> *Multiples flavors can be selected separated with a comma ex: (swarm,boh)* | True
`requirements`   | Describe requirements for the feature to works properly | features <br> clusterSizing | - | False
features    | Features who should be installed before to start   | -  |  feature_list | False
clusterSizing    | ? |  ? | ? | False
`parameters` | List of parameters mandatory to launch the feature installation | - | parameter_list | False
`install` | Describe how to install the feature | ansible <br> apt <br> bash <br> dcos <br> dnf <br> helm <br> yum <br> *You can specify how to install the feature with any combinaison of installation methods, just by creating a new subkey for each method* | - | True
ansible <br> apt <br> bash <br> dcos <br> dnf <br> helm <br> yum | Describe how to install the feature for a specific method | check <br> add <br> remove | - | True
check    | Describe the process to check if the feature is already installed <br> runs should all exit with 0 if the feature is installed | pace <br> steps | - | True
add    | Describe the process to install the feature <br> runs should all return 0 if the installation works well | pace <br> steps | - | True 
remove    | Describe the process to remove the feature <br> runs should all return 0 if the suppression works well | pace <br> steps | - | True 
pace | List the steps needed to achieve the check/add/remove | - | step_list <br> *Separated by commas, they will be executed in the provided order* | True
steps | Each steps subkey will be a step | step <br> *There could be any number of step but they have to be registerd in pace to be taken in account* | - | True
step<br>*Step real name could be anything* | A sub task of check/add/remove | wallTime <br> targets <br> run | - | True
serial | Allow the step to be executed on all targets in parallel | - | true <br> false | False
wallTime | Timeout of the step (in minutes) | - | timeoutValue | False
targets | Where shoud the step be executed | hosts <br> masters <br> privateNodes <br> publicNodes | - | True
hosts | Shoud the step be executed on a single host | - | famse (will not be executed) <br> yes (will be executed) | True
masters <br> privateNodes <br> publicNodes | Shoud the step be executed on cluster masters/privateNodes/publicNodes | - | none (will not be executed) <br> one (will be executed on only one, the same on all steps) <br> all (will be executed on each) | True
run | Script to execute remotly on the device(s) targeted by the chosen method <br> An exit code different from 0 will be considered as a failure | - | script <br> *The script will be extanded by preseted functions and templated parameters, [cf. Install-step-run](###Install-step-run)* | True
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

Each install step has a run field describing the commands who will be executed on the targeted host (the execution method will depend of the chosen installer). If a step exits with a return code other than 0, the installation of the components will be considered a failure and the following steps will not be executed<br>
Several templated parameters are available : 
*   {{.Username}} : the name of the default user of the targeted host
*   {{.Hostname}} : the hostname of the current targeted host
*   {{.HostIP}}   : the IP of the current targeted host
*   {{.GatewayIP}} : The private IP of the gateway
*   {{.PublicIP}} : the public IP of the gateway
*   {{._parameter_}} : parameter given to the feature

Several embedded functions are available (cf. system/scripts/bash_library.sh)

### Proxy-rule-content

Each proxy rule needs content to be set with the parameters needed by kong and have to be formated in json. <br>
Several templated parameters are available : 
*   {{.Hostname}} : the hostname of the current targeted host
*   {{.HostIP}}   : the IP of the current targeted host
*   {{.GatewayIP}} : The private IP of the gateway
*   {{.PublicIP}} : the public IP of the gateway
*   {{._parameter_}} : parameter given to the feature
*   {{._rule_name_}} : the ID of the rule identified with name rule_name

#### Services
A kong service aims to register a local url.

Example :
```
{
    "name": "remotedesktop_{{.Hostname}}",
    "url": "http://{{.HostIP}}:9080/guacamole/"
}
```

#### Routes
A kong route aims to link a service to a public url.

Example : 
```
{
    "paths": ["/remotedesktop/{{.Hostname}}"],
    "service": { "id": "{{.guacamole}}" }
}
```

#### Upstreams

?