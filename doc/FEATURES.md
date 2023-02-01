# SafeScale: Features

Features allow user to install various tools on a single host or a cluster.

The engine analyzes the feature .yaml file and cuts the action in steps. It tries to parallelize as much as possible the execution of these steps.<br>
For example, when all the masters of a cluster are targeted, the engine executes each step on all masters in parallel.

## Embedded Features

Here is a non-exhaustive list of features that are embedded with Safescale :

feature | description | specificities
----- | ----- | -----
`ansible` |  Install ansible     |
`docker` |  Install docker and docker-compose     |
`ntpclient` |  Install NTP client     |
`ntpserver` |  Install NTP server     |
`remotedesktop` |  Install a remote desktop using guacamole with tigerVNC and xfce desktop   |  On a cluster a remote desktop will be installed on all masters. In this context, Username is automatically set to `cladm` and the associated password is stored in the cluster information, viewable with `safescale cluster inspect <cluster_name>`<br><br>When installed on single host, you will need to set these parameters (this corresponding user must exist on the host before installation of the feature): <br> `Username="existing_user"` <br> `Password="user_password"`
`edgeproxy4subnet` |  Install a Kong reverse proxy for SafeScale use<br>Corresponds to `reverseproxy`  | Only available for clusters
`postgresql4gateway` |  Install a postgresql v9 server on gateways  | Dependency of `edgeproxy4subnet`
`kubernetes` |  Install and configure a kubernetes cluster   |  Only available for clusters
`helm3` |   Install helm packet manager v3  |  Only meaningful on a kubernetes flavored cluster

## How to install a feature

[cf. Usage](USAGE.md)

## How to write a feature

In addition to _embedded features_ listed above, Safescale will look for _external features_ in folders :
*	$HOME/.safescale/features
*	$HOME/.config/safescale/features
*	/etc/safescale/features

Each .yaml file in one of these folder will be treated as a feature.

_Note 1_: Any _external feature_ named as an _embedded feature_ will take precedence over the _embedded feature_.
_Note 2_: it's possible to use subfolder(s) inside ```features``` folder; when using it, the relative path from ```features``` must be used in the name of the feature.

### feature.yaml file

Features are provided as a yaml file which is detailing where, how and which code should be executed to check installation, install or remove the tool
The file have to follow this structure.

```
---
feature:
    suitableFor:
        host: <false | true>
        cluster: <false | all | boh | k8s>
    requirements:
        features:
            - feature1
            - ...
    parameters:
        - mandatory_parameter1
        - ...
    install:
        bash:
            check:
                pace: step1_name[,...]
                steps:
                    step1_name:
                        targets:
                            hosts: <all (default) | none>
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
                        serialized: <true | false>
                        timeout: time_in_minutes
                        targets:
                            hosts: <all (default) | none>
                            masters: <none (default) | one | all>
                            nodes: <none (default) | one | all>
                            gateways: <none (default) | one | all>
                        run: |
                            script_to_execute
                    step2_name:
                        serialized: <true | false>
                        timeout: time_in_minutes
                        targets:
                            hosts: <all (default) | none>
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
                            hosts: <all (default) | none>
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
                  hosts: <all (default) | none>
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
                  hosts: <all (default) | none>
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

| key | description | subkeys | values | mandatory |
| --- | --- | --- | --- | --- |
| `suitableFor`    | Describe where the feature could be installed | *host*<br>*cluster* | - | Yes |
| *host*    |  Allow the feature to be installed on a single host  | - | `true`<br>`false` | Yes |
| *cluster*    |  Allow the feature to be installed on a cluster flavor   | - |  `false` (cannot be installed on any flavor)<br> `any` (can be installed on any flavor)<br> `boh`<br>`dcos`<br>`k8s`<br>`ohpc`<br>`swarm`<br>Multiples flavors can be allowed separated with a comma; ex: (swarm,boh) | Yes |
||||||
| `requirements`   | Describe requirements for the feature to works properly | *features*<br>*clusterSizing* | - | No |
*features*    | Features who should be installed before to start   | -  |  `feature_list` | False
*clusterSizing*    | ? |  ? | ? | False
||||||
`parameters` | List of parameters used by the feature | - | `parameter_list` | False
||||||
| `install` | Marks the beginning of the description of the install methods supported.<br>A single feature file can define several methods of installation using as many subkeys as needed | *apt*<br>*bash*<br>*dcos*<br>*yum*| - | Yes |
| *apt* <br> *bash* <br> *dcos* <br> *yum* | Describe how to install the feature for a specific method | *check*<br>*add*<br>*remove*| - | Yes |
| *check*    | Describe the process to check if the feature is already installed <br> runs should all exit with 0 if the feature is installed | *pace*<br>*steps*<br>*targets* | - | Yes |
| *add*    | Describe the process to install the feature <br> runs should all return 0 if the installation works well | *pace*<br>*steps*<br>*targets* | - | Yes |
| *remove*    | Describe the process to remove the feature <br> runs should all return 0 if the suppression works well | *pace*<br>*steps<br>*targets* | - | No |
| *pace* | Comma-separated list of the steps needed to achieve the action, in specified order | - | `step_list` | Yes |
| *steps* | Marks the beginning of step definitions<br>There could be any number of steps but they have to be registered in *pace* to be applied | *Step real name* | - | Yes |
| *Step real name* | Name of a step<br>type: string | *timeout*<br>*targets*<br>*run*<br>*serialized* | - | Yes |
| *serialized* | Force the step to be executed in serial on targets<br>if set to false, step is executed in parallel on targets | - | `false` (default) <br> `true` | No |
| *timeout* | Timeout of the step (in minutes) | - | `timeout_value` | No |
| *run* | Script to execute remotely on the target(s) by the chosen method <br> An exit code different from 0 will be considered as a failure | - | script <br> The script will be extended by preset functions and templated parameters, [cf. Install-step-run](###Install-step-run) | Yes |
| *targets* | Where shoud the step be executed | *hosts*<br>*masters*<br>*nodes*<br>*gateways*| - | Yes |
| *hosts* | Should the step be executed on a single host | - | `false`|`no` (will not be executed) <br> `true`|`yes` (will be executed) | Yes |
| *gateways* | Shoud the step be executed on gateway(s) | - | `none` (will not be executed on gateways; default) <br> `one`|`any` (will be executed on only one, the same on all steps) <br> `all` (will be executed on all gateways) | No |
| *masters* <br> nodes | Shoud the step be executed on cluster masters/nodes | - | `none` (will not be executed; default) <br> `one` (will be executed on only one, the same on all steps) <br> `all` (will be executed on all) | Yes |
||||||
| `proxy` | Describe the reverse-proxy modifications needed by the feature | *rules* | - | False |
| *rules*  | Describe the reverse-proxy rules needed by the features | - | `rule_list` | True |
| *rule* | Describe a reverse-proxy rule | *name*<br>*type*<br>*targets*<br>*content* | - | True |
| *name* | The rule name | - | `rule_name` | Yes |
| *type* | The kind of rule to apply | - | `service` (https://docs.konghq.com/1.0.x/admin-api/#service-object) <br> `route` (https://docs.konghq.com/1.0.x/admin-api/#route-object) <br> `upstream` (https://docs.konghq.com/1.0.x/admin-api/#upstream-object) | Yes |
| *targets* | Where shoud the step be executed | *hosts* <br> *masters* <br> *nodes* | - | Yes |
| *hosts* | Should the step be executed on a single host | - | `false`|`no` (will not be executed) <br> `true`|`yes` (will be executed) | Yes |
| *masters* <br> *nodes* | Should the step be executed on cluster masters/nodes | - | `none` (will not be executed) <br> `one` (will be executed on only one, the same on all steps)<bt>`all`| Yes |
| *content* | Parameters of the rule, they will depend of the rule type | - | json representation of a map with param_name as key and param_value as value <br> The script will be extended by templated parameters, [cf. Proxy-rule-content](###Proxy-rule-content)* | Yes |

| values | description |
| ----- | ----- |
| `feature_list` | YAML array of feature names |
| `parameter_list` | YAML array of parameters following the format: &lt;name&gt;[=[&lt;value&gt;]]<br>If no `=` is used, parameter &lt;name&gt; needs a mandatory &lt;value&gt; passed by the safescale command<br>if `=` is used without &lt;value&gt;, parameter value is empty |
| `rule_name` | String containing the name of the rule |
| `rule_list` | YAML list of rules |
| `step_list` | Comma-separated string containing a list of steps |
| `timeout_value` | Integer representing minutes |

### Install-step-run

Each install step has a run field describing the commands who will be executed on the targeted host (the execution method will depend of the chosen installer). If a step exits with a return code different from 0, the step will be considered failed and the following steps will not be executed.<br>
Several templated parameters are usable (using GO text template syntax, extended with [sprig](https://github.com/Masterminds/sprig)) :
*   `{{.Username}}` : the name of the user used by SafeScale
*   `{{.Hostname}}` : the hostname of the current targeted host (keep in mind at the lower level, each step is applied on all hosts targeted)
*   `{{.HostIP}}`   : the private IP of the current targeted host
*   `{{.PublicIP}}`   : the public IP of the current targeted host (if there is one)
*   `{{.DefaultRouteIP}}` : The IP of the default route for hosts inside the network
*   `{{.EndpointIP}}` : The public IP to reach the network/platform from Internet
*   `{{.<parameter name>}}` : value of parameter defined in the feature

Several embedded functions are available to be use in scripts (cf. system/scripts/bash_library.sh in SafeScale code)

### Proxy-rule-content

A feature has the ability to configure the Reverse Proxy installed by default on the gateway of a SafeScale network. This Reverse Proxy is using Kong.<br>
3 types of rules are proposed, and can use the same templated parameters describe above.<br>
In addition, each rule of type `service` will define a parameter named as the rule name, to allow to reference it in rule of type `route` (which must appear after the referenced service).

#### rule type `upstream`

This type of rule allows to define the backend(s) of a service in Reverse Proxy. The content follows what Kong is wanting.

Example:
```yaml
- name: controlplane
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
```yaml
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
```yaml
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

In this example, we make the Reverse Proxy to react to an URL of /remotedesktop/&lt;host name&gt;, which will forward traffic
to service id `guacamole` previously defined.

_Note_: In the examples from `service` and `route` paragraphs, we used the same `masters: all` parameter as targets ; the feature engine ensures that the
dynamically defined service parameters are consistent between all the masters, otherwise it may mess the configuration.
