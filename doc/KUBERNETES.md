# SafeScale: platform flavor K8S

This document reports the specific choices made for the Kubernetes flavor of the command ```safescale platform```.

## Differences between complexities (parameter ```--complexity|-C```)

### ```Small``` complexity

This complexity creates a cluster with a single gateway, a single Kubernetes master and a single Kubernetes node. There is no HA ability with it.

### ```Normal``` complexity

This complexity creates a cluster with 2 gateways (unless gateway failover is explicitly disabled with ```--disable gateway-failover```), 3 Kubernetes Masters and 3 Kubernetes Nodes, with HA ability :

- the 2 gateways ensure Internet connectivity for the LAN.
- the 3 Kubernetes Masters allows the failure of 1 master at a time.

### ```Large``` complexity

This complexity creates a cluster with 2 gateways (unless gateway failover is explicitly disabled with ```--disable gateway-failover```), 5 Kubernetes Masters and 6 Kubernetes Nodes, with HA ability :

- the 2 gateways ensure Internet connectivity for the LAN.
- the 5 Kubernetes Masters allows the failure of 2 masters at a time.

___

## Port used for localAPIEndpoint

In the section ```initConfiguration``` of the configuration used by *kubeadm*, under ```localAPIEndpoint``` subsection, the value of ```bindPort```, set to ```6443``` by default, is changed to ```6444``` when the platform complexity is ```Normal``` or ```Large```.

The reason of this change is to be able to serve any Kubernetes master through a VIP on port 6443.

So if you want to upgrade Kubernetes settings, think about this point.

Here is a way to determine the port used :

```shell
$ grep -- '--secure-port' /etc/kubernetes/manifests/kube-apiserver.yaml | cut -d= -f2
6444
```
