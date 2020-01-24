# SafeScale: platform flavor K8S

This document reports the specific choices made for the Kubernetes flavor of safescale platform.

## Port used for localAPIEndpoint

In the section ```initConfiguration``` of kubeadm, under ```localAPIEndpoint``` subsection, the value of ```bindPort```, set to ```6443``` by default, is changed to ```6444``` when the platform complexity is ```Normal``` or ```Large```).

The reason of this change is to be able to serve any Kubernetes master through a VIP on port 6443.

So if you want to upgrade Kubernetes settings, think about this point.

Here is a way to determine the port to use :

```shell
# grep -- '--secure-port' /etc/kubernetes/manifests/kube-apiserver.yaml | cut -d= -f2
6444
```
