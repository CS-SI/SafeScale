# Cluster creation

This video shows the creation of a Kubernetes cluster composed of 1 gateway for the local network, 1 master and 1 node,
with Remote Desktop on the master, and Reverse Proxy on the gateway.

It then adds these features :

- wps : WPS server with hardcoded action (which needs EODAG docker image as requirement)
- sparkmaster: Spark Master container on master
- s2p : Spark Slaves containing necessary S2P code to do the job

WPS will be able to accept requests on https://\<cluster public ip\>/services/wps from Internet, thanks
to the Reverse Proxy of the cluster.
