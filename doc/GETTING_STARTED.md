# Getting Started Safescale
## To get binaries :
1. Get on github : https://github.com/CS-SI/SafeScale/releases  
2. Compil : https://github.com/CS-SI/SafeScale/blob/master/doc/build/BUILDING.md
3. Build with docker : https://github.com/CS-SI/SafeScale/blob/master/doc/build/DOCKER_BUILD.md

# Steps to launch daemon safescaled :
1. Copy binaries on your client
2. Install jq 
3. Launch daemon `safescaled` one time to create config dir
4. Create a tenant.toml into `$HOME/.safescale`
5. (optionally) Add env and aliases on your `.bashrc`  
example :  
```
export SAFESCALE_METADATA_SUFFIX="your trigram"
alias sc=safescale  
alias schls="safescale host ls | jq"  
````
6. Relaunch daemon: `safescaled` (`safescaled -d -v` for verbose and debug mode)

# Example : safescale command
## List tenants
`safescale tenant ls`
## Set current tenant (the one that will execute next commands)
`safescale tenant set <tenant_name>`
## Get current tenant
`safescale tenant get`


## To create a host :
````
# First you need to create a network :
safescale network create <network_name>
safescale host create --net <network_name> --sizing "cpu<=2,ram<=7,disk<=100" <hostname> 
````

## To create a cluster:
// Warning of specs for tenant (Example : Flexible Engine : need CIDR parameter)
`safescale cluster create -C Normal -F K8S --cidr 192.168.11.0/24 <cluster_name>`

## To add one node on a cluster
`safescale cluster expand <cluster_name>`

## To delete one node from a cluster
`safescale cluster shrink <cluster_name>`

## To list all masters into a cluster
`safescale cluster inspect <cluster_name> | jq '.result.nodes.masters'`  

To get private IP addresses of these masters :
`safescale cluster inspect <cluster_name> | jq '.result.nodes.masters[].private_ip'`  
If you want to remove `""` around the results, you need to add `-r` option after `jq` command

## To list all nodes into a cluster
`safescale cluster inspect <cluster_name> | jq '.result.nodes.nodes'` 