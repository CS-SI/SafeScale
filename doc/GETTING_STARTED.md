# Getting Started Safescale
## To get binaries :
1. Get on github : https://github.com/CS-SI/SafeScale/releases  
2. Compil : https://github.com/CS-SI/SafeScale/blob/master/doc/build
3. Compil with docker : After git checkout, run ./create-docker.sh -f (for that you need to install `docker.io`)

# Steps to launch daemon safescaled :
1. Copie binaries on your client
2. Install jq 
3. Launch `safescaled` one time to create config dir
4. Create a tenant.toml into `.safescale`
5. Add env and aliases on your `.bashrc`  
example :  
```
export SAFESCALE_METADATA_SUFFIX="your trigram"
alias sc=safescale  
alias schls="safescale host ls | jq"  
alias sccls="safescale cluster ls | jq"  
alias sctls="safescale tenant ls | jq"  
alias sctget="safescale tenant get | jq"  
````
6. Launch : `safescaled on terminal` or `safescaled -d -v` for verbose and debug mode

# Example : safescale command
## List tenants
`safescale tenant ls`
## Set tenants
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
`safescale cluster create -C "Normal" -F "K8S" --cidr 192.168.11.0/24 <cluster_name>`

## To delete a node on a cluster
`safescale shrink <node_name>`

## To add a node on a cluster
`safescale expand <cluster_name>`

## To list all masters node into a cluster
`safescale cluster inspect <cluster_name> | jq '.result.nodes.masters'`  
To get IPs adresses of this masters :
`safescale cluster inspect <cluster_name> | jq '.result.nodes.masters[].private_ip'`  
If you want to remove "" you need to add "-r" option after jq command
