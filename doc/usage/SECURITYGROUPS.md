# SafeScale Security Groups

To configure Network accesses, SafeScale proposes Security Group with Cloud Provider corresponding support.

Security Groups are owned by a Network, but by design the names must be unique in the tenant (because implementations vary on this point between all Cloud Providers).

A Security Group can be bound to a resource (Subnet or Host). A bond does not imply automatically that the rules of the Security Group are applied to the resource, because a Security Group bond can be enabled and disabled.

A Security Group cannot be deleted by SafeScale if it's bound to a resource (Subnet or Host).

As for other SafeScale resources, it's strongly discouraged to manipulate Security Groups created by SafeScale manually on Cloud Provider side, without a good knowledge of how SafeScale works; this may lead to metadata inconsistency and provoke issues.


## Security Groups dedicated to Subnets

When a Subnet is created, 2 dedicated Security Groups are created:
- `safescale-sg_subnet_gataways.<subnet name>.<network name>`: contains the rules that are applied automatically to Host(s) created as gateway; cannot be removed or unbound from Host, only disabled
- `safescale-sg_subnet_internals.<subnet name>.<network name>`: contains the rules that are applied to Host(s), allowing traffic between hosts in the subnet; cannot be removed or unbound from host, only disabled
- `safescale-sg_subnet_publicip.<subnet name>.<network name>`: contains the rules that are applied to Host(s) with public ip,

## Creation of Security Group

As a Security Group is owned by a Network, the command to create/delete/add rules are network related:
- safescale network security group create my-net my-security-group
- safescale network security group delete my-net my-security-group
- safescale network security group add rule [flags] my-net my-security-group
- safescale network security group delete rule [flags] my-net my-security-group
- safescale network security group inspect my-net my-security-group
- safescale network security group bonds my-net my-security-group

## What happens when a Security Group is bound to a Subnet

The Security Group is bound to all the Hosts registered as attached to the Subnet (using SafeScale metadata).

## What happens when a Security Group is bound to a Host

The Security Group is registered as used by the Host, and its rules are applied to the Host.

You can also bind other Security Group you have created.

When a Security Group is bound to a Host, the rules contained in the Security Group are applied on the Host.

## Examples

### Open and close port in the gateway

Imagine you want to accept traffic on gateway on port 8000 from internet :

First create a network with subnet and gateway :

```bash
$ safescale network create my-net
```

When network is created, check that you have the three default security groups :

```bash
$ safescale network securtiy group ls my-net
```

You should get something like this :

```json
{
  "result": [
    {
      "description": "SG for gateways in Subnet my-net of Network my-net",
      "id": "2fa6a3d0-1e6c-4b35-b50a-334197b216fb",
      "name": "safescale-sg_subnet_gateways.my-net.my-net"
    },
    {
      "description": "SG for internal access in Subnet my-net of Network my-net",
      "id": "4fbae0d7-ca19-4977-81dd-e0af3937ef93",
      "name": "safescale-sg_subnet_internals.my-net.my-net"
    },
    {
      "description": "SG for hosts with public IP in Subnet my-net of Network my-net",
      "id": "c666cfac-2ead-4191-99d8-259678a56787",
      "name": "safescale-sg_subnet_publicip.my-net.my-net"
    }
  ],
  "status": "success"
}
```

Now you can add security group rule to open port on gateway :
```bash
$ safescale network security group rule add -D ingress --port-from 8000 --port-to 8000 --cidr "0.0.0.0/0" my-net safescale-sg_subnet_gateways.my-net.my-net
```

And you can close the port using this command : 
```bash
$ safescale network security group rule delete -D ingress --port-from 8000 --port-to 8000 --cidr "0.0.0.0/0" my-net safescale-sg_subnet_gateways.my-net.my-net
```