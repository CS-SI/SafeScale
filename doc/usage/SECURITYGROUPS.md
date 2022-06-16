# SafeScale Security Groups

To configure Network accesses, SafeScale proposes Security Group with Cloud Provider corresponding support.

Security Groups are owned by a Network, but by design the names must be unique in the tenant (because implementations vary on this point between all Cloud Providers).

A Security Group can be bound to a resource (Subnet or Host). A bond does not imply automatically that the rules of the Security Group are applied to the resource, because a Security Group bond can be enabled and disabled.

A Security Group cannot be deleted by SafeScale if it's bound to a resource (Subnet or Host).

As for other SafeScale resources, it's strongly discouraged to manipulate Security Groups created by SafeScale manually on Cloud Provider side, without a good knowledge of how SafeScale works; this may lead to metadata inconsistency and provoke issues.


## Security Groups dedicated to Subnets

When a Subnet is created, 2 dedicated Security Groups are created:
- `subnet_<subnet name>_gateway_sg`: contains the rules that are applied automatically to Host(s) created as gateway; cannot be removed or unbound from Host, only disabled
- `subnet_<subnet name>_internal_sg`: contains the rules that are applied to Host(s), allowing traffic between hosts in the subnet; cannot be removed or unbound from host, only disabled

## Security Group dedicated to Hosts

When a new Host is created, a dedicated Security Group called `host_<hostname>_default_sg` is created, without rules. You can add/remove rules to if you want to tune the network accesses to Host.

This dedicated Security Group cannot be unbound or removed from Host, only disabled.

## Creation of Security Group

As a Security Group is owned by a Network, the command to create/delete/add rules are network related:
- safescale network security group create my-net my-security-group
- safescale network security group delete my-net my-security-group
- safescale network security group add rule [flags] my-net my-security-group
- safescale network security group inspect my-net my-security-group
- safescale network security group bonds my-net my-security-group

## What happen when a Security Group is bound to a Subnet

The Security Group is bound to all the Hosts registered as attached to the Subnet (using SafeScale metadata).

## What happen when a Security Group is bound to a Host

The Security Group is registered as used by the Host, and its rules are applied to the Host.

You can also bind other Security Group you have created.

When a Security Group is bound to a Host, the rules contained in the Security Group are applied on the Host.
