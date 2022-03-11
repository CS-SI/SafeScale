# SafeScale: Networks

A SafeScale Network corresponds to a Network (Openstack, OVH, ...) or a VPC (AWS, FlexibleEngine, ...) on Cloud Provider side.

It's main purpose is to contain Subnets, with isolation from other Networks or Internet.

Using Networks, you will be able to use same CIDR for different usages.

## Network creation

There are two ways to create a Network as a user :
- the full-featured mode, where Networks and Subnets are fully managed 
- the legacy mode, where a Network was a Cloud Provider Network/VPC with a Subnet using the same name as the Network/VPC. Of course, this legacy mode uses the full-featured mode to realize the work.

The legacy is the default mode, to be consistent with scripts that used SafeScale before v20.09. To use the full-featured mode, the flag `--empty` has to be used at Network creation.

### legacy mode

In this mode, this command,

```bash
$ safescale network create --cidr 172.16.0.0/16 my-net
```

will create a Network/VPC, named `my-net` with the CIDR specified, then a Subnet named as the Network, with a CIDR set to `172.16.0.0/17`, creates a Host to act as gateway of the subnet. This produces the exact same remote configuration than the releases of SafeScale previous v20.09.

The command:
```bash
$ safescale network inspect my-net | jq
```

will display information about the Network like this:

```json
{
  "result": {
    "cidr": "192.168.0.0/24",
    "gateway_ids": [
      "859f7332-95d4-4f83-b881-87e5b9363b3e"
    ],
    "gateway_name": "gw-my-net",
    "id": "a003465b-96fd-4262-a61b-5583453df5d8",
    "name": "my-net",
    "network_cidr": "192.168.0.0/23",
    "network_id": "77bf146b-ff73-4907-bbf5-8fa1c964bd05",
    "state": 3
  },
  "status": "success"
}
```

If the flag `--cidr` is not used, the default CIDR is `192.168.0.0/23` for the Network and `192.168.0.0/24` for the default Subnet.

This command,
``` bash
$ safescale network rm my-net
```
will delete the gateway, the subnet then the Network, in a single command.

This may fail however if you have added a subnet in the Network using full-feature mode. You should have to first delete the Subnet, then the Network.

#### Notes:

    - Comparing to releases before v20.09, some supplemental information are provided: `network_cidr` and `network_id`;
      These ones were hidden previously.
    - It's totally possible to create new Subnets in the Network created, it's the reason why the default Subnet created
      does not cover the entire CIDR of the Network (otherwise it would not be possible in same Provider, like FlexibleEngine).


### full-featured mode

To use this mode, you have to add `--empty` flag to the `safescale network create` call:

```bash
$ safescale network create --empty --cidr 172.16.0.0/16 my-net
```

This will create a Network/VPC on provider side, with the CIDR requested, but without the default SUbnet, gateway, ... You will have to create explicitly Subnets in this Network.

Note that the flags `--gwname`, `--os`, `--sizing` and `failover` are meaningless in this mode. They will have to be used with `safescale network subnet create`

To inspect the Network, same command is used:
```bash
$ safescale network inspect my-net | jq
```
but the result is different:
```json
{
  "result": {
    "cidr": "172.16.0.0/16",
    "id": "2d0c120e-2898-4c6a-bef7-c4b9d4390aa7",
    "name": "my-net"
  },
  "status": "success"
}
```

To delete a Network, use
```bash
$ safescale network rm my-net
```

A Network owns Subnets, but also Security Groups. To know more about Security Groups, see [SECURITYGROUPS.md](SECURITYGROUPS.md)
