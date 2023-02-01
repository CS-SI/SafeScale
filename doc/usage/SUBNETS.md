# SafeScale: Subnets

A SafeScale Subnet corresponds to a LAN on which Hosts will be created. All Cloud Providers offer corresponding resources. 

Subnets are owned by Networks; their names have to be unique across the Network.

## Preambule

Everywhere you see `reference`, this means a name or an ID of a resource.

## Subnet creation

The command to create a Subnet takes this form:
```bash
$ safescale network subnet create [options] <network reference> <subnet name>
```

| Option      | Description                                                                                                             |
| ---          |-------------------------------------------------------------------------------------------------------------------------|
| `--cidr`    | Defines the CIDR to use. If not used, SafeScale will choose the first CIDR available by manipulating the netmask part of the Network CIDR. 
|             | For example, if the Network CIDR is set to 172.16.0.0/16, then SafeScale will search for an available CIDR in 172.16.0.0/17. |
| `--gwname`  | Defines the name of the gateway (default: gw-<subnet name>)                                                             |
| `--os`      | Defines the Image to use as Operating System                                                                            |
| `--sizing`  | Defines the sizing of the gateway                                                                                       |
| `--failover` | Tells that 2 gateways and an internal Virtual IP have to be created.                                                    |
|             | These gateways will work in primary/secondary mode, and the default route will be the IP address of the VIP             |
| 

Example:
```bash
$ safescale network subnet create my-net my-subnet
```

## Subnet details

This command,
```bash
$ safescale network subnet inspect my-net my-subnet | jq
```

will display information about the Subnet like this:

```json
{
  "result": {
    "cidr": "192.168.0.0/24",
    "gateway_ids": [
      "859f7332-95d4-4f83-b881-87e5b9363b3e"
    ],
    "gateway_name": "gw-net-vpl",
    "id": "a003465b-96fd-4262-a61b-5583453df5d8",
    "name": "net-vpl",
    "state": 3
  },
  "status": "success"
}
```

### Subnet deletion
Use the command,
```bash
$ safescale network subnet delete my-net my-subnet
```
to delete a Subnet (and its gateway(s)). This command should fail if there are Hosts in Subnet (take attention that Hosts created manually using Cloud Provider UI are not managed by SafeScale, and may also prevent a successful operation)

## Subnet Security Group relationships

### List Security Groups of a Subnet

```bash
$ safescale network subnet security group list my-net my-subnet | jq`
```

### Bind a Security Group to a Subnet

This command,
```bash
$ safescale network subnet security group bind <network reference> <subnet reference> <security group reference>
```

will bind a Security Group to a Subnet, trigerring an update of Hosts attached to the Subnet applying the Security Group rules.

Example:
```bash
$ safescale network subnet security group bind my-net my-subnet my-security-group
```

### Unbind a Security Group from a Subnet

This command,
```bash
$ safescale network subnet security group unbind my-net my-subnet my-security-group
```
will unbind a Security Group from a Subnet, trigerring an update of Hosts attached to the Subnet removing the Security Group rules.

### Disable a Security Group of a Subnet

This command,

```bash
$ safescale network subnet security group disable my-net my-subnet my-security-group
```

will disable the rules of the Security Group on the Subnet, triggering an update on all Hosts attached to the Subnet.

[../internals/SECURITYGROUPS.md#subnet_disable](see this for technical implementation details)

### Enable a Security Group of a Subnet

This command,
```bash
$ safescale network subnet security group enable my-net my-subnet my-security-group
``` 
will enable the Security Group of bound to Subnet, applying the rules to the Hosts attached to the Subnet.

[../internals/SECURITYGROUPS.md#subnet_enable](see this for technical implementation details)
