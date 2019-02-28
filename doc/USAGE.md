# SafeScale usage
<br>
## Content

- [safescaled](#safescaled)
    - [Configuration](#safescaled_conf)
    - [Usage](#safescaled_usage)
- [safescale](#safescale)
    - [Global options](#safescale_globals)
    - [Commands](#safescale_cmds)
        - [tenant](#safescale_tenant)
        - [network](#safescale_network)
        - [host](#safescale_host)
        - [volume](#safescale_volume)
        - [share](#safescale_share)
        - [bucket](#safescale_bucket)
        - [ssh](#safescale_ssh)
        - [cluster](#cluster)

___

SafeScale is composed of 2 parts:

 - a daemon working in background, called [`safescaled`](#safescaled)
 - a client interacting with the daemon, called [`safescale`](#safescale)
<br>

##<a name="safescaled"></a>safescaled

`safescaled` is a daemon and you only need to launch it on your own computer.
The purpose of this daemon is to execute requests ordered by `safescale` client on the providers.
<br>

#### <a name="safescaled_conf"></a>Configuration
To dialog with the different providers, the daemon needs authentication parameters to be able to connect to the underlying provider's API. These credentials are given in the file `tenants.toml` (may also be `tenants.json` or `tenants.yaml`, in their respective corresponding format). This file is searched in order (first file found is used) in the folowing directories:

> - . (current directory)
 - $HOME/.safescale
 - $HOME/.config/safescale
 - /etc/safescale

The content of this configuration file is explained in [TENANTS.md](tenants.md).

Each section `tenants` contains specific authentication parameters for each Cloud Provider.
> - `client` can be one of the available provider's drivers in
    - cloudwatt
    - cloudferro
    - local
    - flexibleengine
    - opentelekom
    - ovh
 - `name` is a logical name representing the tenant

Here is an example of a tenant file:
```yaml
[[tenants]]
  name = "logical_name_for_this_ovh_tenant"
  client = "ovh"

  [tenants.identity]
    ApplicationKey = "your_application_key"
    OpenstackID = "your_login"
    OpenstackPassword = "your_password"

  [tenants.compute]
    Region = "your_region"
    ProjectName = "your_project_name_or_id"

  [tenants.network]
    ProviderNetwork = "Ext-Net"

  [tenants.objectstorage]
    Type = "swift"
    AuthURL = "https://auth.cloud.ovh.net/v2.0"

[[tenants]]
  name = "logical_name_for_this_cloudwatt_tenant"
  client = "cloudwatt"

  [tenants.identity]
    Username = "your_login"
    Password = "your_password"

  [tenants.compute]
    Region = "your_region"
    TenantName = "your_tenant_name_or_id"

  [tenants.objectstorage]
    Type = "swift"

[[tenants]]
  client = "flexibleengine"
  name = "logical_name_for_this_flexibleengine_tenant"

  [tenants.identity]
    Username = "your_login"
    Password = "your_password"
    DomainName = "your_domaine_name"

  [tenants.compute]
    ProjectID = "your_project_id"
    Region = "your_region"

  [tenants.network]
    VPCName = "your_VPC_name"
    VPCCIDR = "your_VPC_cidr"

  [tenants.objectstorage]
    Type = "s3"
    Endpoint = "https://oss.eu-west-0.prod-cloud-ocb.orange-business.com"
    AccessKey = "your_S3_login"
    SecretKey = "your_S3_password"

[[tenants]]
  client = "opentelekom"
  name = "logical_name_for_this_opentelekom_tenant"

  [tenants.identity]
    Username = "your_login"
    Password = "your_password"
    DomainName = "your_domaine_name"

  [tenants.compute]
    ProjectID = "your_project_id"
    Region = "your_region"

  [tenants.network]
    VPCName = "your_VPC_name"
    VPCCIDR = "your_VPC_cidr"

  [tenants.objectstorage]
    Type = "s3"
    Endpoint = "https://obs.eu-de.otc.t-systems.com"
    AccessKey = "your_S3_login"
    SecretKey = "your_S3_password"
```

A detail description of the content of the file tenants.toml can be found in [TENANTS.md](TENANTS.md).
<br>

#### <a name="safescaled_usage"></a>Usage

If you built SafeScale from source, make install will have installed the binaries in $GOPATH/bin.
To launch the SafeScale daemon, simply execute the following command (from a regular user, no need to be root):

```bash
${GOPATH}/bin/safescaled &
```

It should display in your terminal something like this:

```bash
Safescaled version: 19.03.0, build f3973fb5a642b7d93b0f20417631e2706a86c211 (2019/02/25-14:49)
Ready to serve :-)
```

By default, safescaled displays only warnings and errors messages. To have more information, you can use -v to increase verbosity, and -d to use debug mode.
<br><br>
## <a name="safescale"></a>safescale
___
`safescale` is the client part of SafeScale. It consists of a CLI to interact with the safescale daemon to manage cloud infrastructures.

The different available commands can be obtained via the **`--help`** option on each command and are reminded hereafter. _Note that, despite of our efforts, the help got by the CLI might be more accurate and up-to-date than the following descriptions._

Each command returns its results on the standard output in 2 forms according to the expected result type:

- no result is expected: a simple comment about the execution of the comment
- a result is expected: the result is formatted in **JSON** (or null if no result is produced); for eye-candy formatting, you can use `| jq` at the end of the command.

The commands are presented in logical order as if the user wanted to create some machines with a shared storage space.
<br>
#### <a name="safescale_globals"></a>Global options

``safescale`` accepts global_options just before the subcommand, which are :

option | description
----- | -----
`-v` | Increase the verbosity.<br><br>ex: `safescale -v host create ...`
`-d` | Displays debugging information.<br><br>ex: `safescale -d host create ...`

Example:
```bash
$ safescale -v host create myhost
```
<br>
#### <a name="safescale_cmds"></a>Commands

<br>
#### <a name="safescale_tenant"></a>tenant
A tenant must be set before using any other command as it indicates to SafeScale which tenant the command must be executed on. _Note that if only one tenant is defined in the `tenants.toml`, it will be automatically selected while invoking any other command._
The following actions are proposed:

action | description
----- | -----
`safescale tenant list` | List available tenants i.e. those found in the `tenants.toml` file.<br><br>example:<br><br>`$ safescale tenant list`<br>`[{"Name":"TestOvh","Provider":"ovh"}]`
`safescale tenant get` | Display the current tenant used for action commands.<br><br>example:<br><br>`$ safescale tenant get`<br>`{"Name":"TestOvh"}`
`safescale tenant set <tenant_name>` | Set the tenant to use by the next commands. The 'tenant_name' must match one of those present in the `tenants.toml` file (key 'name'). The name is case sensitive.<br><br>example:<br><br> `$ safescale tenant set TestOvh`<br>`Tenant 'TestOvh' set`<br>or<br>`Unable to set tenant 'testovh': Tenant 'testovh' not found in configuration`

<br><br>

#### <a name="safescale_network"></a>network

This command manages networks on the provider side, on which hosts may be attached to (**may** because it's also possible to create a host without attached network but with a public IP address).
In SafeScale, a host is automatically created to act as the gateway for the network. If not given, default values are used to size this gateway.
The following actions are proposed:

action | description
----- | -----
`safescale network create [command_options] <network_name>`<br>ex: `safescale network create example_network`| Creates a network with the given name.<br>`command_options`:<ul><li>`--cidr value` cidr of the network (default: "192.168.0.0/24")</li><li>`--cpu value` Number of CPU for the gateway (default: 1)</li><li>`--ram value` RAM for the gateway (default: 1 Go)</li><li>`--disk value` Disk space for the gateway (default: 100 Mo)</li><li>`--os value` Image name for the gateway (default: "Ubunutu 18.04")</li></ul>success response: `{"ID":"583c6af2-7f44-4e38-b223-0142374f94bd","Name":"example_network","CIDR":"192.168.0.0/24"}`<br><br>failure response: `Could not get network list: rpc error: code = Unknown desc = Network example_network already exists`
`safescale network list [command_options]` | List networks created by SafeScale<br>`command_options`:<ul><li>`--all` List all network existing on the current tenant (not only those created by SafeScale)</li></ul>ex: `[{"ID":"583c6af2-7f44-4e38-b223-0142374f94bd","Name":"example_network","CIDR":"192.168.0.0/24"}]`<br><br>ex (all): `[{"ID":"583c6af2-7f44-4e38-b223-0142374f94bd","Name":"example_network","CIDR":"192.168.0.0/24"},{"ID":"85049bb9-7567-4557-a26b-dc6bad977d68","Name":"other_network","CIDR":"192.168.111.0/28"}]`
`safescale network inspect <network_name_or_id>`<br>ex: `safescale network inspect example_network`| Get info on a network<br><br>success response: `{"ID":"583c6af2-7f44-4e38-b223-0142374f94bd","Name":"example_network","CIDR":"192.168.0.0/24"}`<br><br>failure response: `Could not inspect network fake_network: rpc error: code = Unknown desc = Network 'fake_network' does not exist`
`safescale network delete <network_name_or_id>`<br>ex: `safescale network delete example_network`| Delete the network whose name or id is given<br><br>success response: `Network 'example_network' deleted`<br><br>failure response: `Could not delete network example_network: rpc error: code = Unknown desc = Network example_network does not exist`<br><br>failure response: `Could not delete network example_network: rpc error: code = Unknown desc = Network 'd1f10b4c-37fe-41e4-9370-adaf76756c39' has hosts attached: 2ab6786a-64e8-430a-94a7-e4404a91e7ae 3ed78537-2088-4516-904d-f61c7440e8e1`

<br><br>

#### <a name="safescale_host"></a>host
This command family deals with host management: creation, list, connection, deletion...
The following actions are proposed:

action | description
--- | ---
`safescale [global_options] host create <Host_name> [command_options] `|Creates a new host. This host will be attached on the given network. Note that by default this host is created with a private IP address.<br>`command_options`:<ul><li>`--net <network_name>` specifies the network to connect the host to. Can't be used with `--public`.<li>`--cpu value` Number of CPU for the host (default: 1)</li><li>`--cpu-freq value` CPU frequence (default :0)  -----  [scanner](SCANNER.md) needed</li><li>`--ram value` RAM for the host (default: 1 Go)</li><li>`--disk value` Disk space for the host (default: 100 Mo)</li><li>`--gpu value` Number of GPU for the host (default :0)  ----- [scanner](SCANNER.md) needed</li><li>`--os value` Image name for the host (default: "Ubuntu 18.04")</li><li>`--public` creates the host with public IP; can't be used with `--net`.</li></ul>ex: `safescale host create --net example_network example_host_master`<br><br>success response: `{"ID":"a93ae865-357d-4e40-9834-95dacab38065","Name":"example_host_master","CPU":4,"RAM":15,"Disk":100,"IP":"192.168.0.6","State":2,"PrivateKey":"-----BEGIN RSA PRIVATE KEY-----\n[...]-----END RSA PRIVATE KEY-----\n","GatewayID":"e2d336e7-3cbc-48bc-a5c2-efd5d4ece5c0"}`<br><br>responses failure:`Could not create host 'example_host_master': rpc error: code = Unknown desc = host 'example_host_master' already exists`<br><br>Note:`As most of the providers (ovh, flexible, ...) didn't provide informations`
`safescale host list [options]` | List hosts created by SafeScale<br>`command_options`:<ul><li>`--all` List all existing hosts on the current tenant (not only those created by SafeScale)</li></ul>ex: `[{"ID":"e2d336e7-3cbc-48bc-a5c2-efd5d4ece5c0","Name":"gw_example_network","CPU":4,"RAM":15,"Disk":100,"IP":"abc.def.ghi.jkl","State":2,"PrivateKey":"-----BEGIN RSA PRIVATE KEY-----\n[...]-----END RSA PRIVATE KEY-----\n"},{"ID":"a93ae865-357d-4e40-9834-95dacab38065","Name":"example_host_master","CPU":4,"RAM":15,"Disk":100,"IP":"192.168.0.6","State":2,"PrivateKey":"-----BEGIN RSA PRIVATE KEY-----\n[...]-----END RSA PRIVATE KEY-----\n","GatewayID":"e2d336e7-3cbc-48bc-a5c2-efd5d4ece5c0"}]`<br><br>ex (all): `{"ID":"e2d336e7-3cbc-48bc-a5c2-efd5d4ece5c0","Name":"gw_example_network","CPU":4,"RAM":15,"Disk":100,"IP":"abc.def.ghi.jkl","State":2,"PrivateKey":"-----BEGIN RSA PRIVATE KEY-----\n[...]-----END RSA PRIVATE KEY-----\n"},{"ID":"a93ae865-357d-4e40-9834-95dacab38065","Name":"example_host_master","CPU":4,"RAM":15,"Disk":100,"IP":"192.168.0.6","State":2,"PrivateKey":"-----BEGIN RSA PRIVATE KEY-----\n[...]-----END RSA PRIVATE KEY-----\n","GatewayID":"e2d336e7-3cbc-48bc-a5c2-efd5d4ece5c0"},{"ID":"961843ac-1675-465e-893d-81d090b2bf7f","Name":"other_host","CPU":4,"RAM":15,"Disk":100,"IP":"mno.pqr.stu.vwx","State":2,"PrivateKey":"-----BEGIN RSA PRIVATE KEY-----\n[...]-----END RSA PRIVATE KEY-----\n"}]`
`safescale host inspect <Host_name_or_id>`|Get info on an host<br><br>success response: `{"ID":"2ab6786a-64e8-430a-94a7-e4404a91e7ae","Name":"example_host_master","CPU":4,"RAM":15,"Disk":100,"IP":"192.168.0.5","State":2,"PrivateKey":"-----BEGIN RSA PRIVATE KEY-----\n[...]-----END RSA PRIVATE KEY-----\n","GatewayID":"e2d336e7-3cbc-48bc-a5c2-efd5d4ece5c0"}`<br><br>failure response: `Could not inspect host 'fake_host': rpc error: code = Unknown desc = host fake_host does not exist`
`safescale host ssh <Host_name_or_id>`|Get ssh config to connect to host<br><br>success response:`{"User":"gpac","Host":"192.168.0.5","PrivateKey":"-----BEGIN RSA PRIVATE KEY-----\n[...]-----END RSA PRIVATE KEY-----\n","Port":22,"gateway":{[...]}}`<br><br>response error:`Could not get ssh config for host 'fake_host': rpc error: code = Unknown desc = host 'fake_host' does not exist`
`safescale host delete <Host_name_or_id>`| Delete an host<br><br>success response: `host 'example_host' deleted`<br><br>failure response: `Could not delete host 'example_host': rpc error: code = Unknown desc = host 'example_host' does not exist`
`safescale host check-feature <Host_name_or_id> <feature_name> [command_options]`|Check if a feature is present on the host<br>`command_options`:<ul><li>`-p "<PARAM>=<VALUE>"` Sets the value of a parameter required by the feature</li></ul>ex: `safescale host check-feature myhost remotedesktop`<br><br>success response:`Feature 'remotedesktop' found on host 'myhost'`<br><br>failure response:`Feature 'remotedesktop' not found on host 'myhost'`
`safescale [global_options] host add-feature <Host_name_or_id> <feature_name> [command_options]`| Adds the feature to the host<br>`command_options`:<ul><li>`-p "<PARAM>=<VALUE>"` Sets the value of a parameter required by the feature</li><li>`--skip-proxy` disables the application of (optional) reverse proxy rules inside the feature</ul>ex: `safescale host add-feature myhost remotedesktop`<br><br>success response: `Feature 'remotedesktop' installed successfully on host 'myhost'`
`safescale host delete-feature <Host_name_or_id> <feature_name> [command_options]`| Adds the feature to the host<br>`command_options`:<ul><li>`-p "<PARAM>=<VALUE>"` Sets the value of a parameter required by the feature</li></ul>ex: `safescale host delete-feature myhost remotedesktop`<br><br>success response: `Feature 'remotedesktop' deleted successfully from host 'myhost'`<br><br>failure response may vary

<br><br>

#### <a name="safescale_volume"></a>volume
This command family deals with volume (i.e. block storage) management: creation, list, attachment to an host, deletion...
The following actions are proposed:

action | description
--- | ---
`safescale volume create <volume_name> [command_options] `| Create a volume with the given name on the current tenant using default sizing values.<br>`command_options`:<br><ul><li>`--size value` Size of the volume (in Go) (default: 10)</li><li>`--speed value` Allowed values: SSD, HDD, COLD (default: "HDD")</li></ul>success response: `{"ID":"727204a8-9b15-43c6-b2da-e641a2c90876","Name":"example_volume","Speed":1,"Size":10}`<br><br>failure response: `Could not create volume 'example_volume': rpc error: code = Unknown desc = Volume 'example_volume' already exists`
`safescale volume list`|List available volumes<br><br>success response: `[{"ID":"727204a8-9b15-43c6-b2da-e641a2c90876","Name":"example_volume","Speed":1,"Size":10},{"ID":"eaf46ce8-ef14-4e10-b33f-c1a5c25c5f98","Name":"other_volume","Speed":1,"Size":10}]`
`safescale volume inspect <volume_name_or_id>`|Get info on a volume.<br><br>success response: `{"ID":"727204a8-9b15-43c6-b2da-e641a2c90876","Name":"example_volume","Speed":1,"Size":10}`<br><br>failure response: `Could not get volume 'fake_volume': rpc error: code = Unknown desc = Volume 'fake_volume' does not exist`
`safescale volume attach <volume_name_or_id> [command_options] `|Attach the volume to an host. It mounts the volume on a directory of the host. The directory is created if it does not already exists.<br>`command_options`:<ul><li>`--path value` Mount point of the volume (default: "/shared/<volume_name>)</li><li>`--format value` Filesystem format (default: "ext4")</li><li>`--do-not-format` If possible filesystem is mounted without formating</li></ul>success response: `Volume 'example_volume' attached to host 'example_hos_master'`<br><br>failure response 1: `Could not attach volume 'fake_volume' to host 'example_host': rpc error: code = Unknown desc = No volume found with name or id 'fake_volume'`<br><br>failure response 2: `Could not attach volume 'example_volume' to host 'fake_host': rpc error: code = Unknown desc = No host found with name or id 'fake_host'`
`safescale volume detach <volume_name_or_id> <Host_name_or_id>`|Detach a volume from an host<br><br>success response:`Volume 'example_volume' detached from host 'example_host'`<br><br>failure response 1:`Could not detach volume 'fake_volume' from host 'example_host': rpc error: code = Unknown desc = No volume found with name or id 'fake_volume'`<br><br>failure response 2:`Could not detach volume 'example_volume' from host 'fake_host': rpc error: code = Unknown desc = No host found with name or id 'fake_host'`
`safescale volume delete <volume_name_or_id>`| Delete the volume with the given name.<br><br>success response: `Volume 'eaf46ce8-ef14-4e10-b33f-c1a5c25c5f98' deleted`<br><br>failure response: `Could not delete volume 'other_volume': rpc error: code = Unknown desc = Volume 'other_volume' does not exist`<br><br>failure response: `Could not delete volume '727204a8-9b15-43c6-b2da-e641a2c90876': rpc error: code = Unknown desc = Error deleting volume: Invalid request due to incorrect syntax or missing required parameters.`

<br><br>

#### <a name="safescale_share"></a>share
This command familly deals with share management: creation, list, deletion...
The following actions are proposed:

action | description
--- | ---
`safescale [global_options] share list`|List existing shares<br>response: `[{"Host":"shareserver","ID":"69fd8c3e-2665-4e20-a960-8b13b914752b","Name":"share-1","Path":"/shared/data","Type":"nfs"}]`<br><br>
`safescale [global_options] share inspect <share_name>`|List the nfs server and all clients connected to it.<br><br>success response: `[{"Host":"ea46f11d-1782-4fd8-bdf1-d99a414e0179","ID":"69fd8c3e-2665-4e20-a960-8b13b914752b","Name":"share-1","Path":"/shared/data","Type":"nfs"}]`
`safescale [global_options] share create <Share_name> <host_name_or_id> [command_options] `|Create a nfs server on an host and expose directory<br>`command_options`:<ul><li>`--path value` Path to be exported (default: "/shared/data")</li></ul>
`safescale [global_options] share mount <share_name> <host_name_or_id> [command_options] `|Mount an exported nfs directory on an host<br>`command_options`:<ul><li>`--path value` Path to mount nfs directory on (default: /data)</li></ul>success response: _empty_<br><br>failure response: `Can't mount share 'share-1': failed to find share 'share-1'`<br><br>failure response: `Can't mount share 'share-vpl-1': host 'clientserver' not found`|List all created shares<br><br>
`safescale [global_options] share umount <share_name> <host_name_or_id>`|Unmount an exported nfs directory on an host<br><br>success response: _empty_<br><br>failure response: `Can't unmount share 'share-1': failed to find share 'share-1'`<br><br>failure response: `Can't unmount share 'share-1': host 'clientserver' not found`
`safescale [global_options] share delete <share_name>`|Delete a nfs server by unexposing directory<br><br>success response: _empty_<br><br>failure response: `Failed to find share 'share-1'`

<br><br>

#### <a name="safescale_bucket"></a>bucket
This command familly deals with object storage management: creation, list, mounting as filesystem, deleting...
The following actions are proposed:

action | description
--- | ---
`safescale [global_options] bucket create <bucket_name>`|Create a bucket<br><br>success response: _empty_<br><br>failure response: `Could not create bucket 'example_bucket': rpc error: code = Unknown desc = Container example_container already exists`
`safescale [global_options] bucket list`|List buckets<br><br>response: `{"Buckets":[{"Name":"0.safescale-xxxxx"},{"Name":"example_bucket"}]}`
`safescale [global_options] bucket inspect <bucket_name>`|Get info on a bucket<br><br>success response: `{"Bucket":"example_bucket","Host":{"Name":""},"Path":""}`<br><br>failure response: `Could not inspect bucket 'fake_bucket': rpc error: code = Unknown desc = Error getting bucket fake_bucket: Resource not found`
`safescale b[global_options] ucket mount <Bucket_name> <Host_name_or_id> [command_options] `|Mount a bucket as a filesystem on an host.<br>`command_options`:<ul><li>`--path value` Mount point of the bucket (default: "/buckets/<bucket_name>"</li></ul>success response: `Bucket 'example_bucket' mounted on '/buckets/' on host 'example_host'`<br><br>failure response: `Could not mount bucket 'fake_bucket': rpc error: code = Unknown desc = Error getting bucket fake_bucket: Resource not found`<br><br>failure response: `Could not mount bucket 'example_bucket': rpc error: code = Unknown desc = No host found with name or id 'fake_host'`
`safescale [global_options] bucket umount <bucket_name> <host_name_or_id>`|Umount a bucket from the filesystem of an host.<br><br>success message:`Bucket 'example_bucket' umounted from host 'example_host'`<br><br>failure message: `Could not umount bucket 'fake_bucket': rpc error: code = Unknown desc = Error getting bucket fake_container: Resource not found`
`safescale [global_options] bucket delete <bucket_name>`|Delete a bucket<br><br>success response: _empty_<br><br>failure response: `Could not delete bucket 'fake_bucket': rpc error: code = Unknown desc = Error deleting bucket 'fake_bucket': Resource not found`<br><br>failure response: `Could not delete bucket 'example_bucket': rpc error: code = Unknown desc = Error deleting bucket 'example_bucket': Expected HTTP response code [202 204] when accessing [DELETE https://storage.sbg3.cloud.ovh.net/v1/AUTH_ee1f341c48d24180ab7eaba2625a1e25/example_container], but got 409 instead <html><h1>Conflict</h1><p>There was a conflict when trying to complete your request.</p></html>`

<br><br>

#### <a name="safescale_ssh"></a>ssh
The following commands deals with ssh commands to be executed on an host.
The following actions are proposed:

action | description
--- | ---
`safescale [global_options] ssh run [command_options] <Host name_or_id>`|Run a command on the host<br><br>`command_options`:<ul><li>`-c value` The command to execute</li></ul>Example:<br><br>`$ safescale ssh run -c "ls -la ~" example_host`<br><br>`total 32`<br>`drwxr-xr-x 4 gpac gpac 4096 Jun  5 13:25 .`<br>`drwxr-xr-x 4 root root 4096 Jun  5 13:00 ..`<br>`-rw------- 1 gpac gpac   15 Jun  5 13:25 .bash_history`<br>`-rw-r--r-- 1 gpac gpac  220 Aug 31  2015 .bash_logout`<br>`-rw-r--r-- 1 gpac gpac 3771 Aug 31  2015 .bashrc`<br>`drwx------ 2 gpac gpac 4096 Jun  5 13:01 .cache`<br>`-rw-r--r-- 1 gpac gpac    0 Jun  5 13:00 .hushlogin`<br>`-rw-r--r-- 1 gpac gpac  655 May 16  2017 .profile`<br>`drwx------ 2 gpac gpac 4096 Jun  5 13:00 .ssh`
`safescale [global_options] ssh copy <src> <dest>`|Copy a local file/directory to an host or copy from host to local<br><br>example:<br><br>`$ safescale ssh copy /my/local/file example_Host:/remote/path`
`safescale [global_options] ssh connect <host_name_or_id>`|Connect to the host with interactive shell<br><br>example:<br><br> `$  safescale ssh connect example_host`<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`gpac@example-Host:~$`

<br><br>

#### <a name="safescale_cluster"></a>cluster

This command family deals with cluster management: creation, inspection, deletion, ...
The following actions are proposed:

actions | description
--- | ---
`safescale [global_options] cluster create <cluster_name> -F <cluster_flavor> -N <network_CIDR> [command_options]`|Creates a new cluster.<br>parameters:<ul><li>`<cluster_flavor>` defines the "flavor" of the cluster. Can be BOH (Bunch Of Hosts, without any cluster management layer), SWARM (Docker Swarm cluster)</li><li>`<network_CIDR>` defines the CIDR of the network for the cluster.</li></ul><br>command_options:<ul><li>`-C <complexity>` defines the "complexity" of the cluster, ie how many masters/nodes will be created (depending of cluster flavor). Valid values are `small`, `normal`, `large`.</li><li>`--cpu <value>`| Number of CPU for masters and nodes (default depending of cluster flavor)</li><li>`--ram value` RAM for the host (default: 1 Go)</li><li>`--disk value` Disk space for the host (default depending of cluster flavor)</li><li>`--os value` Image name for the servers (default: "Ubuntu 18.04", may be overriden by a cluster flavor)</li></ul><br>example:<br>`safescale cluster create swarm -F swarm -C small -N 192.168.22.0/24`<br>`{"admin_login":"cladm","admin_password":<admin password>,"cidr":"192.168.22.0/24","complexity":1,"complexity_label":"Small","features":{"installed":{},"disabled":{"proxycache":{}}},"flavor":3,"flavor_label":"SWARM","gateway_ip":"192.168.22.17","last_state":5,"last_state_label":"Created","name":"swarm","network_id":"b4969c87-4c1c-473b-b5c9-3d0eec05c5a7","nodes":{"masters":[{"id":"77e1b68c-6629-4769-b49e-c80167c6e2fb","public_ip":"","private_ip":"192.168.22.72"}],"private_nodes":[{"id":"5634d5fc-e25f-4e1e-b0f6-004b618d21bf","public_ip":"","private_ip":"192.168.22.107"}],"public_nodes":[]},"public_ip":"51.38.226.175","tenant":<tenant name>}`
`safescale [global_options] cluster list` | List clusters created by SafeScale<br><br>example:<br>`safescale cluster list`<br>`[{"admin_login":"cladm","admin_password":<admin password>,"cidr":"192.168.22.0/24","complexity":1,"complexity_label":"Small","features":{"installed":{},"disabled":{"proxycache":{}}},"flavor":3,"flavor_label":"SWARM","gateway_ip":"192.168.22.17","last_state":5,"last_state_label":"Created","name":"swarm","network_id":"b4969c87-4c1c-473b-b5c9-3d0eec05c5a7","nodes":{"masters":[{"id":"77e1b68c-6629-4769-b49e-c80167c6e2fb","public_ip":"","private_ip":"192.168.22.72"}],"private_nodes":[{"id":"5634d5fc-e25f-4e1e-b0f6-004b618d21bf","public_ip":"","private_ip":"192.168.22.107"}],"public_nodes":[]},"public_ip":"51.38.226.175","tenant":<tenant name>}]`
`safescale [global_options] cluster inspect <cluster_name>`|Get info about a cluster<br><br>success response is identical to `safescale cluster create`<br><br>failure response: `Cluster 'removed' not found.`
`safescale [global_options] cluster delete <cluster_name> [command_options]`| Delete a cluster. By default, ask for user confirmation before doing anything<br>`command_options`:<ul><li>`-y` disables the confirmation<br><br>success response: `host 'example_host' deleted`<br><br>failure response: `Could not delete host 'example_host': rpc error: code = Unknown desc = host 'example_host' does not exist`
`safescale [global_options] cluster check-feature <cluster_name> <feature_name> [command_options]`|Check if a feature is present on the cluster<br>`command_options`:<ul><li>`-p "<PARAM>=<VALUE>"` Sets the value of a parameter required by the feature</li></ul>ex: `safescale cluster check-feature swarm docker`<br><br>success response:`Feature 'docker' found on cluster 'swarm'`<br><br>failure response:`Feature 'docker' not found on cluster 'swarm'`
`safescale [global_options] cluster add-feature <cluster_name> <feature_name> [command_options]`|Adds a feature to the cluster<br>`command_options`:<ul><li>`-p "<PARAM>=<VALUE>"` Sets the value of a parameter required by the feature</li><li>`--skip-proxy` disables the application of (optional) reverse proxy rules inside the feature</ul>ex: `safescale cluster add-feature swarm remotedesktop`<br><br>success response: `Feature 'remotedesktop' installed successfully on cluster 'swarm'`<br><br>failure response may vary
`safescale [global_options] cluster delete-feature <cluster_name> <feature_name> [command_options]`|Deletes a feature from a cluster<br>`command_options`:<ul><li>`-p "<PARAM>=<VALUE>"` Sets the value of a parameter required by the feature</li></ul>ex: `safescale cluster delete-feature swarm remote-desktop`<br><br>success response: `Feature 'remote-desktop' deleted successfully from cluster 'swarm'`<br><br>failure response may vary
<br><br>
