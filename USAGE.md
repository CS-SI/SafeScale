# SafeScale usage

## Broker

The SafeScale broker tool is composed of 2 elements:
 - a daemon working in background
 - a client offering a CLI to interact with the daemon

### Brokerd

Brokerd is a daemon and you only need to launch it on your machine.
The purpose of this daemon is to execute requests from SafeScale broker's client on the providers.

#### Configuration
To dialog with the different providers, the daemon needs authentication parameters to be able to connect to the underlying provider's API. These credentials are given in the file `tenants.toml`. This file is search in order (first file founs is used) in the folowing directories:
 - . (current directory)
 - $HOME/.safescale
 - $HOME/.config/safescale
 - /etc/safescale

The content of this configuration file is presented hereafter. 
One section 'tenants' with specific authentication parameters for each tenant. Specific keys 'client' and 'name' are for SafeScale internal use:
 - `client` must be one of the available provider's drivers in
   - ovh
   - cloudwatt
   - flexibleengine
   - aws
 - `name` is a logical name representing the tenant

```yaml
[[tenants]]
client = "ovh"
name = "logical_name_for_this_tenant"
ApplicationKey = "your_application_key"
OpenstackID = "your_login"
OpenstackPassword = "your_password"
Region = "your_region"
ProjectName = "your_project_name_or_id"

[[tenants]]
client = "cloudwatt"
name = "logical_name_for_this_tenant"
Username = "your_login"
Password = "your_password"
TenantName = "your_tenant_name_or_id"
Region = "your_region"
```
#### Usage

To launch the SafeScale broker's daemon simply execute the following command:
```bash
${GOPATH:-$HOME}/src/github.com/CS-SI/SafeScale/broker/daemon/brokerd &
```
It should display in your terminal (with your current date and time):
```
2018/06/04 14:35:36 Starting server
2018/06/04 14:35:36 Registering services
2018/06/04 14:35:36 Ready to serve :-)
```

### Broker

Broker is the client part of the SafeScale broker layer. It consists of a CLI to interact with the broker daemon to manage clound infrastructures.

The different available commands can be obtained via the '**--help**' option on each command and are reminded hereafter. _Note that, dispite of our efforts, the help got by the CLI might be more accurate and up-to-date than the followings descriptions._

Each command returns its results on the standard output in 2 forms according to the expected result type:
 - no result is expected: a simple comment about the execution of the comment
 - a result is expected: the result is formatted in **JSON** (or null if no result is produced)

The commands are presented in logical order as if the user wanted to create some machines with a shared storage space.

#### tenant
A tenant must be set before using any other command as it indicates to SafeScale which tenant the command must be executed on. _Note that if only one tenant is defined in the `tenants.toml`, it will be automatically set while invoking any other command._
command | description
----- | -----
`broker tenant list` | List available tenants i.e. those found in the `tenants.toml` file.<br>ex: `[{"Name":"TestOvh","Provider":"ovh"}]`
`broker tenant get` | Display the current tenant used for action commands.<br>ex: `{"Name":"TestOvh"}`
`broker tenant set <tenant_name>`<br><br>ex: `broker tenant set TestOvh` | Set the tenant to use by the next commands. The 'tenant_name' must match one of those present in the `tenants.toml` file (key 'name'). The name is case sensitive.<br>success response: `Tenant 'TestOvh' set`<br> failure response: `Could not get current tenant: rpc error: code = Unknown desc = Unable to set tenant 'testovh': Tenant 'testovh' not found in configuration`

#### network

We first need to create a network on which we will net attach some virtual machines.
A virtual machine is automatically created to act as the gateway for the network. If not given, default values are used to define this gateway.

command | description
--- | ---
`broker network create [command options] <network_name>`<br>ex: `broker network create example_network`| Creates a network with the given name.<br>Options:<ul><li>`--cidr value` cidr of the network (default: "192.168.0.0/24")</li><li>`--cpu value` Number of CPU for the gateway (default: 1)</li><li>`--ram value` RAM for the gateway (default: 1 Go)</li><li>`--disk value` Disk space for the gateway (default: 100 Mo)</li><li>`--os value` Image name for the gateway (default: "Ubunutu 16.04")</li></ul>success response: `{"ID":"583c6af2-7f44-4e38-b223-0142374f94bd","Name":"example_network","CIDR":"192.168.0.0/24"}`<br>failure response: `Could not get network list: rpc error: code = Unknown desc = Network example_network already exists`
`broker network list [options]` | List networks created by SafeScale<br>Options:<ul><li>`--all` List all network existing on the current tenant (not only those created by SafeScale)</li></ul>ex: `[{"ID":"583c6af2-7f44-4e38-b223-0142374f94bd","Name":"example_network","CIDR":"192.168.0.0/24"}]`<br>ex (all): `[{"ID":"583c6af2-7f44-4e38-b223-0142374f94bd","Name":"example_network","CIDR":"192.168.0.0/24"},{"ID":"85049bb9-7567-4557-a26b-dc6bad977d68","Name":"other_network","CIDR":"192.168.111.0/28"}]`
`broker network inspect <network_name_or_id>`<br>ex: `broker network inspect example _network`| Get info on a network<br>success response: `{"ID":"583c6af2-7f44-4e38-b223-0142374f94bd","Name":"example_network","CIDR":"192.168.0.0/24"}`<br>failure response: `Could not inspect network fake_network: rpc error: code = Unknown desc = Network 'fake_network' does not exists`
`broker network delete <network_name_or_id>`<br>ex: `broker network delete example_network`| Delete the network whose name or id is given<br>success response: `Network 'example_network' deleted`<br>failure response: `Could not delete network example_network: rpc error: code = Unknown desc = Network example_network does not exists`<br>failure response: `Could not delete network example_network: rpc error: code = Unknown desc = Network 'd1f10b4c-37fe-41e4-9370-adaf76756c39' has vms attached: 2ab6786a-64e8-430a-94a7-e4404a91e7ae 3ed78537-2088-4516-904d-f61c7440e8e1`

#### vm
This command familly deals with virtual machines management: creation, list, connection, deletion...
The following commands allow this management.
command | description
--- | ---
`broker vm create [command options] <VM_name>`|Creates a new VM. This VM will be attached on the given network. Note that by default this VM is created with a public IP address.<br>Options:<ul><li>`--net value` Name (or id) of the network to attache the VM to. This option is **mandatory**</li><li>`--cpu value` Number of CPU for the VM (default: 1)</li><li>`--ram value` RAM for the VM (default: 1 Go)</li><li>`--disk value` Disk space for the VM (default: 100 Mo)</li><li>`--os value` Image name for the VM (default: "Ubuntu 16.04")</li><li>`--private` Create the VM with no public IP</li></ul>ex: `broker vm create --net example_network example_vm_master`<br>success response: `{"ID":"a93ae865-357d-4e40-9834-95dacab38065","Name":"example_vm_master","CPU":4,"RAM":15,"Disk":100,"IP":"192.168.0.6","State":2,"PrivateKey":"-----BEGIN RSA PRIVATE KEY-----\n[...]-----END RSA PRIVATE KEY-----\n","GatewayID":"e2d336e7-3cbc-48bc-a5c2-efd5d4ece5c0"}`<br>responses failure:`Could not create vm 'example_vm_master': rpc error: code = Unknown desc = VM 'example_vm_master' already exists`
`broker vm list [options]` | List VMs created by SafeScale<br>Options:<ul><li>`--all` List all existing VMs on the current tenant (not only those created by SafeScale)</li></ul>ex: `[{"ID":"e2d336e7-3cbc-48bc-a5c2-efd5d4ece5c0","Name":"gw_example_network","CPU":4,"RAM":15,"Disk":100,"IP":"abc.def.ghi.jkl","State":2,"PrivateKey":"-----BEGIN RSA PRIVATE KEY-----\n[...]-----END RSA PRIVATE KEY-----\n"},{"ID":"a93ae865-357d-4e40-9834-95dacab38065","Name":"example_vm_master","CPU":4,"RAM":15,"Disk":100,"IP":"192.168.0.6","State":2,"PrivateKey":"-----BEGIN RSA PRIVATE KEY-----\n[...]-----END RSA PRIVATE KEY-----\n","GatewayID":"e2d336e7-3cbc-48bc-a5c2-efd5d4ece5c0"}]`<br>ex (all): `{"ID":"e2d336e7-3cbc-48bc-a5c2-efd5d4ece5c0","Name":"gw_example_network","CPU":4,"RAM":15,"Disk":100,"IP":"abc.def.ghi.jkl","State":2,"PrivateKey":"-----BEGIN RSA PRIVATE KEY-----\n[...]-----END RSA PRIVATE KEY-----\n"},{"ID":"a93ae865-357d-4e40-9834-95dacab38065","Name":"example_vm_master","CPU":4,"RAM":15,"Disk":100,"IP":"192.168.0.6","State":2,"PrivateKey":"-----BEGIN RSA PRIVATE KEY-----\n[...]-----END RSA PRIVATE KEY-----\n","GatewayID":"e2d336e7-3cbc-48bc-a5c2-efd5d4ece5c0"},{"ID":"961843ac-1675-465e-893d-81d090b2bf7f","Name":"other_vm","CPU":4,"RAM":15,"Disk":100,"IP":"mno.pqr.stu.vwx","State":2,"PrivateKey":"-----BEGIN RSA PRIVATE KEY-----\n[...]-----END RSA PRIVATE KEY-----\n"}]`
`broker vm inspect <VM_name_or_id>`|Get info on a VM<br>success response: `{"ID":"2ab6786a-64e8-430a-94a7-e4404a91e7ae","Name":"example_vm_master","CPU":4,"RAM":15,"Disk":100,"IP":"192.168.0.5","State":2,"PrivateKey":"-----BEGIN RSA PRIVATE KEY-----\n[...]-----END RSA PRIVATE KEY-----\n","GatewayID":"e2d336e7-3cbc-48bc-a5c2-efd5d4ece5c0"}`<br>failure response: `Could not inspect vm 'fake_vm': rpc error: code = Unknown desc = VM fake_vm does not exists`
`broker vm ssh <VM_name_or_id>`|Get ssh config to connect to VM<br>success response:`{"User":"gpac","Host":"192.168.0.5","PrivateKey":"-----BEGIN RSA PRIVATE KEY-----\n[...]-----END RSA PRIVATE KEY-----\n","Port":22,"gateway":{[...]}}`<br>response error:`Could not get ssh config for vm 'fake_vm': rpc error: code = Unknown desc = VM 'fake_vm' does not exists`
`broker vm delete <VM_name_or_id>`| Delete a VM<br>success response: `VM 'example_vm' deleted`<br>failure response: `Could not delete vm 'example_vm': rpc error: code = Unknown desc = VM 'example_vm' does not exists`

#### volume
This command familly deals with volume (i.e. block storage) management: creation, list, attachment to a VM, deletion... The following commands allow this management.

command | description
--- | ---
`broker volume create [options] <volume_name>`| Create a volume with the given name on the current tenant using default sizing values.<br>Options:<br><ul><li>`--size value` Size of the volume (in Go) (default: 10)</li><li>`--speed value` Allowed values: SSD, HDD, COLD (default: "HDD")</li></ul>success response: `{"ID":"727204a8-9b15-43c6-b2da-e641a2c90876","Name":"example_volume","Speed":1,"Size":10}`<br>failure response: `Could not create volume 'example_volume': rpc error: code = Unknown desc = Volume 'example_volume' already exists`
`broker volume list`|List available volumes<br>success response: `[{"ID":"727204a8-9b15-43c6-b2da-e641a2c90876","Name":"example_volume","Speed":1,"Size":10},{"ID":"eaf46ce8-ef14-4e10-b33f-c1a5c25c5f98","Name":"other_volume","Speed":1,"Size":10}]`
`broker volume inspect <volume_name_or_id>`|Get info on a volume.<br>success response: `{"ID":"727204a8-9b15-43c6-b2da-e641a2c90876","Name":"example_volume","Speed":1,"Size":10}`<br>failure response: `Could not get volume 'fake_volume': rpc error: code = Unknown desc = Volume 'fake_volume' does not exists`
`broker volume attach [options] <volume_name_or_id>`|Attach the volume to a VM. It mounts the volume on a directory of the VM. The directory is created if it does not already exists.<br>Options:<ul><li>`--path value` Mount point of the volume (default: "/shared/<volume_name>)</li><li>`--format value` Filesystem format (default: "ext4")</li></ul>success response: `Volume 'example_volume' attached to vm 'example_vm_master'`<br>failure response 1: `Could not attach volume 'fake_volume' to VM 'example_vm': rpc error: code = Unknown desc = No volume found with name or id 'fake_volume'`<br>failure response 2: `Could not attach volume 'example_volume' to VM 'fake_vm': rpc error: code = Unknown desc = No VM found with name or id 'fake_vm'`
`broker volume detach <volume_name_or_id> <vm_name_or_id>`|Detach a volume from a VM<br>success response:`Volume 'example_volume' detached from VM 'example_vm'`<br>failure response 1:`Could not detach volume 'fake_volume' from VM 'example_vm': rpc error: code = Unknown desc = No volume found with name or id 'fake_volume'`<br>failure response 2:`Could not detach volume 'example_volume' from VM 'fake_vm': rpc error: code = Unknown desc = No VM found with name or id 'fake_vm'`
`broker volume delete <volume_name_or_id>`| Delete the volume with the given name.<br>success response: `Volume 'eaf46ce8-ef14-4e10-b33f-c1a5c25c5f98' deleted`<br>failure response: `Could not delete volume 'other_volume': rpc error: code = Unknown desc = Volume 'other_volume' does not exists`<br>failure response: `Could not delete volume '727204a8-9b15-43c6-b2da-e641a2c90876': rpc error: code = Unknown desc = Error deleting volume: Invalid request due to incorrect syntax or missing required parameters.`

#### nas
This command familly deals with nas management: creation, list, deletion... The following commands allow this management:
command | description
--- | ---
`broker nas create [options] <Nas_name> <VM_name_or_id>`|Create a nfs server on a VM and expose directory<br>Options:<ul><li>`--path value` Path to be exported (default: "/shared/data")</li></ul>
`broker nas mount [options] <NAS_name> <VM_name_or_id>`|Mount an exported nfs directory on a VM<br>Options:<ul><li>`--path value` Path to mount nfs directory on (default: /data)</li></ul>success response: _empty_<br>failure response: `Could not mount nfs directory: rpc error: code = Unknown desc = Unable to find Nas 'fake_nas'`<br>failure response: `Could not mount nfs directory: rpc error: code = Unknown desc = Unable to find VM 'fake_vm'`
`broker nas list`|List all created NAS<br>response: `[{"Nas":{"Name":"example_nas"},"VM":{"ID":"a8dd08af-de24-4ba5-b8ee-e9567188e6af"},"path":"/shared/data","isServer":true}]`
`broker nas inspect <NAS_name>`|List the nfs server ans all clients connected to it.<br>success response: `[{"Nas":{"Name":"example_nas"},"VM":"ID":"a8dd08af-de24-4ba5-b8ee-e9567188e6af"},"path":"/shared/data","isServer":true},{"Nas":{"Name":"example_nas"},"VM":{"ID":"81419528-bd4a-427b-a5e6-7d63a1459b8d"},"path":"/data"}]`
`broker nas umount <NAS_name> <VM_name_or_id>`|Umount an exported nfs directory on a VM<br>success response: _empty_<br>failure response: `Could not umount nfs directory: rpc error: code = Unknown desc = Unable to find Nas 'fake_nas'`<br>failure response: `Could not umount nfs directory: rpc error: code = Unknown desc = Unable to find VM 'fake_vm'`
`broker nas delete <Nas_name>` | Delete a nfs server by unexposing directory<br>success response: _empty_<br>failure response: `Could not create nas: rpc error: code = Unknown desc = NAS 'example_nas' already exists`<br>failure response: `Could not create nas: rpc error: code = Unknown desc = No VM found with name or id 'fake_vm'`

#### container
This command familly deals with objetc storage management: creation, list, mounting as filesystem, deleting... The following commands allow this management:
command | description
--- | ---
`broker container create <Container_name>`|Create a container<br>success response: _empty_<br>failure response: `Could not create container 'example_container': rpc error: code = Unknown desc = Container example_container alredy exists`
`broker container list`|List containers<br>response: `{"Containers":[{"Name":"0.safescale"},{"Name":"example_container"}]}`
`broker container inspect <container_name>`|Get info on a container<br>success response: `{"Container":"example_container","VM":{"Name":""},"Path":""}`<br>failure response: `Could not inspect container 'fake_container': rpc error: code = Unknown desc = Error getting container fake_container: Resource not found`
`broker container mount [options] <container_name> <VM_name_or_id>`|Mount a container on the filesusteme of a VM.<br>Options:<ul><li>`--path value` Mount point of the container (default: "/containers/<container_name>"</li></ul>success response: `Container 'example_container' mounted on '/containers/' on VM 'example_vm'`<br>failure response: `Could not mount container 'fake_container': rpc error: code = Unknown desc = Error getting container fake_container: Resource not found`<br>failure response: `Could not mount container 'example_container': rpc error: code = Unknown desc = No VM found with name or id 'fake_vm'`
`broker container umount <container_name> VM_name_or_id>`|Umount a container from the filesystem of a VM.<br>success message:`Container 'example_container' umounted from VM 'example_vm'`<br>failure message: `Could not umount container 'fake_container': rpc error: code = Unknown desc = Error getting container fake_container: Resource not found`
`broker container delete <container_name>`|Delete a container<br>success response: _empty_<br>failure response: `Could not delete container 'fake_container': rpc error: code = Unknown desc = Error deleting container fake_container: Resource not found`<br>failure response: `Could not delete container 'example_container': rpc error: code = Unknown desc = Error deleting container example_container: Expected HTTP response code [202 204] when accessing [DELETE https://storage.sbg3.cloud.ovh.net/v1/AUTH_ee1f341c48d24180ab7eaba2625a1e25/example_container], but got 409 instead <html><h1>Conflict</h1><p>There was a conflict when trying to complete your request.</p></html>`
#### ssh
command | description
--- | ---
`broker ssh run [options] <VM_name_or_id>`|Run a command on the VM<br>Options:<ul><li>`-c value` The command to execute</li></ul>ex: `broker ssh run -c "ls -la ~" example_vm`<br>response:<br>total 32<br>drwxr-xr-x 4 gpac gpac 4096 Jun  5 13:25 .<br>drwxr-xr-x 4 root root 4096 Jun  5 13:00 ..<br>-rw------- 1 gpac gpac   15 Jun  5 13:25 .bash_history<br>-rw-r--r-- 1 gpac gpac  220 Aug 31  2015 .bash_logout<br>-rw-r--r-- 1 gpac gpac 3771 Aug 31  2015 .bashrc<br>drwx------ 2 gpac gpac 4096 Jun  5 13:01 .cache<br>-rw-r--r-- 1 gpac gpac    0 Jun  5 13:00 .hushlogin<br>-rw-r--r-- 1 gpac gpac  655 May 16  2017 .profile<br>drwx------ 2 gpac gpac 4096 Jun  5 13:00 .ssh
`broker ssh copy <src> <dest>`|Copy a local file/directory to a VM or copy from VM to local<br>ex: `broker ssh copy /my/local/file example_vm:/remote/path`
`broker ssh connect <VM_name_or_id>`|Connect to the VM with interactive shell<br>ex: ` broker ssh connect example_vm`<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`gpac@example-vm:~$`

## Perform
TODO