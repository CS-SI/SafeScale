# SafeScale usage

## Broker

The SafeScale broker layer is composed of 2 elements:
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
`broker tenant set <tenant_name>`<br><br>ex: `broker tenant set TestOvh` | Set the tenant to use by the next commands. The 'tenant_name' must match one of those present in the `tenants.toml` file (key 'name'). The name is case sensitive.<br>response success: `Tenant 'TestOvh' set`<br> response failure: `Could not get current tenant: rpc error: code = Unknown desc = Unable to set tenant 'testovh': Tenant 'testovh' not found in configuration`

#### network

We first need to create a network on which we will net attach some virtual machines.
A virtual machine is automatically created to act the gateway for the network. If not given, default values are used to define the gateway.

command | description
--- | ---
`broker network create [command options] <network_name>`<br>ex: `broker network create exemple_network`| Creates a network with the given name.<br>Options:<br><ul><li>`--cidr value` cidr of the network (default: "192.168.0.0/24")</li><li>`--cpu value` Number of CPU for the gateway (default: 1)</li><li>`--ram value` RAM for the gateway (default: 1 Mo)</li><li>`--disk value` Disk space for the gateway (default: 100 Mo)</li><li>`--os value` Image name for the gateway (default: "Ubunutu 16.04")</li></ul>response success: `{"ID":"583c6af2-7f44-4e38-b223-0142374f94bd","Name":"exemple_network","CIDR":"192.168.0.0/24"}`<br>response failure: `Could not get network list: rpc error: code = Unknown desc = Network exemple_network already exists`
`broker network list` | List networks created by SafeScale<br>ex: `[{"ID":"583c6af2-7f44-4e38-b223-0142374f94bd","Name":"exemple_network","CIDR":"192.168.0.0/24"}]`
`broker network list --all` | List all network existing on the current tenant (not only those created by SafeScale)<br>ex: `[{"ID":"583c6af2-7f44-4e38-b223-0142374f94bd","Name":"exemple_network","CIDR":"192.168.0.0/24"},{"ID":"85049bb9-7567-4557-a26b-dc6bad977d68","Name":"other_network","CIDR":"192.168.111.0/28"}]`
`broker network inspect <network_name_or_id>`<br>ex: `broker network inspect exemple _network`| Get info on a network<br>response success: `{"ID":"583c6af2-7f44-4e38-b223-0142374f94bd","Name":"exemple_network","CIDR":"192.168.0.0/24"}`<br>response failure: `Could not inspect network fake_network: rpc error: code = Unknown desc = Network 'fake_network' does not exists`
`broker network delete <network_name_or_id>`<br>ex: `broker network delete exemple_network`| Delete the network whose name or id is given<br>response success: `Network 'exemple_network' deleted`<br>response failure: `Could not delete network exemple_network: rpc error: code = Unknown desc = Network exemple_network does not exists`<br>response failure: `Could not delete network exemple_network: rpc error: code = Unknown desc = Network 'd1f10b4c-37fe-41e4-9370-adaf76756c39' has vms attached: 2ab6786a-64e8-430a-94a7-e4404a91e7ae 3ed78537-2088-4516-904d-f61c7440e8e1`

#### vm
TODO

#### volume
TODO
#### nas
TODO
#### container
TODO
#### ssh
TODO

## Perform
TODO