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