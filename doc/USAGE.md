# SafeScale usage
<br>

## Content

- [SafeScale usage](#content)
  - [Introduction](#intro)
  - [safescaled](#safescaled)
      - [Configuration](#safescaled_config)
      - [Usage](#safescaled_usage)
      - [Options](#safescaled_options)
      - [Environment variables](#safescaled_env)
  - [safescale](#safescale)
      - [Host sizing definition](#safescale_sizing)
      - [Global options](#safescale_globals)
      - [Commands](#commands)
         - [tenant](#tenant)
         - [network](#network)
         - [subnet](#subnet)
         - [host](#host)
         - [volume](#volume)
         - [share](#share)
         - [bucket](#bucket)
         - [ssh](#ssh)
         - [cluster](#cluster)
      - [Environnement variables](#safescale_env)

___

## <a name="intro">Introduction</a>
SafeScale is composed of 2 parts:

 - a daemon working in background, called [`safescaled`](#safescaled)
 - a client interacting with the daemon, called [`safescale`](#safescale)
<br>

## <a name="safescaled">safescaled</a>

`safescaled` is a daemon and you only need to launch it on your own computer.
The purpose of this daemon is to execute requests ordered by `safescale` client on the providers.
<br>
It is composed internally of 2 layers:
- `Infra` which manages Cloud Provider resources with an abstraction layer
- `Platform` which allows creating and managing clusters

#### <a name="safescaled_config">Configuration</a>

To dialog with the different providers, the daemon needs authentication parameters to be able to connect to the underlying provider's API.
These credentials are given in the file `tenants.toml` (may also be `tenants.json` or `tenants.yaml`, in their respective corresponding format).
This file is searched in order (first file found is used) in the following directories:

> - . (current directory)
> - $HOME/.safescale
> - $HOME/.config/safescale
> - /etc/safescale

The content of this configuration file is explained in [TENANTS.md](TENANTS.md).

Each `tenants` section contains specific authentication parameters for each Cloud Provider.
> - `client` can be one of the available provider drivers in:
>    - aws
>    - cloudferro
>    - flexibleengine
>    - gcp
>    - local (currently broken, not compiled by default, cf this [documentation](LIBVIRT_PROVIDER.md))
>    - openstack (pure OpenStack support)
>    - outscale
>    - opentelekom
>    - outscale
>    - ovh
> - `name` is a logical name representing the tenant
>

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
    AuthURL = "https://auth.cloud.ovh.net/v3"

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
<br>

#### <a name="safescaled_usage">Usage</a>

If you built SafeScale from source, `make install` will install the binaries in $GOPATH/bin.
To launch the SafeScale daemon, simply execute the following command (from a regular user, no need to be root):

```bash
$ ${GOPATH}/bin/safescaled &
```
or if `${GOPATH}/bin` is in your `PATH`:

```bash
$ safescaled &
```

It should display in your terminal something like this:

```bash
Safescaled version: 21.03.0, build f3973fb5a642b7d93b0f20417631e2706a86c211 (2021/03/25-14:49)
Ready to serve :-)
```

By default, `safescaled` displays only warnings and errors messages. To have more information, you can use `-v` to increase verbosity, and `-d` to use debug mode (`-d -v` will produce A LOT of messages, it's for debug purposes).
<br><br>

#### <a name="safescaled_options">Options</a>

<table>
<thead><tr><th align="left" style="width: 350px">Option</th><th align="left" style="min-width:650px">Description</th></tr></thead>
<tbody>
<tr valign="top">
  <td><code>--verbose|-v</code></td>
  <td>Increase the verbosity.<br><br>ex: <code>safescale -v host create ...</code></td>
</tr>
<tr valign="top">
  <td><code>--debug|-d</code></td>
  <td>Displays debugging information.<br><br>ex: <code>safescale -d host create ...</code></td></td>
</tr>
<tr valign="top">
  <td><code>--listen|-l</code></td>
  <td>defines on what interface and what port safescaled will listen; default is <code>localhost:50051</code></td>
</tr>
</tbody>
</table>

Examples:
```bash
$ safescaled 
```
will start the daemon, listening on `localhost` on default port `50051`; it will be reachable only from the same host.
<br>
```bash
$ safescaled -v -l :50000
```
will start the daemon, listening on all interfaces and on port `50000` (instead of default port 50051)
<br>

<u>Note</u>: `-d -v` will display far more debugging information than simply `-d` (used to trace what is going on in details)

#### <a name="safescaled_env">Environment variables</a>

You can also set some parameters of `safescaled` using environment variables, which are :
- `SAFESCALED_LISTEN`: equivalent to `--listen`, allows to define on what interface and/or what port `safescaled` has to listen on; used also by `safescale` to reach the daemon
- `SAFESCALE_METADATA_SUFFIX`: allows to specify a suffix to add to the name of the Object Storage bucket used to store SafeScale metadata on the tenant.
  This allows to "isolate" metadata between different users of SafeScale on the same tenant (useful in development for example). There is no equivalent command line parameter.

___

## <a name="safescale">safescale</a>

`safescale` is the client part of SafeScale. It consists of a CLI to interact with the SafeScale daemon to manage cloud infrastructures.

The different available commands can be obtained via the **`--help`** option on each command and are listed hereafter. Note that, despite our efforts, the help displayed by the CLI might be more accurate and up-to-date than the following descriptions.

Each command returns its results on the standard output in 2 forms according to the expected result type:

- no result is expected: a simple comment about the execution of the command
- a result is expected: the result is formatted in **JSON** (or null if no result is produced); for eye-candy formatting, you can use `| jq` at the end of the command.
- outputs are expected: the outputs are displayed in sync with the work done on the remote side (for example, `safescale platform kubectl` command)

Each command has an exit status which is 0 if it succeeded, and !=0 if failed. If the command displays a result in JSON format, the JSON code contains the same exit code.

<br>

#### <a name="safescale_sizing">Host sizing definition</a>

In multiple occasions, it will be necessary to define the Host sizing required. This sizing allows to find the Host templates that match on Cloud Provider side.

The format used by this string representation is: <pre>&lt;component&gt;&lt;operator&gt;&lt;value&gt;[,...]</pre>

where:
<ul>
  <li><code>&lt;component&gt;</code> can be:
      <ul>
        <li><code>cpu</code></li>
        <li><code>cpufreq</code> (<a href="SCANNER.md">scanner</a> needed)</li>
        <li><code>gpu</code> (<a href="SCANNER.md">scanner</a> needed)</li>
        <li><code>ram</code></li>
        <li><code>disk</code>
      </ul>
  </li><br>
  <li><code>&lt;operator&gt;</code> can be:
      <ul>
        <li><code>=</code> means exactly <code>&lt;value&gt;</code></li>
        <li><code>~</code> means between <code>&lt;value&gt;</code> and 2x<code>&lt;value&gt;</code> (not available for component <code>&lt;disk&gt;</code>)</li>
        <li><code>&lt;</code> means strictly lower than <code>&lt;value&gt;</code> (not available for component <code>&lt;disk&gt;</code>)</li>
        <li><code>&lt;=</code> means lower or equal to <code>&lt;value&gt;</code> (not available for component <code>&lt;disk&gt;</code>)</li>
        <li><code>&gt;</code> means strictly greater than <code>&lt;value&gt;</code> (not available for component <code>&lt;disk&gt;</code>)</li>
        <li><code>&gt;=</code> means greater or equal to <code>&lt;value&gt;</code></li>
      </ul>
  </li><br>
  <li><code>&lt;value&gt;</code> can be:
      <ul>
        <li>an integer
        <li>a float
        <li>an including interval <code>[&lt;lower_value&gt;-&lt;upper_value&gt;]</code></li>
      </ul>
  </li>
</ul>
Each <code>&lt;component&gt;</code> accepts <code>&lt;value&gt;</code> following these rules:
<ul>
  <li><code>&lt;cpu&gt;</code> is expecting an integer as number of cpu cores, or an interval with minimum and maximum number of cpu cores</li>
  <li><code>&lt;cpufreq&gt;</code> is expecting an integer as minimum cpu frequency in MHz</li>
  <li><code>&lt;gpu&gt;</code> is expecting an integer as number of GPU (scanner would have been run first to be able to determine which template proposes GPU)</li>
  <li><code>&lt;ram&gt;</code> is expecting a float as memory size in GB, or an interval with minimum and maximum memory size</li>
  <li><code>&lt;disk&gt;</code> is expecting an integer as system disk size in GB</li>
</ul>
<u>examples</u>:
<ul>
  <li><code>"cpu <= 4, ram <= 10, disk >= 100"</code><br>Match any Host template with at most 4 cores,at most 10 GB of ram  and at least 100 GB of system disk</li>
  <li><code>"cpu ~ 4, ram = [14-32]"</code><br>Match any Host template with between 4 and 4x2=8 cores, between 14 and 32 GB of ram (it's identical to <code>"cpu=[4-8], ram=[14-32]"</code>)</li>
  <li><code>"cpu <= 8, ram ~ 16"</code><br>Match any Host template with at most 8 cores and between 16 and 16x2=32 GB of ram</li>
</ul>

Every time you will see <code>&lt;sizing&gt;</code> in this document, you will have to refer to this format.
<br><br>

#### <a name="safescale_globals">Global options</a>

`safescale` accepts global options just before the subcommand, which are:

<table>
<thead><tr><td style="min-width:350px">Option</td><td style="width:650px">Description</td></tr></thead>
<tbody>
<tr>
  <td valign="top"><code>--verbose|-v</code></td>
  <td>Increase the verbosity.<br><br>
      example: <code>safescale -v host create ...</code>
  </td>
</tr>
<tr>
  <td valign="top"><code>--debug|-d</code></td>
  <td>Displays debugging information.<br><br>
      <u>example</u>: <code>safescale -d host create ...</code>
  </td>
</tr>
</tbody>
</table>

Example:
```bash
$ safescale -v network create --cidr 192.168.1.0/24 mynetwork 
```
<br>

#### <a name="safescale_commands">Commands</a>

There are 3 categories of commands:
- the one dealing with tenants (aka cloud providers): [tenant](#tenant)
- the ones dealing with infrastructure resources: [network](#network), [subnet](#subnet), [host](#host), [volume](#volume), [share](#share), [bucket](#bucket), [ssh](#ssh)
- the one dealing with clusters: [cluster](#cluster)

The commands are presented in logical order as if the user wanted to create some servers with a shared storage space.

<u>Note</u>: for clarity, the json results are beautified (as if the example is called with `| jq`); real outputs are one-liners.

#### <a name="tenant">tenant</a>

A tenant must be set before using any other command as it indicates to SafeScale which tenant the command must be executed on. _Note that if only one tenant is defined in the `tenants.toml`, it will be automatically selected while invoking any other command.<br>
The following actions are proposed:

<table>
<thead><td><div style="width:350px"><b>Action</b></div></td><td><div style="min-width: 650px"><b>Description</b></div></td></thead>
<tbody>
<tr>
  <td valign="top"><code>safescale tenant list</code></td>
  <td>List available tenants i.e. those found in the <code>tenants.toml</code>code> file.<br><br>
      <u>example</u>:
      <pre>$ safescale tenant list</pre>
      response:
      <pre>
{
    "result": {
        "name": "TestOVH"
    },
    "status":"success"
}
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale tenant get</code></td>
  <td>Display the current tenant used for action commands.<br><br>
      <u>example</u>:
      <pre>$ safescale tenant get</pre>
      response when tenant set:
      <pre>
{
    "result": {
        "name":"TestOVH"
    },
    "status": "success"
}
      </pre>
      response when tenant not set:
      <pre>
{
    "error": {
        "exitcode": 6,
        "message": "Cannot get tenant: no tenant set"
    },
    "result": null,
    "status": "failure"
}
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale tenant set &lt;tenant_name&gt;</code></td>
  <td>Set the tenant to use by the next commands. The <code>&lt;tenant_name&gt;</code> must match one of those present in
      the <code>tenants.toml</code> file, from key <code>name</code>). The name is case sensitive.<br><br>
      <u>example</u>:
      <pre>$ safescale tenant set TestOvh</pre>
      response on success:
      <pre>
{
  "result": null,
  "status": "success"
}
      </pre>
      response on failure:
      <pre>
{
  "error": {
    "exitcode": 6,
    "message": "Unable to set tenant 'TestOvh': tenant 'TestOvh' not found in configuration"
  },
  "result": null,
  "status": "failure"
}
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><a name="tenant_scan"><code>safescale tenant scan &lt;tenant_name&gt;</code></a></td>
  <td>REVIEW_ME: Scan the given tenant <code>&lt;tenant_name&gt;</code> for templates (see <a href="SCANNER.md">scanner documentation</a> for more details)</td>
</tr>
</tbody>
</table>

---
#### <a name="template">template</a>

A template represents a predefined host sizing proposed by Cloud Provider.
The following actions are available:

<table>
<thead><td><div style="width:350px"><b>Action</b></div></td><td><div style="min-width:650px"><b>Description</b></div></td></thead>
<tbody>
<tr>
  <td valign="top"><code>safescale template list</code></td>
  <td>List available templates from the current tenant.<br><br>
      <u>example</u>:
      <pre>$ safescale template list</pre>
      response:
      <pre>
{
  "result": [
    {
      "cores": 16,
      "disk": 400,
      "id": "0526e13e-dad5-473f-ad61-2f15e0db2a15",
      "ram": 240
    }
  ],
  "status": "success"
}
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale template inspect &lt;template_name&gt;</code></td>
  <td>Display information about a template.<br><br>
      <u>example</u>:
      <pre>safescale template inspect s1-4</pre>
      response on success (without scan):<pre>
{
  "result": [
    {
      "cores": 1,
      "disk": 20,
      "id": "cbef4222-84ff-4f8b-ba40-e5ba85cfbb53",
      "name": "s1-4",
      "ram": 4,
    }
  ],
  "status": "success"
}
      </pre>
      response on success (after scan):<pre>
{
  "result": [
    {
      "cores": 1,
      "disk": 20,
      "id": "cbef4222-84ff-4f8b-ba40-e5ba85cfbb53",
      "name": "s1-4",
      "ram": 4,
      "scanned": {
        "cpu_arch": "x86_64",
        "cpu_frequency_Ghz": 2.39998,
        "cpu_model": "Intel Core Processor (Haswell, no TSX)",
        "disk_size_Gb": 20,
        "hypervisor": "KVM",
        "image_id": "c48cd747-14be-4e73-9a8b-6c9a1bec6ceb",
        "image_name": "Ubuntu 20.04",
        "last_updated": "Wednesday, 24-Feb-21 18:53:22 CET",
        "main_disk_speed_MBps": 228.61,
        "main_disk_type": "HDD",
        "number_of_core": 1,
        "number_of_cpu": 1,
        "number_of_socket": 1,
        "ram_size_Gb": 3.75,
        "sample_net_speed_KBps": 17.827375,
        "template_id": "c48cd747-14be-4e73-9a8b-6c9a1bec6ceb",
        "template_name": "s1-4",
        "tenant_name": "ovh"
      }
    }
  ],
  "status": "success"
}
      </pre>
      response on failure:<pre>
{
  "error": {
    "exitcode": 6,
    "message": "Cannot inspect tenant: template named 's1-4' not found"
  },
  "result": null,
  "status": "failure"
}
      </pre>
  </td>
</tr>
</tbody>
</table>
<br>

--- 
#### <a name="network">network</a>

This command manages `Networks`, `Subnets`and `SecurityGroups` on the provider side. In some Cloud Providers terminology, `Network` can be called **VPC** (FlexibleEngine, AWS, ...).

Before release v21.03, Cloud Provider networks and subnets were melted into a SafeScale `Network`. Since release v21.03, Subnets are introduced.
For compatibility reason, default behavior of `safescale network` has been maintained as before, creating by default a `Subnet` named as the `Network` with a CIDR derived from the one of the Network.
For example, `safescale network create --cidr 172.16.0.0/16 my-net` will create a `Network` with a CIDR of 172.16.0.0/16 <u>and</u> a `Subnet` inside the `Network` with a CIDR of 172.16.0.0/17.

Since v21.03, it's now possible to create a `Network` without default `Subnet`, using `--empty` flag, leaving the responsibility of `Subnet` creation to the user. If `--empty` is used, the flags `--gwname`, `--os`, `--gw-sizing` and `--failover` are meaningless.

A `Network` being the owner of a `SecurityGroup`, the commands relative to `SecurityGroup` resides inside `safescale network security group`.

The following actions are proposed:

<table>
<thead><td><div style="width:350px"><b>Action</b></div></td><td><div style="min-width:650px"><b>Description</b></div></td></thead>
<tbody>
<tr>
  <td valign="top"><code>safescale network create [command_options] &lt;network_name&gt;</code></td>
  <td>Creates a network with the given name.<br><br>
      <code>command_options</code>:
      <ul>
        <li><code>--cidr &lt;cidr&gt;</code>
            CIDR of the network (default: "192.168.0.0/24")</li>
        <li><code>--empty</code>
            do not create a default Subnet in the Network<br>
        </li>
        <u>Note</u>: following options are meaningful only if <code>--empty</code> is not used
        <li><code>--gwname &lt;host_name&gt;</code>
            Name of the gateway (<code>gw-&lt;subnet_name&gt;</code> by default)</li>
        <li><code>--os "&lt;os_name&gt;"</code>
            Image name for the gateway (default: "Ubuntu 20.04")</li>
        <li><code>--failover</code>
            creates 2 gateways for the network and a Virtual IP used as internal default route for the automatically created <code>Subnet</code></li>
        <li><code>--sizing|-S &lt;sizing&gt;</code> Describes sizing of gateway (refer to <a href="#safescale_sizing">Host sizing definition</a>a> paragraph for details)</li>
      </ul><br>
      <u>example</u>:
        <pre>$ safescale network create example_network</pre>
        response on success:
        <pre>
{
  "result": {
    "cidr": "192.168.0.0/24",
    "gateway_id": "48112419-3bc3-46f5-a64d-3634dd8bb1be",
    "id": "76ee12d6-e0fa-4286-8da1-242e6e95844e",
    "name": "example_network",
    "virtual_ip": {}
  },
  "status": "success"
}
        </pre>
        response on failure:
        <pre>
{
  "error": {
    "exitcode": 6,
    "message": "Network 'example_network' already exists"
  },
  "result": null,
  "status": "failure"
}
        </pre>
  </td>
</tr>
<tr>
  <td valign="top">
    <code>safescale network list [command_options]</code>
  </td>
  <td>List <code>Networks</code> created by SafeScale<br><br>
    <code>command_options</code>:
    <ul>
      <li><code>--all</code> List all network existing on the current tenant (not only those created by SafeScale)</li>
    </ul>
    <u>examples</u>:
    <ul>
      <li><pre>$ safescale network list</pre>
          response:
          <pre>
{
  "result": [
    {
      "cidr": "192.168.0.0/24",
      "gateway_id": "48112419-3bc3-46f5-a64d-3634dd8bb1be",
      "id": "76ee12d6-e0fa-4286-8da1-242e6e95844e",
      "name": "example_network",
      "virtual_ip": {}
    }
  ],
  "status": "success"
}
          </pre>
      </li>
      <li>
        <pre>safescale network list --all</pre>
        response on success:
        <pre>
{
  "result": [
    {
      "cidr": "192.168.0.0/24",
      "id": "76ee12d6-e0fa-4286-8da1-242e6e95844e",
      "name": "example_network",
      "virtual_ip": {}
    },
    {
      "cidr": "10.0.0.0/16",
      "id": "eb5979e8-6ac6-4436-88d6-c36e3a949083",
      "name": "not_managed_by_safescale",
      "virtual_ip": {}
    }
  ],
  "status": "success"
}
        </pre>
      </li>
    </ul>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale network inspect &lt;network_name_or_id&gt;</code></td>
  <td>Get information about a <code>Network</code> created by SafeScale.<br><br>
      <u>example</u>:
      <pre>$ safescale network inspect example_network</pre>
      response on success:
      <pre>
{
  "result": {
    "cidr": "192.168.0.0/24",
    "gateway_id": "48112419-3bc3-46f5-a64d-3634dd8bb1be",
    "gateway_name": "gw-example_network",
    "id": "76ee12d6-e0fa-4286-8da1-242e6e95844e",
    "name": "example_network"
  },
  "status": "success"
}
      </pre>
      response on failure:
      <pre>
{
  "error": {
    "exitcode": 6,
    "message": "Failed to find 'networks/byName/fake_network'"
  },
  "result": null,
  "status": "failure"
}
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale network delete &lt;network_name_or_id&gt;</code></td>
  <td>Delete a <code>Network</code> created by SafeScale.<br><br>
      <u>example</u>:
      <pre>$ safescale network delete example_network</pre>
      response on success:
      <pre>
{
  "result": null,
  "status": "success"
}
      </pre>
      response on failure (<code>Network</code> does not exist):
      <pre>
{
  "error": {
    "exitcode": 6,
    "message": "Cannot delete network: failed to find Network 'example_network'"
  },
  "result": null,
  "status": "failure"
}
      </pre>
      response on failure (hosts still attached to network):
      <pre>
{
  "error": {
    "exitcode": 6,
    "message": "Cannot delete network: failed to delete Subnet 'example_network': cannot delete subnet 'example_network': 1 host is still attached to it: example-host"
  },
  "result": null,
  "status": "failure"
}
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale network subnet create [command_options] &lt;network_name_or_id&gt; &lt;subnet_name></code></td>
  <td>Creates a <code>Subnet</code> with the given name.<br><br>
      <code>command_options</code>:
      <ul>
        <li><code>--cidr &lt;cidr&gt;</code> CIDR of the network (default: "192.168.0.0/24")</li>
        <li><code>--gwname &lt;name&gt;</code> name of the gateway (default: <code>gw-&lt;subnet_name&gt;</code>)</li>
        <li><code>--os "&lt;os name&gt;"</code> Image name for the gateway (default: "Ubuntu 20.04")</li>
        <li><code>--sizing|-S &lt;sizing&gt;</code> Describes sizing of gateway (refer to <a href="#safescale_sizing">Host sizing definition</a> paragraph for details)</li>
        <li><code>--failover</code>creates 2 gateways for the network with a VIP used as internal default route. The names of the gateways cannot be changed, and will be <code>gw-&lt;subnet_name&gt;</code> and <code>gw2-&lt;subnet_name&gt;</code>
        </li>
      </ul>
      <u>example</U>:
      <pre>$ safescale network subnet create --cidr 192.168.1.0/24 example_network example_subnet</pre>
      response on success:
      <pre>
{
  "result": {
    "cidr": "192.168.1.0/24",
    "gateway_ids": [
      "8fd9b241-f4fe-4f80-a162-def3858053ee"
    ],
    "id": "acca6c3c-f17b-4132-a8a3-cef147fde464",
    "name": "example_subnet",
    "state": 3
  },
  "status": "success"
}
      </pre>
      response on failure:
      <pre>
{
  "error": {
    "exitcode": 6,
    "message": "Cannot create Subnet: subnet 'example_subnet' already exists"
  },
  "result": null,
  "status": "failure"
}
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale network subnet list [command_options] &lt;network_name_or_id&gt;</code></td>
  <td>List <code>Subnets</code> created by SafeScale.<br><br>
      <code>command_options</code>:
      <ul>
        <li><code>--all</code> List all network existing on the current tenant (not only those created by SafeScale)</li>
      </ul>
      <u>examples</u>:
      <ul>
        <li>
          <pre>$ safescale network subnet list example_network</pre>
          response on success:
          <pre>
{
  "result": [
    {
      "cidr": "192.168.0.0/24",
      "id": "05a662a3-3801-4a82-af86-c15956de19a9",
      "name": "example_network"
    },
    {
      "cidr": "192.168.1.0/24",
      "id": "acca6c3c-f17b-4132-a8a3-cef147fde464",
      "name": "example_subnet"
    }
  ],
  "status": "success"
}
          </pre>
        </li>
        <li>
          <pre>$ safescale network subnet list --all example_network</pre>
          response:
          <pre>
{
  "result": [
    {
      "id": "05a662a3-3801-4a82-af86-c15956de19a9",
      "name": "example_network"
    },
    {
      "id": "3e545f60-44fc-4687-a1db-b7a7cd5cdc71",
      "name": "mycluster"
    },
    {
      "id": "634a92e0-8066-4234-bf89-553ff62bbcdc"
    },
    {
      "id": "acca6c3c-f17b-4132-a8a3-cef147fde464",
      "name": "example_subnet"
    },
  ],
  "status": "success"
}
          </pre>
        </li>
        <li>
          <pre>$ safescale network subnet list --all -</pre>
          response:
          <pre>
{
  "result": [
    {
      "id": "05a662a3-3801-4a82-af86-c15956de19a9",
      "name": "example_network"
    },
    {
      "id": "3e545f60-44fc-4687-a1db-b7a7cd5cdc71",
      "name": "mycluster"
    },
    {
      "id": "634a92e0-8066-4234-bf89-553ff62bbcdc"
    },
    {
      "id": "831f226e-bca3-4d5a-b713-5c85a9179298",
      "name": "Ext-Net"
    },
    {
      "id": "98de7b3b-bb78-4890-8d66-101d43cbb428"
    },
    {
      "id": "acca6c3c-f17b-4132-a8a3-cef147fde464",
      "name": "example_subnet"
    },
    {
      "id": "ae3d806b-8ef9-4ec8-b573-ab7c4facd4c6",
      "name": "Ext-Net"
    },
    {
      "id": "c05ecaaf-9c22-430c-8571-4bcc29b4be8d",
      "name": "Ext-Net"
    },
    {
      "id": "c49a8ef1-f6fb-4ece-babc-bbefc8721349",
      "name": "Ext-Net"
    },
    {
      "id": "d55f9a90-b45d-4735-8f12-562575438d93",
      "name": "Ext-Net"
    },
    {
      "id": "f1a368d8-d221-45cc-bc50-7df8a589795f",
      "name": "Ext-Net"
    }
  ],
  "status": "success"
}
          </pre>
        </li>
      </ul>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale network subnet inspect &lt;network_name_or_id&gt; &lt;subnet_name_or_id&gt;</code></td>
  <td>Get information about a <code>Subnet</code> created by SafeScale.`<br><br>
      <u>example</u>:
      <pre>$ safescale network subnet inspect example_network example_subnet</pre>
      response on success:
      <pre>
{
  "result": {
    "cidr": "192.168.1.0/24",
    "gateway_ids": [
      "8fd9b241-f4fe-4f80-a162-def3858053ee"
    ],
    "gateway_name": "gw-example_subnet",
    "gateways": [
      "gw-example_subnet"
    ],
    "id": "acca6c3c-f17b-4132-a8a3-cef147fde464",
    "name": "example_subnet",
    "state": 3
  },
  "status": "success"
}
      </pre>
      response on failure:
      <pre>
{
  "error": {
    "exitcode": 6,
    "message": "Cannot inspect Subnet: failed to find a subnet referenced by 'example_subnet' in network 'example_network'"
  },
  "result": null,
  "status": "failure"
}
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale network subnet delete &lt;network_name_or_id&gt; &lt;subnet_name_or_id&gt;</code></td>
  <td>Delete a <code>Subnet</code> created by SafeScale.<br><br>
      If <code>&lt;subnet_name_or_id&gt;</code> contains a name, <code>&lt;network_name_or_id&gt;</code> is mandatory.<br>
      If <code>&lt;subnet_name_or_id&gt;</code> contains an ID, <code>&lt;network_name_or_id&gt;</code> can be omitted using <code>""</code> or <code>-</code>.<br><br>
      examples:
      <ul>
        <li><pre>$ safescale network subnet delete example_network example_subnet</pre>
            response on success:
            <pre>
{
  "result": null,
  "status": "success"
}
            </pre>
            response on failure (Hosts still attached to Subnet):
            <pre>
{
  "error": {
    "exitcode": 6,
    "message": "Cannot delete Subnet 'example_subnet': 1 host is still attached to it: myhost"
  },
  "result": null,
  "status": "failure"
}
            </pre>
            response on failure (subnets still present in Network):
            <pre>
{
  "error": {
    "exitcode": 6,
    "message": "Cannot delete network: failed to delete Network 'vpl-net', 2 Subnets still inside"
  },
  "result": null,
  "status": "failure"
}</pre>
        </li>
        <li><pre>$ safescale network subnet delete - 48112419-3bc3-46f5-a64d-3634dd8bb1be</pre>
            response on success:
            <pre>
{
  "result": null,
  "status": "success"
}
            </pre>
            response on failure (hosts still attached to Subnet):
            <pre>
{
  "error": {
    "exitcode": 6,
    "message": "Cannot delete Subnet 'example_subnet': 1 host is still attached to it: myhost"
  },
  "result": null,
  "status": "failure"
}
            </pre>
            <u>note</u>: <code>example_network</code> will not be used in this case, the `Subnet` ID is sufficient to locate the concerned resource.
        </li>
      </ul>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale network security group create [command_options] &lt;network_name_or_id&gt; &lt;security_group_name&gt;</code></td>
  <td>REVIEW_ME: <br>Creates a <code>SecurityGroup</code> in a <code>Network</code>.<br>
      <code>command_options</code>:
      <ul>
        <li><code>--description</code> Describes the usage of the Security Group (optional)</li>
      </ul>
      example:
      <pre>$ safescale network security group create --description "sg for hosts in example_network" example_network sg-example-hosts</pre>
      response on success:
      <pre>
{"result":{
      </pre>
      response on failure:
      <pre>
{
  "error": {
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale network security group list [command_options] &lt;network_name_or_id&gt;</code></td>
  <td>List <code>SecurityGroups</code> available in a <code>Network</code><br>
      <code>command_options</code>:
      <ul>
        <li><code>--all</code> List all Security Groups (not only those created by SafeScale) (optional)</li>
      </ul>
      <u>examples</u>:
      <ul>
        <li><pre>$ safescale network security group list</pre>
            response on success:
            <pre>
{
  "result": [
    {
      "description": "SG for gateways in Subnet vpl-net of Network vpl-net",
      "id": "0be8c7bd-fec3-4ca3-b7bc-0f5cf012b6ca",
      "name": "safescale-sg_subnet_gateways.example_network.example_network"
    },
    {
      "description": "SG for internal access in Subnet vpl-net of Network vpl-net",
      "id": "411e237a-7659-46ee-a3e8-051d8653edf1",
      "name": "safescale-sg_subnet_internals.example_network.example_network"
    },
    {
      "description": "SG for hosts with public IP in Subnet vpl-net of Network vpl-net",
      "id": "ad3b5701-45cc-4da3-92d4-589900bb45f0",
      "name": "safescale-sg_subnet_publicip.example_network.example_network"
    },
  ],
  "status": "success"
}
          </pre>
        </li>
        <li><pre>$ safescale network security group list --all</pre>
            response on success:
            <pre>
{
  "result": [
    {
      "description": "SG for gateways in Subnet vpl-net of Network vpl-net",
      "id": "0be8c7bd-fec3-4ca3-b7bc-0f5cf012b6ca",
      "name": "safescale-sg_subnet_gateways.example_network.example_network"
    },
    {
      "description": "SG for internal access in Subnet vpl-net of Network vpl-net",
      "id": "411e237a-7659-46ee-a3e8-051d8653edf1",
      "name": "safescale-sg_subnet_internals.example_network.example_network"
    },
    {
      "description": "SG for hosts with public IP in Subnet vpl-net of Network vpl-net",
      "id": "ad3b5701-45cc-4da3-92d4-589900bb45f0",
      "name": "safescale-sg_subnet_publicip.example_network.example_network"
    },
    {
      "description": "Default security group",
      "id": "a81a28a5-3925-4ae7-bdee-69ee6c24f335",
      "name": "default"
    },
  ],
  "status": "success"
}
            </pre>
        </li>
      </ul>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale network security group inspect &lt;network_name_or_id&gt; &lt;security_group_name_or_id&gt;</code></td>
  <td>REVIEW_ME: Get information about a <code>SecurityGroup</code><br><br>
      example:
      <pre>$ safescale network security group inspect example_network safescale-sg_subnet_publicip.example_network.example_network</pre>
      response on success:
      <pre>
{
  "result": {
    "description": "SG for hosts with public IP in Subnet vpl-cluster of Network vpl-cluster",
    "id": "d1eaabcd-765b-49e9-883a-2f34d273bec0",
    "name": "safescale-sg_subnet_publicip.example_network.example_network"
  },
  "status": "success"
}
      </pre>
      response on failure:
      <pre>
{
  "error": {
    "exitcode": 6,
    "message": "cannot inspect security group: failed to find Security Group 'safescale-sg_subnet_publicip.example_network.example_network'"
  },
  "result": null,
  "status": "failure"
}
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale network security group delete &lt;network_name_or_id&gt; &lt;security_group_name_or_id&gt;</code></td>
  <td>REVIEW_ME: Deletes a Security Group<br><br>
      example:
      <pre>$ safescale network security group delete example_network sg-example-hosts</pre>
      response on success:
      <pre>
{
  "result": null,
  "status": "success"
}
      </pre>
      response on failure:
      <pre>
{"error":{
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale network security group clear &lt;network_name_or_id&gt; &lt;security_group_name_or_id&gt;</code></td>
  <td>REVIEW_ME: Removes rules from a Security Group<br><br>
      example:
      <pre>$ safescale network security group clear example_network sg-example-hosts</pre>
      response on success:
      <pre>
{
  "result": null,
  "status": "success"
}
      </pre>
      response on failure:
      <pre>
{"error":{
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale network security group bonds &lt;network_name_or_id&gt; &lt;security_group_name_or_id&gt;</code></td>
  <td>REVIEW_ME: Lists Security Groups bonds<br><br>
      example:
      <pre>$ safescale network security group bonds example_network sg-example-hosts</pre>
      response on success:
      <pre>
{"result":
      </pre>
      response on failure:
      <pre>
{"error":{
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale network security group rule add [command_options] &lt;network_name_or_id&gt; &lt;security_group_name_or_id&gt;</code></td>
  <td>REVIEW_ME: Add a Security Group rule<br><br>
      <code>command_options</code>:
      <ul>
        <li><code>--direction ingress|egress</code>code> Defines the direction of the rule (optional, default: ingress)</li>
        <li><code>--protocol tcp|udp|icmp|all</code> Defines the protocol for the rule (optional, default: tcp)</li>
        <li><code>--from-port &lt;port_number&gt;</code> Defines the first port of a port range (default: none)</li>
        <li><code>--to-port &lt;port_number&gt;</code> Defines the last port of a port range (default: none)<br>
            If there is one port, just set <code>--from-port</code>
        </li>
        <li><code>--source &lt;CIDR&gt;</code> Defines source CIDR (meaningful with <code>--direction ingress</code><br>
            Can be used multiple times to define many sources
        </li>
        <li><code>--target &lt;CIDR&gt;</code> Defines target CIDR (meaningful with <code>--direction egress</code><br>
            Can be used multiple times to define many sources
        </li>
        <li><code>--description &lt;text&gt;</code> Sets a description to the rule (optional)
      </ul>
      example:
      <pre>$ safescale network security group rule add --from-port 80 --source 0.0.0.0/0 --description "allow HTTP" example_network sg-for-some-hosts</pre>
      response on success:
      <pre>
{
  "result": null,
  "status": "success"
}
      </pre>
      response on failure:
      <pre>
{
  "error":
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale network security group rule delete [command_options] &lt;network_name_or_id&gt; &lt;security_group_name_or_id&gt;</code></td>
  <td>REVIEW_ME: Delete a rule from a Security Group<br><br>
      <code>command_options</code>:
      <ul>
        <li><code>--direction ingress|egress</code>code> Defines the direction of the rule (optional, default: ingress)</li>
        <li><code>--protocol tcp|udp|icmp|all</code> Defines the protocol for the rule (optional, default: tcp)</li>
        <li><code>--from-port &lt;port_number&gt;</code> Defines the first port of a port range (default: none)</li>
        <li><code>--to-port &lt;port_number&gt;</code> Defines the last port of a port range (default: none)<br>
            If there is one port, just set <code>--from-port</code>
        </li>
        <li><code>--source &lt;CIDR&gt;</code> Defines source CIDR (meaningful with <code>--direction ingress</code><br>
            Can be used multiple times to define many sources
        </li>
        <li><code>--target &lt;CIDR&gt;</code> Defines target CIDR (meaningful with <code>--direction egress</code><br>
            Can be used multiple times to define many sources
        </li>
      </ul>
      example:
      <pre>$ safescale network security group rule add --from-port 80 --source 0.0.0.0/0 --description "allow HTTP" example_network sg-for-some-hosts</pre>
      response on success:
      <pre>
{
  "result":null,
  "status":"success"
}
      </pre>
      response on failure:
      <pre>
{
  "error": {
      </pre>
  </td>
</tr>
</tbody>
</table>

Note: if <code>&lt;subnet_name_or_id&gt;</code> or <code>&lt;security_group_name_od_id&gt;</code> contain an ID, value can be empty string ("" or CHECK_THIS:`-`); the ID is sufficient to locate what resource is concerned.

<br><br>

--- 
#### <a name="host">host</a>

This command family deals with host management: creation, list, connection, deletion...
The following actions are proposed:

REVIEW_ME:
<table>
<thead><td><div style="width:350px">Action</div></td><td><div style="min-width: 650px">description</div></td></thead>
<tbody>
<tr>
  <td valign="top"><code>safescale [global_options] host create [command_options] &lt;host_name&gt;</code></td>
  <td>Creates a new host. This host will be attached to the requested `Subnet`. Note that by default this host is created with a private IP address.<br><br>
      <code>command_options</code>:
      <ul>
        <li><code>--network &lt;network_name&gt;</code> Specifies the `Network` in which the `Subnet` to connect the host to resides. Cannot be used with <code>--public</code>.</li>
        <li><code>--subnet &lt;subnet_name&gt;</code> Specifies the `Subnet` to connect the `Host` to. Can't be used with <code>--public</code>.</li>
        <li><code>--single|--public</code> Creates a **single** `Host` with public IP; cannot be used with <code>--network</code>/<code>--subnet</code>.</li>
        <li><code>--sizing|-S &lt;sizing&gt;</code> Describes sizing of Host (refer to [Host sizing](#safescale_sizing) paragraph)</li>
        <li><code>--keep-on-failure|-k</code> Do not destroy `Host` in case of failure (for post-mortem debugging)</li>
      </ul>
      <u>examples</u>:
      <ul>
        <li>
          Create an Host inside a Network (with a Subnet named as the Network):
          <pre>$ safescale host create --network example_network myhost</pre>
          response on success:
          <pre>
{
  "result": {
    "cpu": 1,
    "disk": 10,
    "gateway_id": "48112419-3bc3-46f5-a64d-3634dd8bb1be",
    "id": "8afd43aa-1747-4f7b-a0a5-1fc89a4ac7e3",
    "name": "myhost",
    "password": "xxxxxxxxxx",
    "private_ip": "192.168.0.196",
    "private_key": "-----BEGIN RSA PRIVATE KEY----- ... -----END RSA PRIVATE KEY-----\n",
    "ram": 2,
    "state": 2
  },
  "status": "success"
}
          </pre>
          response on failure:
          <pre>
{
  "error": {
    "exitcode": 1,
    "message": "Failed to create host 'example_host': name is already used"
  },
  "result": null,
  "status": "failure"
}
          </pre>
        </li>
        <li>
          Create a Host inside a specific Subnet of a Network:
          <pre>$ safescale host create --network example_network --subnet example_subnet --sizing "cpu=4,ram=[7-14],disk>=100" myhost</pre>
          response on success:
          <pre>
{"result":{
          </pre>
          response on failure:
          <pre>
{"error": {
          </pre>
        </li>
      </ul>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] host list [options]</code></td>
  <td>List hosts<br>
      <code>command_options</code>code:
      <ul>
        <li><code>--all</code>code> List all existing hosts on the current tenant (not only those created by SafeScale)</li>
      </ul>
      <u>examples</u>:
      <ul>
        <li>
          <pre>$ safescale host list</pre>
          response:
          <pre>
{
  "result": [
    {
      "id": "425bfe96-a902-4bb4-8f4e-f8c928700f08",
      "name": "gw-reclaim"
    },
    {
      "id": "49658036-55c0-4fb7-9f5f-1cf4c2054967",
      "name": "gw-basictest-network-1"
    }
  ],
  "status": "success"
}
          </pre>
        </li>
        <li>
          <pre>$ safescale host list --all</pre>
          response:
          <pre>
{
  "result": [
    {
      "id": "425bfe96-a902-4bb4-8f4e-f8c928700f08",
      "name": "gw-reclaim"
    },
    {
      "id": "49658036-55c0-4fb7-9f5f-1cf4c2054967",
      "name": "gw-basictest-network-1"
    },
    {
      "id": "abcaa3df-6f86-4533-9a29-6e20e16fd957",
      "name": "myhost"
    }
  ],
  "status": "success"
}
          </pre>
          <u>note</u>: `Host` `myhost` was not created by SafeScale, but appears anyway.
        </li>
      </ul>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] host inspect &lt;host_name_or_id&gt;</code></td>
  <td>Get detailed information about a host<br><br>
      example:
      <pre>$ safescale host inspect example_host</pre>
      response on success:
      <pre>
{
  "result": {
    "cpu": 1,
    "disk": 10,
    "gateway_id": "39a5043a-1790-4a4f-bb87-788bb7252d13",
    "id": "abcaa3df-6f86-4533-9a29-6e20e16fd957",
    "name": "myhost",
    "password": "xxxxxxxxxxxx",
    "private_ip": "192.168.0.169",
    "private_key": "-----BEGIN RSA PRIVATE KEY----- ... -----END RSA PRIVATE KEY-----\n",
    "ram": 2,
    "state": 2
  },
  "status": "success"
}
      </pre>
      response on failure:
      <pre>
{
  "error": {
    "exitcode": 6,
    "message": "Cannot inspect host: failed to find host 'myhost'"
  },
  "result": null,
  "status": "failure"
}
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] host ssh &lt;host_name_or_id&gt;</code></td>
  <td>Get SSH configuration to connect to host (for use without SafeScale for example)<br><br>
      example:
      <pre>$ safescale host ssh myhost</pre>
      response on success:
      <pre>
{
  "result": {
    "GatewayConfig": {
      "GatewayConfig": null,
      "Host": "51.83.34.22",
      "LocalPort": 0,
      "Port": 22,
      "PrivateKey": "-----BEGIN RSA PRIVATE KEY----- ... -----END RSA PRIVATE KEY-----\n",
      "User": "safescale"
    },
    "Host": "192.168.0.169",
    "LocalPort": 0,
    "Port": 22,
    "PrivateKey": "-----BEGIN RSA PRIVATE KEY----- ... -----END RSA PRIVATE KEY-----\n",
    "User": "safescale"
  },
  "status": "success"
}
      </pre>
      response on failure:
      <pre>
{
  "error": {
    "exitcode": 6,
    "message": "Failed to find 'hosts/byName/myhost'"
  },
  "result": null,
  "status": "failure"
}      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] host delete &lt;host_name_or_id&gt; [...]</code></td>
  <td>Delete host(s)<br><br>
      example:
      <pre>$ safescale host delete myhost</pre>
      response on success:
      <pre>
{
  "result": null,
  "status": "success"
}
      </pre>
      response on failure: REVIEW_ME
      <pre>
{
  "error": {
    "exitcode": 6,
    "message": "Failed to find host 'myhost'"
  },
  "result": null,
  "status": "failure"
}      </pre>
  </td>
</tr>
<tr>
  <td><code>safescale [global_options] host start &lt;host_name_or_id&gt;</code></td>
  <td>REVIEW_ME: Starts a Host.<br><br>
      example:
      <pre>$ safescale host start example_host</pre>
      response on success:
      <pre>
{
      </pre>
      response on failure:
      <pre>
{
      </pre>
  </td>
</tr>
<tr>
  <td><code>safescale [global_options] host stop &lt;host_name_or_id&gt;</code></td>
  <td>REVIEW_ME: Stop a Host.<br><br>
      example:
      <pre>$ safescale host stop example_host</pre>
      response on success:
      <pre>
{
      </pre>
      response on failure:
      <pre>
{
      </pre>
  </td>
</tr>
<tr>
  <td><code>safescale [global_options] host reboot &lt;host_name_or_id&gt;</code></td>
  <td>REVIEW_ME: Reboots an Host.<br><br>
      example:
      <pre>$ safescale host reboot example_host</pre>
      response on success:
      <pre>
{
      </pre>
      response on failure:
      <pre>
{
      </pre>
  </td>
</tr>
<tr>
  <td><code>safescale [global_options] host status &lt;host_name_or_id&gt;</code></td>
  <td>REVIEW_ME: Displays the current status of an Host.<br><br>
      example:
      <pre>$ safescale host status example_host</pre>
      response on success:
      <pre>
{
      </pre>
      response on failure:
      <pre>
{
      </pre>
  </td>
</tr>

<tr>
  <td valign="top"><code>safescale [global_options] host feature check [command_options] &lt;host_name_or_id&gt; &lt;feature_name&gt;</code></td>
  <td>Check if a feature is present on the host<br>
      <code>command_options</code>:
      <ul>
        <li><code>-p "&lt;PARAM&gt;=&lt;VALUE&gt;"</code> Sets the value of a parameter required by the feature</li>
      </ul>
      example:
      <pre>$ safescale host check-feature myhost docker</pre>
      response if feature is present: REVIEW_ME
      <pre>
{
  "result": null,
  "status": "success"
}
      </pre>
      response if feature is not present:
      <pre>
{
  "error": {
    "exitcode": 4,
    "message": "Feature 'docker' not found on host 'myhost'"
  },
  "result": null,
  "status": "failure"
}
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] host feature add [command_options] &lt;host_name_or_id&gt; &lt;feature_name&gt;</code></td>
  <td>Adds the feature to the host<br>
      <code>command_options</code>:
      <ul>
        <li><code>--param|-p "&lt;PARAM&gt;=&lt;VALUE&gt;"</code> Sets the value of a parameter required by the feature</li>
        <li><code>--skip-proxy</code> Disables the application of (optional) reverse proxy rules defined in the feature</li>
      </ul>
      example:
      <pre>$ safescale host feature add -p Username=&lt;username&gt; -p Password=&lt;password&gt; myhost remotedesktop </pre>
      response on success:
      <pre>
{
  "result": null,
  "status": "success"
}
      </pre>
      response on failure may vary.
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] host feature delete [command_options] &lt;host_name_or_id&gt; &lt;feature_name&gt;</code></td>
  <td>Deletes the feature from the host<br>
     <code>command_options</code>:
      <ul>
        <li><code>-p "&lt;PARAM&gt;=&lt;VALUE&gt;"</code>code> Sets the value of a parameter required by the feature</li>
      </ul>
      example:
      <pre>$ safescale host feature delete -p Username=&lt;username&gt; -p Password=&lt;password&gt; myhost remotedesktop</pre>
      response on success:
      <pre>
{
  "result": null,
  "status": "success"
}
      </pre>
      response on failure may vary.
  </td>
</tr>
<tr>
  <td><code>safescale [global_options] host security group list &lt;host_name_or_id&gt;</code></td>
  <td>REVIEW_ME: Lists the Security Groups bound to an Host.<br><br>
      example:
      <pre>$ safescale host security group list example_host</pre>
      response on success:
      <pre>
{
      </pre>
      response on failure:
      <pre>
{
      </pre>
  </td>
</tr>
<tr>
  <td><code>safescale [global_options] host security group bind &lt;host_name_or_id&gt; &lt;securitygroup_name_or_id&gt;</code></td>
  <td>REVIEW_ME: Links a Security Group to an Host.<br><br>
      example:
      <pre>$ safescale host security group bind example_host sg-for-some-hosts</pre>
      response on success:
      <pre>
{
      </pre>
      response on failure:
      <pre>
{
      </pre>
  </td>
</tr>
<tr>
  <td><code>safescale [global_options] host security group unbind &lt;host_name_or_id&gt; &lt;securitygroup_name_or_id&gt;</code></td>
  <td>REVIEW_ME: Unlinks a Security Group from an Host.<br><br>
      example:
      <pre>$ safescale host security group bind example_host sg-for-some-hosts</pre>
      response on success:
      <pre>
{
      </pre>
      response on failure:
      <pre>
{
      </pre>
  </td>
</tr>
<tr>
  <td><code>safescale [global_options] host security group disable &lt;host_name_or_id&gt; &lt;securitygroup_name_or_id&gt;</code></td>
  <td>REVIEW_ME: Disables a Security Group bound to an Host, the rules of the Security Group are then not being appliedd.<br><br>
      example:
      <pre>$ safescale host security group disable example_host sg-for-some-hosts</pre>
      response on success:
      <pre>
{
      </pre>
      response on failure:
      <pre>
{
      </pre>
  </td>
</tr>
<tr>
  <td><code>safescale [global_options] host security group enable &lt;host_name_or_id&gt; &lt;securitygroup_name_or_id&gt;</code></td>
  <td>REVIEW_ME: Enables a Security Group bound to an Host, the rules of the Security Group are then being applied.<br><br>
      example:
      <pre>$ safescale host security group enable example_host sg-for-some-hosts</pre>
      response on success:
      <pre>
{
      </pre>
      response on failure:
      <pre>
{
      </pre>
  </td>
</tr>
</tbody>
</table>

<br><br>

#### <a name="volume">volume</a>

This command family deals with volume (i.e. block storage) management: creation, list, attachment to a host, deletion...
The following actions are proposed:

<table>
<thead><td><div style="width:350px">Action</div></td><td><div style="min-width: 650px">description</div></td></thead>
<tbody>
<tr>
  <td><code>safescale volume create [command_options] &lt;volume_name&gt;></code></td>
  <td>
    Create a volume with the given name on the current tenant using default sizing values.<br><br>
    <code>command_options</code>:<br>
    <ul>
      <li><code>--size value</code> Size of the volume (in Go) (default: 10)</li>
      <li><code>--speed value</code> Allowed values: <code>SSD</code>, <code>HDD</code>, <code>COLD</code> (default: <code>HDD</code>)</li>
    </ul>
    example:
    <pre>$ safescale volume create myvolume</pre>
    response on success:REVIEW_ME
    <pre>
{
  "result": {
    "ID": "c409033f-e569-42f5-927a-5b1c35029500",
    "Name": "myvolume",
    "Size": 10,
    "Speed": "HDD"
  },
  "status": "success"
}
    </pre>
    response on failure:
    <pre>
{
  "error": {
    "exitcode": 6,
    "message": "Volume myvolume already exists"
  },
  "result": null,
  "status": "failure"
}
    </pre>
  </td>
</tr>
<tr>
  <td><code>safescale volume list</code></td>
  <td>
    List available volumes<br><br>
    example:
    <pre>$ safescale volume list</pre>
    response:
    <pre>
{
  "result": [
    {
      "id": "4463647d-035b-4e16-8ea9-b3c29acd1887",
      "name": "myvolume",
      "size": 10,
      "speed": 1
    }
  ],
  "status": "success"
}
    </pre>
  </td>
</tr>
<tr>
  <td><code>safescale volume inspect &lt;volume_name_or_id&gt;</code></td>
  <td>
    Get info about a volume.<br><br>
    example:
    <pre>$ safescale volume inspect myvolume</pre>
    response on success: REVIEW_ME
    <pre>
{
  "result": {
    "device_uuid": "cc3bbc5c-bc99-409d-90be-265bcdc5b506",
    "format": "nfs",
    "host": "i-086512601f6606319",
    "id": "vol-02b5a3740f249d2b2",
    "mount_path": "/data/my-volume",
    "name": "my-volume",
    "size": 200,
    "speed": "VS_HDD"
  },
  "status": "success"
}

    </pre>
    response on failure:
    <pre>
{
  "error": {
    "exitcode": 6,
    "message": "Failed to find volume myvolume"
  },
  "result": null,
  "status": "failure"
}
    </pre>
  </td>
</tr>
<tr>
  <td><code>safescale volume attach [command_options] &lt;volume_name_or_id&gt; &lt;host_name_or_id&gt;</code></td>
  <td>
    Attach the Volume to a Host. It mounts the volume in a directory of the Host. The directory is created if it does not already exists.
    The Volume is formatted by default.<br><br>
    <code>command_options</code>:
    <ul>
      <li><code>--path value</code> Mountpoint of the Volume (default: <code>/shared/&lt;volume_name&gt;</code>)</li>
      <li><code>--format value</code> Filesystem format (default: <code>ext4</code>)</li>
      <li><code>--do-not-format</code> Instructs not to format the Volume.</li>
    </ul>
    example:
    <pre>$ safescale volume attach myvolume myhost</pre>
    response on success:
    <pre>
{
  "result": null,
  "status": "success"
}
    </pre>
    response on failure (Volume not found):
    <pre>
{
  "error": {
    "exitcode": 6,
    "message": "Failed to find volume myvolume"
  },
  "result": null,
  "status": "failure"
}
    </pre>
    response on failure (Host not found):
    <pre>
{
  "error": {
    "exitcode": 6,
    "message": "Failed to find host myhost2"
  },
  "result": null,
  "status": "failure"
}
    </pre>
  </td>
</tr>
<tr>
  <td><code>safescale volume detach &lt;volume_name_or_id&gt; &lt;host_name_or_id&gt;</code></td>
  <td>
    Detach a Volume from a Host<br><br>
    example:
    <pre>$ safescale volume detach myvolume myhost</pre>
    response on success:
    <pre>
{
  "result": null,
  "status": "success"
}
    </pre>
    response on failure (Volume not found):
    <pre>
{
  "error": {
    "exitcode": 6,
    "message": "Failed to find volume myvolume"
  },
  "result": null,
  "status": "failure"
}
    </pre>
    response on failure (Host not found):
    <pre>
{
  "error": {
    "exitcode": 6,
    "message": "Failed to find host myhost"
  },
  "result": null,
  "status": "failure"
}
    </pre>
    response on failure (Volume not attached to Host):
    <pre>
{
  "error": {
    "exitcode": 6,
    "message": "Cannot detach volume myvolume: not attached to host myhost"
  },
  "result": null,
  "status": "failure"
}
    </pre>
  </td>
</tr>
<tr>
  <td><code>safescale volume delete &lt;volume_name_or_id&gt;</code></td>
  <td>
    Delete the Volume with the given name or ID.<br><br>
    example:
    <pre>$ safescale volume delete myvolume</pre>
    response on success:
    <pre>
{
  "result": null,
  "status": "success"
}
    </pre>
    response on failure (Volume attached):
    <pre>
{
  "error": {
    "exitcode": 6,
    "message": "Cannot delete volume myvolume: still attached to 1 host: myhost"
  },
  "result": null,
  "status": "failure"
}
    </pre>
    response on failure (Volume not found):
    <pre>
{
  "error": {
    "exitcode": 6,
    "message": "Cannot delete volume myvolume: failed to find volume myvolume"
  },
  "result": null,
  "status": "failure"
}
    </pre>
  </td>
</tr>
</tbody>
</table>

<br><br>

#### <a name="share">share</a>

This command family deals with share management: creation, list, deletion...
The following actions are proposed:

<table>
<thead><td><div style="width:350px">Action</div></td><td><div style="min-width: 650px">description</div></td></thead>
<tbody>
<tr>
  <td valign="top"><code>safescale [global_options] share list</code></td>
  <td>
    List existing shares<br><br>
    example:
    <pre>$ safescale share list</pre>
    response:
    <pre>
{
  "result": [
    {
      "host": {
        "name": "myhost"
      },
      "id": "d8eed474-dc3b-4a4d-91e6-91dd03cd98dd",
      "name": "myshare",
      "path": "/shared/data",
      "type": "nfs"
    }
  ],
  "status": "success"
}
    </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] share inspect &lt;share_name&gt;</code></td>
  <td>
    Get detailed information about the share.<br><br>
    example:
    <pre>$ safescale share inspect myshare</pre>
    response on success: REVIEW_ME
    <pre>
{
  "result": {
    "mount_list": [
      {
        "host": {
          "name": "myclient"
        },
        "path": "/shared",
        "share": {
          "name": "myshare"
        },
        "type": "nfs"
      }
    ],
    "share": {
      "host": {
        "name": "myhost"
      },
      "id": "d8eed474-dc3b-4a4d-91e6-91dd03cd98dd",
      "name": "myshare",
      "path": "/shared/data",
      "type": "nfs"
    }
  },
  "status": "success"
}
    </pre>
    response on failure:REVIEW_ME
    <pre>
{
  "error": {
    "exitcode": 6,
    "message": "cannot inspect share myshare [caused by {failed to find share myshare}]"
  },
  "result": null,
  "status": "failure"
}
    </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] share create [command_options] &lt;share_name&gt; &lt;host_name_or_id&gt;</code></td>
  <td>
    Create a Share on a Host and export the corresponding folder<br><br>
    <code>command_options</code>:
    <ul>
      <li><code>--path value</code> Path to be exported (default: <code>/shared/data</code>)</li>
    </ul>
    example:<br><br>`$ safescale share create myshare myhost`<br>response on success:<br>`{"result":null,"status":"success"}`<br>reponse on failure:<br>`{"error":{"exitcode":6,"message":"cannot create share 'myshare' [caused by {share 'myshare' already exists}]"},"result":null,"status":"failure"}`</td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] share mount [command_options] &lt;share_name&gt; &lt;host_name_or_id&gt;</code></td>
  <td>
    Mount a Share on a Host<br><br>
    <code>command_options</code>:
    <ul>
      <li><code>--path value</code> Path to mount Share on (default: <code>/data</code>)</li>
    </ul>
    example:
    <pre>$ safescale share mount myshare myclient</pre>
    response on success:
    <pre>
{"result":null,"status":"success"}
    </pre>
    response on failure (Share not found): REVIEW_ME
    <pre>
{"error":{"exitcode":6,"message":"cannot unmount share 'myshare' [caused by {failed to find share 'myshare'}]"},"result":null,"status":"failure"}
    </pre>
    response on failure (hHost not found): REVIEW_ME
    <pre>
{"error":{"exitcode":6,"message":"cannot unmount share 'myshare' [caused by {failed to find host 'myclient'}]"},"result":null,"status":"failure"}
    </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] share umount &lt;share_name&gt; &lt;host_name_or_id&gt;</code></td>
  <td>
    Unmount a Share from an Host<br><br>
    example:
    <pre>$ safescale share umount myshare myclient</pre>
    response on success:
    <pre>
{"result":null,"status":"success"}
    </pre>
    response on failure (Host not found): REVIEW_ME
    <pre>
{"error":{"exitcode":6,"message":"cannot unmount share 'myshare' [caused by {failed to find host 'myclient'}]"},"result":null,"status":"failure"}
    </pre>
    response on failure (Share not found): REVIEW_ME
    <pre>
{"error":{"exitcode":6,"message":"cannot unmount share 'myshare' [caused by {failed to find share 'myshare'}]"},"result":null,"status":"failure"}
    </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] share delete &lt;share_name&gt;</code></td>
  <td>
    Delete a Share.<br>
    <u>Note</u>: the content in itself of the Share is not deleted, it remains on the Host acting as server.<br><br>
    example:
    <pre>$ safescale share delete myshare</pre>
    response on success:
    <pre>
{"result":null,"status":"success"}
    </pre>
    response on failure (Share still mounted):
    <pre>
{"error":{"exitcode":6,"message":"error while deleting share myshare: Cannot delete share 'myshare' [caused by {still used by: 'myclient'}]"},"result":null,"status":"failure"}
    </pre>
    response on failure (Share not found):
    <pre>
{"error":{"exitcode":6,"message":"error while deleting share myshare: Failed to find share 'myshare'"},"result":null,"status":"failure"}
    </pre>
  </td>
</tr>
</tbody>
</table>

<br><br>

#### <a name="bucket">bucket</a>

This command family deals with object storage management: creation, list, mounting as filesystem, deleting...
The following actions are proposed:

<table>
<thead><td><div style="width:350px">Action</div></td><td><div style="min-width: 650px">description</div></td></thead>
<tbody>
<tr>
  <td valign="top"><code>safescale [global_options] bucket create &lt;bucket_name&gt;</code></td>
  <td>
    Create a bucket<br><br>
    example:
    <pre>$ safescale bucket create mybucket</pre>
    response on success: REVIEW_ME
    <pre>
{"result":null,"status":"success"}
    </pre>
    response on failure: REVIEW_ME
    <pre>
{"error":{"exitcode":6,"message":"Cannot create bucket [caused by {bucket 'mybucket' already exists}]"},"result":null,"status":"failure"}
    </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] bucket list</code></td>
  <td>
    List buckets<br><br>
    example:
    <pre>$ safescale bucket list</pre>
    response: REVIEW_ME
    <pre>
{"result":{"buckets":[{"name":"0.safescale-96d245d7cf98171f14f4bc0abd8f8019"},{"name":"mybucket"}]},"status":"success"}
    </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] bucket inspect &lt;bucket_name&gt;</code></td>
  <td>
    Get info about a bucket<br><br>
    example:
    <pre>$ safescale bucket inspect mybucket</pre>
    response on success:
    <pre>
{"result":{"bucket":"mybucket","host":{}},"status":"success"}
    </pre>
    response on failure: REVIEW_ME
    <pre>
{"error":{"exitcode":6,"message":"Cannot inspect bucket [caused by {failed to find bucket 'mybucket'}]"},"result":null,"status":"failure"}
    </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] bucket mount [command_options] &lt;bucket_name&gt; &lt;host_name_or_id&gt;</code></td>
  <td>
    Mount a Bucket as a filesystem on an Host.<br><br>
    <code>command_options</code>:
    <ul>
      <li><code>--path value</code> Mount point of the Bucket (default: <code>/buckets/&lt;bucket_name&gt;</code></li>
    </ul>
    example:
    <pre>$ safescale bucket mount mybucket myhost</pre>
    response on success:
    <pre>
{"result":null,"status":"success"}
    </pre>
    response on failure (Host not found): REVIEW_ME
    <pre>
{"error":{"exitcode":6,"message":"No host found with name or id 'myhost2'"},"result":null,"status":"failure"}
    </pre>
    response on failure (Bucket not found): REVIEW_ME
    <pre>
{"error":{"exitcode":6,"message":"Not found"},"result":null,"status":"failure"}
    </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] bucket umount &lt;bucket_name&gt; &lt;host_name_or_id&gt;</code></td>
  <td>
    Unmount a Bucket from the filesystem of an Host.<br><br>
    example:
    <pre>$ safescale bucket umount mybucket myhost</pre>
    response on success:
    <pre>
{"result":null,"status":"success"}
    </pre>
    response on failure (Bucket not found): REVIEW_ME
    <pre>
{"error":{"exitcode":6,"message":"Failed to find bucket 'mybucket'"},"result":null,"status":"failure"}
    </pre>
    response on failure (Host not found): REVIEW_ME
    <pre>
{"error":{"exitcode":6,"message":"Failed to find host 'myhost'"},"result":null,"status":"failure"}
    </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] bucket delete &lt;bucket_name&gt;</code></td>
  <td>
    Delete a Bucket<br><br>
    example:
    <pre>$ safescale bucket delete mybucket</pre>
    response on success:
    <pre>
{"result":null,"status":"success"}
    </pre>
    response on failure (Bucket not found): REVIEW_ME
    <pre>
{"error":{"exitcode":6,"message":"cannot delete bucket [caused by {Container Not Found}]"},"result":null,"status":"failure"}
    </pre>
    response on failure (Bucket mounted on Host(s)): REVIEW_ME
    <pre>
{"error":{"exitcode":6,"message":"cannot delete bucket [caused by {Container Not Empty}]"},"result":null,"status":"failure"}
    </pre>
  </td>
</tr>
</tbody>
</table>

<br><br>

#### <a name="ssh">ssh</a>

The following commands deals with ssh commands to be executed on a host.
The following actions are proposed:

<table>
<thead><td><div style="width:350px">Action</div></td><td><div style="min-width: 650px">description</div></td></thead>
<tbody>
<tr>
  <td valign="top"><code>safescale [global_options] ssh run -c "&lt;command&gt;" &lt;host_name_or_id&gt;</code></td>
  <td>
    Run a command on the host<br><br>
    <code>command</code> is the command to execute remotely.<br><br> REVIEW_ME
    example:
    <pre>$ safescale ssh run -c "ls -la ~" example_host</pre>
    response on success:
    <pre>
total 32
drwxr-xr-x 4 safescale safescale 4096 Jun  5 13:25 .
drwxr-xr-x 4 root root 4096 Jun  5 13:00 ..
-rw------- 1 safescale safescale   15 Jun  5 13:25 .bash_history
-rw-r--r-- 1 safescale safescale  220 Aug 31  2015 .bash_logout
-rw-r--r-- 1 safescale safescale 3771 Aug 31  2015 .bashrc
drwx------ 2 safescale safescale 4096 Jun  5 13:01 .cache
-rw-r--r-- 1 safescale safescale    0 Jun  5 13:00 .hushlogin
-rw-r--r-- 1 safescale safescale  655 May 16  2017 .profile
drwx------ 2 safescale safescale 4096 Jun  5 13:00 .ssh
    </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] ssh copy &lt;src&gt; &lt;dest&gt;</code></td>
  <td>
    Copy a local file/directory to an Host or copy from an Host to local<br><br>
    example: REVIEW_ME
    <pre>$ safescale ssh copy /my/local/file example_host:/remote/path</pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] ssh connect &lt;host_name_or_id&gt;</code></td>
  <td>
    REVIEW_ME: Connect to an Host with interactive shell<br><br>
    example:
    <pre>$ safescale ssh connect example_host</pre>
    response on success:
    <pre>
safescale@example-Host:~$
    </pre>
  </td>
</tr>
</tbody>
</table>
<br><br>

#### <a name="cluster">cluster</a>

This command family deals with cluster management: creation, inspection, deletion, ...
`cluster` has synonyms: `platform`, `datacenter`, `dc`.

The following actions are proposed:

<table>
<thead><td><div style="width:350px">Action</div></td><td><div style="min-width: 650px">description</div></td></thead>
<tbody>
<tr>
  <td valign="top"><code>safescale [global_options] cluster list</code></td>
  <td>
    List clusters<br><br>
    example:
    <pre>$ safescale cluster list</pre>
    response on success:
    <pre>
{"result":[{"cidr":"192.168.0.0/16","complexity":1,"complexity_label":"Small","default_route_ip":"192.168.2.245","endpoint_ip":"51.83.34.144","flavor":2,"flavor_label":"K8S","last_state":5,"last_state_label":"Created","name":"mycluster","primary_gateway_ip":"192.168.2.245","primary_public_ip":"51.83.34.144","remote_desktop":{"mycluster-master-1":["https://51.83.34.144/_platform/remotedesktop/mycluster-master-1/"]},"tenant":"TestOVH"}],"status":"success"}
    </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] cluster create [command_options] &lt;cluster_name&gt;</code></td>
  <td>Creates a new cluster.<br><br>
      <code>command_options</code>:
      <ul>
        <li><code>-F|--flavor &lt;flavor&gt;</code> Defines the "flavor" of the cluster.<br>
            <code>&lt;flavor&gt;</code> can be:
            <ul>
              <li><code>BOH</code>code> (Bunch Of Hosts, without any cluster management layer)</li>
              <li><code>K8S</code> (Kubernetes, default)</li>
            </ul>
        </li>
        <li><code>-N|--cidr &lt;network_CIDR&gt;</code> Defines the CIDR of the Subnet for the Cluster.</li>
        <li><code>-C|--complexity &lt;complexity&gt;</code> Defines the "complexity" of the Cluster, ie how many masters/nodes will be created (depending of cluster flavor).<br>
            Valid values are:
            <ul>
              <li><code>small</code>: 1 gateway, 1 master, 1 node</li>
              <li><code>normal</code>: 2 gateways (if Cloud Provider supports LAN VIP), 3 masters, 3 nodes</li>
              <li><code>large</code>: 2 gateways (if Cloud Provider supports LAN VIP), 5 masters, 6 node</li>
            </ul>
        </li>
        <li><code>--disable &lt;value&gt;</code> Allows to disable addition of default features (must be used several times to disable several features)<br>
            Accepted <code>&lt;value&gt;</code>s are:
            <ul>
              <li><code>remotedesktop</code> (all flavors)</li>
              <li></li><code>reverseproxy</code> (all flavors)</li>
              <li><code>gateway-failover</code> (all flavors with Normal or Large complexity)</li>
              <li><code>hardening</code> (flavor K8S)</li>
              <li><code>helm</code> (flavor K8S)</li>
            </ul>
        </li>
        <li><code>--os value</code> Image name for the servers (default: "Ubuntu 20.04", may be overriden by a cluster flavor)</li>
        <li><code>-k</code> Keeps infrastructure created on failure; default behavior is to delete resources</li>
        <li><code>--sizing|-S &lt;sizing&gt;</code> Describes sizing of all hosts (refer to <a href="#safescale_sizing">Host sizing definition</a> paragraph for details)</li>
        <li><code>--gw-sizing &lt;sizing&gt;</code> Describes gateway sizing specifically (refer to <a href="#safescale_sizing">Host sizing definition</a> paragraph for details); takes precedence over <code>--sizing</code></li>
        <li><code>--master-sizing &lt;sizing&gt;</code> Describes master sizing specifically (refer to <a href="#safescale_sizing">Host sizing definition</a> paragraph for details); takes precedence over <code>--sizing</code></li>
        <li><code>--node-sizing &lt;sizing&gt;</code> Describes node sizing specifically (refer to <a href="#safescale_sizing">Host sizing definition</a> paragraph for details); takes precedence over <code>--sizing</code></li>
      </ul>
      <b>! DEPRECATED !</b> use <code>--sizing</code>, <code>--gw-sizing</code>, <code>--master-sizing</code> and <code>--node-sizing</code> instead
      <ul>
        <li><code>--cpu &lt;value&gt;</code> Number of CPU for masters and nodes (default depending of Cluster flavor)</li>
        <li><code>--ram &lt;value&gt;</code> RAM for the host (default: 1 Go)</li>
        <li><code>--disk &lt;value&gt;</code> Disk space for the host (default depending of Cluster flavor)</li>
      </ul><br>
      example:
      <pre>$ safescale cluster create -F k8s -C small -N 192.168.22.0/24 mycluster</pre>
      response on success:
      <pre>
{"result":{"admin_login":"cladm","admin_password":"xxxxxxxxxxxx","cidr":"192.168.0.0/16","complexity":1,"complexity_label":"Small","default_route_ip":"192.168.2.245","endpoint_ip":"51.83.34.144","features":{"disabled":{"proxycache":{}},"installed":{}},"flavor":2,"flavor_label":"K8S","gateway_ip":"192.168.2.245","last_state":5,"last_state_label":"Created","name":"mycluster","network_id":"6669a8db-db31-4272-9acd-da49dca07e14","nodes":{"masters":[{"id":"9874cbc6-bd17-4473-9552-1f7c9c7a2d6f","name":"mycluster-master-1","private_ip":"192.168.0.86","public_ip":""}],"nodes":[{"id":"019d2bcc-9d8c-4c76-a638-cf5612322dfa","name":"mycluster-node-1","private_ip":"192.168.1.74","public_ip":""}]},"primary_gateway_ip":"192.168.2.245","primary_public_ip":"51.83.34.144","remote_desktop":{"mycluster-master-1":["https://51.83.34.144/_platform/remotedesktop/mycluster-master-1/"]},"tenant":"XXXX"},"status":"success"}
      </pre>
      response on failure (cluster already exists):
      <pre>
{"error":{"exitcode":8,"message":"Cluster 'mycluster' already exists.\n"},"result":null,"status":"failure"}
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] cluster inspect &lt;cluster_name&gt;</code></td>
  <td>Get info about a cluster<br><br>
      example:
      <pre>$ safescale cluster inspect mycluster</pre>
      response on success:
      <pre>
{"result":{"admin_login":"cladm","admin_password":"xxxxxxxxxxxxxx","cidr":"192.168.0.0/16","complexity":1,"complexity_label":"Small","default_route_ip":"192.168.2.245","defaults":{"gateway":{"max_cores":4,"max_ram_size":16,"min_cores":2,"min_disk_size":50,"min_gpu":-1,"min_ram_size":7},"image":"Ubuntu 20.04","master":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15},"node":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15}},"endpoint_ip":"51.83.34.144","features":{"disabled":{"proxycache":{}},"installed":{}},"flavor":2,"flavor_label":"K8S","gateway_ip":"192.168.2.245","last_state":5,"last_state_label":"Created","name":"mycluster","network_id":"6669a8db-db31-4272-9acd-da49dca07e14","nodes":{"masters":[{"id":"9874cbc6-bd17-4473-9552-1f7c9c7a2d6f","name":"mycluster-master-1","private_ip":"192.168.0.86","public_ip":""}],"nodes":[{"id":"019d2bcc-9d8c-4c76-a638-cf5612322dfa","name":"mycluster-node-1","private_ip":"192.168.1.74","public_ip":""}]},"primary_gateway_ip":"192.168.2.245","primary_public_ip":"51.83.34.144","remote_desktop":{"mycluster-master-1":["https://51.83.34.144/_platform/remotedesktop/mycluster-master-1/"]},"tenant":"XXXX"},"status":"success"}
      </pre>
      response on failure:
      <pre>
{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] cluster state &lt;cluster_name&gt;</code></td>
  <td>REVIEW_ME: Get current state of a Cluster<br><br>
      example:
      <pre>$ safescale cluster state mycluster</pre>
      response on success:
      <pre>
{"result":{
      </pre>
      response on failure:
      <pre>
{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] cluster delete [command_options] &lt;cluster_name&gt;</code></td>
  <td>Delete a cluster. By default, ask for user confirmation before doing anything<br><br>
      <code>command_options</code>code>:
      <ul>
        <li><code>-y</code> disables the confirmation and proceeds straight to deletion</li>
      </ul>
      <u>example</u>:
      <pre>$ safescale cluster delete -y mycluster</pre>
      response on success:
      <pre>
{"result":null,"status":"success"}
</pre>
      response on failure:
      <pre>
{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] cluster feature check [command_options] &lt;cluster_name&gt; &lt;feature_name&gt;</code></td>
  <td>Check if a feature is present on the cluster<br><br>
      <code>command_options</code>:
      <ul>
        <li><code>-p "&lt;PARAM&gt;=&lt;VALUE&gt;"</code> Sets the value of a parameter required by the Feature</li>
      </ul>
      example:
      <pre>$ safescale cluster feature check mycluster docker</pre>
      response on success:
      <pre>
{"result":"Feature 'docker' found on cluster 'mycluster'","status":"success"}
      </pre>
      response on failure:
      <pre>
{"error":{"exitcode":4,"message":"Feature 'docker' not found on cluster 'mycluster'"},"result":null,"status":"failure"}
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] cluster feature add [command_options] &lt;cluster_name&gt; &lt;feature_name&gt;</code></td>
  <td>Adds a feature to the cluster<br><br>
      <code>command_options</code>:
      <ul>
        <li><code>-p "&lt;PARAM&gt;=&lt;VALUE&gt;"</code>code> Sets the value of a parameter required by the Feature</li>
        <li><code>--skip-proxy</code> Disables the application of reverse proxy rules inside the Feature (if there is any)</li>
      </ul>
      example:
      <pre>$ safescale cluster feature add mycluster remotedesktop</pre>
      response on success:
      <pre>
{"result":null,"status":"success"}
      </pre>
      response on failure may vary.
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] cluster feature delete [command_options] &lt;cluster_name&gt; &lt;feature_name&gt;</code></td>
  <td>Deletes a Feature from a Cluster<br><br>
      <code>command_options</code>:
      <ul>
        <li><code>-p "&lt;PARAM&gt;=&lt;VALUE&gt;"</code> Sets the value of a parameter required by the feature</li>
      </ul>
      <u>note</u>: it may be necessary to set some parameters to be able to delete a Feature
      <u>example</u>:
      <pre>$ safescale cluster feature delete my-cluster remote-desktop</pre>
      response on success:
      <pre>
{"result":null,"status":"success"}
      </pre>
      response on failure may vary</td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] cluster expand [command_options] &lt;cluster_name&gt;</code></td>
  <td>REVIEW_ME:Creates new Cluster nodes and add them to Cluster for duty<br><br>
      <code>command_options</code>:
      <ul>
      </ul>
      example:
      <pre>$ safescale cluster expand mycluster</pre>
      response on success:
      <pre>
{"result":{
      </pre>
      response on failure:
      <pre>
{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] cluster shrink [command_options] &lt;cluster_name&gt;</code></td>
  <td>REVIEW_ME: Reduce the numbers of Cluster nodes and deletes the chosen ones<br><br>
      example:
      <pre>$ safescale cluster shrink mycluster</pre>
      response on success:
      <pre>
{"result":{
      </pre>
      response on failure:
      <pre>
{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] cluster stop [command_options] &lt;cluster_name&gt;</code></td>
  <td>Stop all Hosts composing a Cluster<br><br>
      example:
      <pre>$ safescale cluster stop mycluster</pre>
      response on success:
      <pre>
{"result":null,"status":"success"}
      </pre>
      response on failure:
      <pre>
{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] cluster start [command_options] &lt;cluster_name&gt;</code></td>
  <td>Start all Hosts composing a Cluster<br><br>
      example:
      <pre>$ safescale cluster start mycluster</pre>
      response on success:
      <pre>
{"result":null,"status":"success"}
      </pre>
      response on failure:
      <pre>
{"error":{"exitcode":6,"message":"Cannot start cluster: failed to find Cluster 'mycluster'"},"result":null,"status":"failure"}
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] cluster kubectl [command_options] &lt;cluster_name&gt; -- &lt;kubectl_parameters&gt;</code></td>
  <td>Executes <code>kubectl</code> command on Cluster<br><br>
      example:
      <pre>$  safescale cluster kubectl mycluster -- get nodes</pre>
      response on success:
      <pre>
NAME                 STATUS   ROLES    AGE   VERSION
gw-mycluster         Ready    &lt;none&gt;   11m   v1.18.5
mycluster-master-1   Ready    master   11m   v1.18.5
mycluster-node-1     Ready    &lt;none&gt;   10m   v1.18.5
      </pre>
      response on failure:
      <pre>
{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] cluster helm [command_options] &lt;cluster_name&gt; -- &lt;helm_parameters&gt;</code></td>
  <td>REVIEW_ME: Executes helm command on Cluster<br><br>
      example:
      <pre>$ safescale cluster helm mycluster -- install nginx</pre>
      response on success:
      <pre>
{"result":{
      </pre>
      response on failure:
      <pre>
{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] cluster master list [command_options] &lt;cluster_name&gt;</code></td>
  <td>List the masters of a cluster<br><br>
      example:
      <pre>$ safescale cluster master list mycluster</pre>
      response on success:
      <pre>
{"result":[{"id":"53c56611-5d96-4019-b012-354de282dd33","name":"mycluster-master-1"}],"status":"success"}
      </pre>
      response on failure:
      <pre>
{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}
      </pre>
  </td>
</tr>
<!-- <tr>
  <td valign="top"><code>safescale [global_options] cluster master inspect [command_options] &lt;cluster_name&gt; &lt;master_name&gt;</code></td>
  <td>REVIEW_ME: List the masters of a cluster<br><br>
      example:
      <pre>$ safescale cluster master inspect mycluster mycluster-master-1</pre>
      response on success:
      <pre>
{"result":
      </pre>
      response on failure (cluster not found):
      <pre>
{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}
      </pre>
  </td>
</tr> -->
<tr>
  <td valign="top"><code>safescale [global_options] cluster node list [command_options] &lt;cluster_name&gt;</code></td>
  <td>List nodes in a Cluster<br><br>
      example:
      <pre>$ safescale cluster node list mycluster</pre>
      response on success:
      <pre>
{"result":[{"id":"7bb5bb44-9c7f-4ec3-9b19-435095c610c6","name":"mycluster-node-1"}],"status":"success"}
      </pre>
      response on failure: <!-- note for dev: simplify this error message -->
      <pre>
{"error":{"exitcode":1,"message":"rpc error: code = NotFound desc = cannot list cluster nodes: failed to find Cluster 'mycluster': rpc error: code = NotFound desc = cannot list cluster nodes: failed to find Cluster 'mycluster'"},"result":null,"status":"failure"}
      </pre>
  </td>
</tr>
<!-- <tr>
  <td valign="top"><code>safescale [global_options] cluster node inspect [command_options] &lt;cluster_name&gt; &lt;node_name_or_id&gt;</code></td>
  <td>REVIEW_ME: Get info about a specific Cluster Node<br><br>
      example:
      <pre>$ safescale cluster node inspect mycluster mycluster-node-4</pre>
      response on success:
      <pre>
{"result":{"cpu":4,"disk":100,"id":"7bb5bb44-9c7f-4ec3-9b19-435095c610c6","name":"mycluster-node-1","password":"XXXXXXXXXX","private_ip":"192.168.3.145","private_key":"-----BEGIN RSA PRIVATE KEY-----\nXXXXXXXXX\n-----END RSA PRIVATE KEY-----","ram":15,"state":2},"status":"success"}
      </pre>
      response on failure (node not found):
      <pre>
{"error":{"exitcode":6,"message":"rpc error: code = NotFound desc = cannot inspect host: failed to find host 'vpl-net-node-2'"},"result":null,"status":"failure"}  
      </pre>
      response on failure (cluster not found):
      <pre>
{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] cluster node state [command_options] &lt;cluster_name&gt; &lt;node_name_or_id&gt;</code></td>
  <td>REVIEW_ME: Get the state of a specific Cluster node<br><br>
      example:
      <pre>$ safescale cluster node state mycluster mycluster-node-4</pre>
      response on success:
      <pre>
{"result":{
      </pre>
      response on failure (cluster not found):
      <pre>
{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}
      </pre>
      response on failure (node not found):
      <pre>
{"error":{"exitcode":4,"message":"failed to find node 'mycluster-node-4' in Cluster 'mycluster'.\n"},"result":null,"status":"failure"}
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] cluster node stop [command_options] &lt;cluster_name&gt; &lt;node_name_or_id&gt;</code></td>
  <td>REVIEW_ME: Disable a specific Cluster node of duty and stop it<br><br>
      <code>command_options</code>:
      <ul>
      </ul>
      example:
      <pre>$ safescale cluster node stop mycluster mycluster-node-4</pre>
      response on success:
      <pre>
{"result":
      </pre>
      response on failure:
      <pre>
{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] cluster node start [command_options] &lt;cluster_name&gt; &lt;node_name_or_id&gt;</code></td>
  <td>REVIEW_ME: Start a specific Cluster node and enable it for duty<br><br>
      example:
      <pre>$ safescale cluster node start mycluster mycluster-node-4</pre>
      response on success:
      <pre>
{"result":
      </pre>
      response on failure:
      <pre>
{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] cluster node delete [command_options] &lt;cluster_name&gt; &lt;node_name_or_id&gt;</code></td>
  <td>Delete a specific node from Cluster. By default, ask confirmation to the user.<br><br>
      <code>command aliases</code>: <code>remove</code>, <code>destroy</code>, <code>rm</code><br><br>
      <code>command_options</code>:
      <ul>
        <li><code>-y|--yes|--assume-yes</code>Respond yes to all questions (default: no)</li>
        <li><code>-f|--force</code> Force node deletion no matter what (ie. metadata inconsistency) (default: no)</li>
      </ul>
      example:
      <pre>$ safescale cluster node delete -y mycluster mycluster-node-4</pre>
      response on success:
      <pre>
{"result":null,"status":"success"}
      </pre>
      response on failure:
      <pre>
{"error":{"exitcode":6,"message":"rpc error: code = NotFound desc = cannot inspect host: failed to find host 'mycluster-node-4'"},"result":null,"status":"failure"}
      </pre>
  </td>
</tr> -->
</tbody>
</table>

<br><br>

#### <a name="safescale_env">Environment variables</a>

Some parameters of `safescale` can be set using environment variables:
- `SAFESCALED_LISTEN`: equivalent to `--listen`, allows to tell `safescale` how to reach the daemon `safescaled`.
- `SAFESCALE_METADATA_SUFFIX`: allows to specify a suffix to add to the name of the Object Storage bucket used to store SafeScale metadata on the tenant.
  This allows to "isolate" metadata between different users of SafeScale (practical in development for example). There is no equivalent command line parameter.
  This environment variable must be on par between `safescale` and `safescaled`, otherwise strange things may happen...
