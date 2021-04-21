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
      </pre>>
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
  <td valign="top"><code>safescale template inspect</code></td>
  <td>Display templates with scanned information (if available).<br><br>
      <u>example</u>: REVIEW_ME
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
        "image_name": "Ubuntu 18.04",
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
{"result":{
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
            do not create a default Subnet in the Network</li>
        <li><code>--gwname &lt;host_name&gt;</code>
            Name of the gateway (<code>gw-&lt;subnet_name&gt;</code> by default)</li>
        <li><code>--os "&lt;os_name&gt;"</code>
            Image name for the gateway (default: "Ubuntu 18.04")</li>
        <li><code>--failover</code>
            creates 2 gateways for the network with a VIP used as internal default route for the <code>Subnet</code> (when <code>--empty</code> is not used)</li>
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
  <td>List networks created by SafeScale<br><br>
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
  <td>Get info of a <code>Network</code>code><br><br>
      <u>example</u>:
      <pre>$ safescale network inspect example_network</pre>
      response on success:<pre>
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
      response on failure:<pre>
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
  <td>Delete the network whose name or id is given<br><br>
      <u>example</u>:
      <pre>$ safescale network delete example_network</pre>
      response on success:
      <pre>
{
  "result": null,
  "status": "success"
}
      </pre>
      response on failure (network does not exist):
      <pre>
{
  "error": {
    "exitcode": 6,
    "message": "Failed to find 'networks/byName/example_network'"
  },
  "result": null,
  "status": "failure"
}
      </pre>
      response on failure (hosts still attached to network):
      REVIEW_ME:
      <pre>
{
  "error": {
    "exitcode": 6,
    "message": "Cannot delete network 'example_network': 1 host is still attached to it: myhost"
  },
  "result": null,
  "status": "failure"
}
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale network subnet create [command_options] &lt;network_name_or_id&gt; &lt;subnet_name></code></td>
  <td>Creates a `Subnet` with the given name.<br><br>
      <code>command_options</code>:
      <ul>
        <li><code>--cidr &lt;cidr&gt;</code> CIDR of the network (default: "192.168.0.0/24")</li>
        <li><code>--gwname &lt;name&gt;</code> name of the gateway (default: <code>gw-&lt;subnet_name&gt;</code>)</li>
        <li><code>--os "&lt;os name&gt;"</code> Image name for the gateway (default: "Ubuntu 18.04")</li>
        <li><code>--sizing|-S &lt;sizing&gt;</code> Describes sizing of gateway (refer to <a href="#safescale_sizing">Host sizing definition</a> paragraph for details)</li>
        <li>`--failover` creates 2 gateways for the network with a VIP used as internal default route</li>
      </ul>
      <u>example</U>: REVIEW_ME
      <pre>$ safescale network subnet create example_network example_subnet</pre>
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
  <td valign="top"><code>safescale network subnet list [command_options] &lt;network_name_or_id&gt;</code></td>
  <td>REVIEW_ME: List `Subnets` created by SafeScale<br>
      <code>command_options</code>:
      <ul>
        <li><code>--all</code> List all network existing on the current tenant (not only those created by SafeScale)</li>
      </ul>
      <u>examples</u>:
      <ul>
        <li>
          <pre>$ safescale network list</pre>
          response on success:
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
          <pre>$ safescale network list --all</pre>
          response:
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
  <td valign="top"><code>safescale network subnet inspect &lt;network_name_or_id&gt; &lt;subnet_name_or_id&gt;</code></td>
  <td>REVIEW_ME: Get info about a `Subnet`<br><br>
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
  <td valign="top"><code>safescale network subnet delete &lt;network_name_or_id&gt; &lt;subnet_name_or_id&gt;</code></td>
  <td>REVIEW_ME: Delete a Subnet identified by name or id<br><br>
      If <code>&lt;subnet_name_or_id&gt;</code> contains a name, <code>&lt;network_name_or_id&gt;</code> is mandatory.<br>
      If <code>&lt;subnet_name_or_id&gt;</code> contains an ID, <code>&lt;network_name_or_id&gt;</code> can be omitted using <code>""</code> or <code>-</code>.<br><br>
      examples:
      <ul>
        <li><pre>$ safescale network subnet delete example_network example_subnet</pre>
            response on success:
            <pre>
{"result":
            </pre>
            response on failure (Network not found):
            <pre>
{"error":{
            </pre>
            response on failure (Subnet not found):
            <pre>
{"error":{
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
        </li>
        <li><pre>$ safescale network subnet delete example_network 48112419-3bc3-46f5-a64d-3634dd8bb1be</pre>
            response on success:
            <pre>
{"result":
            </pre>
            response on failure (Subnet not found):
            <pre>
{"error":{
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
            <u>note</u>: <code>example_network</code> will not be used in this case, the `Subnet` ID is sufficient to locate the concerned `Subnet`.
        </li>
      </ul>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale network security group create [command_options] &lt;network_name_or_id&gt; &lt;security_group_name&gt;</code></td>
  <td>REVIEW_ME: <br>Creates a Security Group in a Network.<br>
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
  <td valign="top"><code>safescale network security group list [command_options] &lt;network_name_or_id&gt;</code></td>
  <td>REVIEW_ME: List Security Groups<br>
      <code>command_options</code>:
      <ul>
        <li><code>--all</code> List all Security Groups existing on the current tenant (not only those created by SafeScale) (optional)</li>
      </ul>
      <u>examples</u>:
      <ul>
        <li><pre>$ safescale network security group list</pre>
            response on success:
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
        <li><pre>$ safescale network security group list --all</pre>
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
  <td valign="top"><code>safescale network security group inspect &lt;network_name_or_id&gt; &lt;security_group_name_or_id&gt;</code></td>
  <td>REVIEW_ME: Get information about a Security Group<br><br>
      example:
      <pre>$ safescale network security group inspect example_network sg-example-hosts</pre>
      response on success:
      <pre>
{"result":{
      </pre>
      response on failure:
      <pre>
{"error":{
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
  <td>REVIEW_ME: Delete the network whose name or id is given<br><br>
      example:
      <pre>$ safescale network delete example_network</pre>
      response on success:
      <pre>
{
  "result": null,
  "status": "success"
}
      </pre>
      response on failure (network does not exist):
      <pre>
{
  "error": {
    "exitcode": 6,
    "message": "Failed to find 'networks/byName/example_network'"
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
    "message": "Cannot delete network 'example_network': 1 host is still attached to it: myhost"
  },
  "result": null,
  "status": "failure"
}
      </pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale network security group rule delete [command_options] &lt;network_name_or_id&gt; &lt;security_group_name_or_id&gt;</code></td>
  <td>REVIEW_ME: Delete the network whose name or id is given<br><br>
      example:
      <pre>$ safescale network security group rule delete \
           --direction ingress --protocol tcp --from-port 80 --sources 0.0.0.0/0 \
           example_network sg-example-hosts</pre>
      response on success:
      <pre>
{
  "result":null,
  "status":"success"
}
      </pre>
      response on failure (network does not exist):
      <pre>
{
  "error": {
    "exitcode": 6,
    "message": "Cannot delete network 'example_network': 1 host is still attached to it: myhost"
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
    "message": "Cannot delete network 'example_network': 1 host is still attached to it: myhost"
  },
  "result": null,
  "status": "failure"
}
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
  <td valign="top"><code>safescale [global_options] host ssh [command_options] &lt;host_name_or_id&gt;</code></td>
  <td>Get SSH configuration to connect to host (for use without SafeScale for example)<br><br>
      <code>command_options</code>
      <ul>
        <li><code>-u &lt;user_name&;gt;</code> Allow to define a particular user to connect with (by default, uses <code>OPERATOR_USERNAME</code> from tenant file)</li>
      </ul><br>
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
      response on failure:
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
  <td valign="top"><code>safescale [global_options] host feature check [command_options] &lt;host_name_or_id&gt; &lt;feature_name&gt;</code></td>
  <td>Check if a feature is present on the host<br>
      <code>command_options</code>:
      <ul>
        <li><code>-p "&lt;PARAM&gt;=&lt;VALUE&gt;"</code> Sets the value of a parameter required by the feature</li>
      </ul>
      example:
      <pre>$ safescale host check-feature myhost docker</pre>
      response if feature is present:
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
        <li><code>-p "&lt;PARAM&gt;=&lt;VALUE&gt;"</code>code> Sets the value of a parameter required by the feature</li>
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
</tbody>
</table>

<br><br>

#### <a name="volume">volume</a>

This command family deals with volume (i.e. block storage) management: creation, list, attachment to a host, deletion...
The following actions are proposed:

REVIEW_ME:
<table>
<thead><td><div style="width:350px">Action</div></td><td><div style="min-width: 650px">description</div></td></thead>
<tbody>
<tr>
  <td><code>safescale volume create [command_options] &lt;volume_name&gt;></code></td>
  <td>Create a volume with the given name on the current tenant using default sizing values.<br>`command_options`:<br><ul><li>`--size value` Size of the volume (in Go) (default: 10)</li><li>`--speed value` Allowed values: SSD, HDD, COLD (default: "HDD")</li></ul>Example:<br><br>`$ safescale volume create myvolume`<br>response on success:<br>`{"result":{"ID":"c409033f-e569-42f5-927a-5b1c35029500","Name":"myvolume","Size":10,"Speed":"HDD"},"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":6,"message":"Volume 'myvolume' already exists"},"result":null,"status":"failure"}`</td>
</tr>
<tr>
  <td><code>safescale volume list</code></td>
  <td>List available volumes<br><br>Example:<br><br>`$ safescale volume list`<br>response:<br>`{"result":[{"id":"4463647d-035b-4e16-8ea9-b3c29acd1887","name":"myvolume","size":10,"speed":1}],"status":"success"}`</td>
</tr>
<tr>
  <td><code>safescale volume inspect &lt;volume_name_or_id&gt;</code></td>
  <td>Get info about a volume.<br><br>Example:<br><br>`$ safescale volume inspect myvolume`<br>response on success:<br>`{"result":{"Device":"03f6d07b-f0b1-47f5-9dce-6063ed0865da","Format":"nfs","Host":"myhost","ID":"4463647d-035b-4e16-8ea9-b3c29acd1887","MountPath":"/data/myvolume","Name":"myvolume","Size":10,"Speed":"HDD"},"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":6,"message":"Failed to find volume 'myvolume'"},"result":null,"status":"failure"}`</td>
</tr>
<tr>
  <td><code>safescale volume attach [command_options] &lt;volume_name_or_id&gt; &lt;host_name_or_id&gt;</code></td>
  <td>Attach the volume to a host. It mounts the volume on a directory of the host. The directory is created if it does not already exists. The volume is formatted by default.<br>`command_options`:<ul><li>`--path value` Mount point of the volume (default: "/shared/<volume_name>)</li><li>`--format value` Filesystem format (default: "ext4")</li><li>`--do-not-format` instructs not to format the volume.</li></ul>Example:<br><br>`$ safescale volume attach myvolume myhost`<br>response on success:<br>`{"result":null,"status":"success"}`<br>response on failure (volume not found):<br>`{"error":{"exitcode":6,"message":"Failed to find volume 'myvolume'"},"result":null,"status":"failure"}`<br>response on failure (host not found):<br>`{"error":{"exitcode":6,"message":"Failed to find host 'myhost2'"},"result":null,"status":"failure"}`</td>
</tr>
<tr>
  <td><code>safescale volume detach &lt;volume_name_or_id&gt; &lt;host_name_or_id&gt;</code></td>
  <td>Detach a Volume from a Host<br><br>Example:<br><br>`$ safescale volume detach myvolume myhost`<br>response on success:<br>`{"result":null,"status":"success"}`<br>response on failure (volume not found):<br>`{"error":{"exitcode":6,"message":"Failed to find volume 'myvolume'"},"result":null,"status":"failure"}`<br>response on failure (host not found):<br>`{"error":{"exitcode":6,"message":"Failed to find host 'myhost'"},"result":null,"status":"failure"}`<br>response on failure (volume not attached to host):<br>`{"error":{"exitcode":6,"message":"Cannot detach volume 'myvolume': not attached to host 'myhost'"},"result":null,"status":"failure"}`</td>
</tr>
<tr>
  <td><code>safescale volume delete &lt;volume_name_or_id&gt;</code></td>
  <td>Delete the Volume with the given name or ID.<br><br>Example:<br><br>`$ safescale volume delete myvolume`<br>response on success:<br>`{"result":null,"status":"success"}`<br>response on failure (volume attached):<br>`{"error":{"exitcode":6,"message":"Cannot delete volume 'myvolume': still attached to 1 host: myhost"},"result":null,"status":"failure"}`<br>response on failure (volume not found):<br>`{"error":{"exitcode":6,"message":"Cannot delete volume 'myvolume': failed to find volume 'myvolume'"},"result":null,"status":"failure"}`</td>
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
  <td>List existing shares<br><br>Example:<br><br>`$ safescale share list`<br>response:<br>`{"result":[{"host":{"name":"myhost"},"id":"d8eed474-dc3b-4a4d-91e6-91dd03cd98dd","name":"myshare","path":"/shared/data","type":"nfs"}],"status":"success"}`</td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] share inspect &lt;share_name&gt;</code></td>
  <td>Get detailed information about the share.<br><br>Example:<br><br>`$ safescale share inspect myshare`<br>response on success:<br>`{"result":{"mount_list":[{"host":{"name":"myclient"},"path":"/shared","share":{"name":"myshare"},"type":"nfs"}],"share":{"host":{"name":"myhost"},"id":"d8eed474-dc3b-4a4d-91e6-91dd03cd98dd","name":"myshare","path":"/shared/data","type":"nfs"}},"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":6,"message":"cannot inspect share 'myshare' [caused by {failed to find share 'myshare'}]"},"result":null,"status":"failure"}`</td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] share create [command_options] &lt;share_name&gt; &lt;host_name_or_id&gt;</code></td>
  <td>Create a share on a host and export the corresponding folder<br>`command_options`:<ul><li>`--path value` Path to be exported (default: "/shared/data")</li></ul>Example:<br><br>`$ safescale share create myshare myhost`<br>response on success:<br>`{"result":null,"status":"success"}`<br>reponse on failure:<br>`{"error":{"exitcode":6,"message":"cannot create share 'myshare' [caused by {share 'myshare' already exists}]"},"result":null,"status":"failure"}`</td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] share mount [command_options] &lt;share_name&gt; &lt;host_name_or_id&gt;</code></td>
  <td>Mount an exported nfs directory on a host<br>`command_options`:<ul><li>`--path value` Path to mount nfs directory on (default: /data)</li></ul>Example:<br><br>`$ safescale share mount myshare myclient`<br>response on success:<br>`{"result":null,"status":"success"}`<br>response on failure (share not found):<br>`{"error":{"exitcode":6,"message":"cannot unmount share 'myshare' [caused by {failed to find share 'myshare'}]"},"result":null,"status":"failure"}`<br>response on failure (host not found):<br>`{"error":{"exitcode":6,"message":"cannot unmount share 'myshare' [caused by {failed to find host 'myclient'}]"},"result":null,"status":"failure"}`</td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] share umount &lt;share_name&gt; &lt;host_name_or_id&gt;</code></td>
  <td>Unmount an exported nfs directory on a host<br><br>Example:<br><br>`$ safescale share umount myshare myclient`<br>response on success:<br>`{"result":null,"status":"success"}`<br>response on failure (host not found):<br>`{"error":{"exitcode":6,"message":"cannot unmount share 'myshare' [caused by {failed to find host 'myclient'}]"},"result":null,"status":"failure"}`<br>response on failure (share not found):<br>`{"error":{"exitcode":6,"message":"cannot unmount share 'myshare' [caused by {failed to find share 'myshare'}]"},"result":null,"status":"failure"}`</td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] share delete &lt;share_name&gt;</code></td>
  <td>Delete a nfs server by unexposing directory<br><br>Example:<br><br>`$ safescale share delete myshare`<br>response on success:<br>`{"result":null,"status":"success"}`<br>response on failure (share still mounted):<br>`{"error":{"exitcode":6,"message":"error while deleting share myshare: Cannot delete share 'myshare' [caused by {still used by: 'myclient'}]"},"result":null,"status":"failure"}`<br>response on failure (share not found):<br>`{"error":{"exitcode":6,"message":"error while deleting share myshare: Failed to find share 'myshare'"},"result":null,"status":"failure"}`</td>
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
  <td>Create a bucket<br><br>Example:<br><br>`$ safescale bucket create mybucket`<br>response on success:<br>`{"result":null,"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":6,"message":"Cannot create bucket [caused by {bucket 'mybucket' already exists}]"},"result":null,"status":"failure"}`</td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] bucket list</code></td>
  <td>List buckets<br><br>Example:<br><br>`$ safescale bucket list`<br>response:<br> `{"result":{"buckets":[{"name":"0.safescale-96d245d7cf98171f14f4bc0abd8f8019"},{"name":"mybucket"}]},"status":"success"}`</td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] bucket inspect &lt;bucket_name&gt;</code></td>
  <td>Get info about a bucket<br><br>Example:<br><br>`$ safescale bucket inspect mybucket`<br>response on success:<br>`{"result":{"bucket":"mybucket","host":{}},"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":6,"message":"Cannot inspect bucket [caused by {failed to find bucket 'mybucket'}]"},"result":null,"status":"failure"}`</td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] bucket mount [command_options] &lt;bucket_name&gt; &lt;host_name_or_id&gt;</code></td><td>Mount a bucket as a filesystem on a host.<br>`command_options`:<ul><li>`--path value` Mount point of the bucket (default: "/buckets/<bucket_name>"</li></ul>Example:<br><br>`$ safescale bucket mount mybucket myhost`<br>response on success:<br>`{"result":null,"status":"success"}`<br>response on failure (host not found):<br>`{"error":{"exitcode":6,"message":"No host found with name or id 'myhost2'"},"result":null,"status":"failure"}`<br><br>response on failure (bucket not found):<br>`{"error":{"exitcode":6,"message":"Not found"},"result":null,"status":"failure"}`</td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] bucket umount &lt;bucket_name&gt; &lt;host_name_or_id&gt;</code></td>
  <td>Umount a bucket from the filesystem of a host.<br><br>Example:<br><br>`$ safescale bucket umount mybucket myhost`<br>response on success:<br>`{"result":null,"status":"success"}`<br><br>response on failure (bucket not found):<br>`{"error":{"exitcode":6,"message":"Failed to find bucket 'mybucket'"},"result":null,"status":"failure"}`<br>response on failure (host not found):<br>`{"error":{"exitcode":6,"message":"Failed to find host 'myhost'"},"result":null,"status":"failure"}`</td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] bucket delete &lt;bucket_name&gt;</code></td>
  <td>Delete a bucket<br><br>Example:<br><br>`$ safescale bucket delete mybucket`<br>response on success:<br>`{"result":null,"status":"success"}`<br>response on failure (bucket not found):<br>`{"error":{"exitcode":6,"message":"cannot delete bucket [caused by {Container Not Found}]"},"result":null,"status":"failure"}`<br><br>response on failure (bucket mounted on hosts):<br>`{"error":{"exitcode":6,"message":"cannot delete bucket [caused by {Container Not Empty}]"},"result":null,"status":"failure"}`</td>
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
  <td>Run a command on the host<br><br>`parameters`:<ul><li>`command` is the command to execute remotely.</li></ul>Example:<br><br>`$ safescale ssh run -c "ls -la ~" example_host`<br>response:<br>`total 32`<br>`drwxr-xr-x 4 safescale safescale 4096 Jun  5 13:25 .`<br>`drwxr-xr-x 4 root root 4096 Jun  5 13:00 ..`<br>`-rw------- 1 safescale safescale   15 Jun  5 13:25 .bash_history`<br>`-rw-r--r-- 1 safescale safescale  220 Aug 31  2015 .bash_logout`<br>`-rw-r--r-- 1 safescale safescale 3771 Aug 31  2015 .bashrc`<br>`drwx------ 2 safescale safescale 4096 Jun  5 13:01 .cache`<br>`-rw-r--r-- 1 safescale safescale    0 Jun  5 13:00 .hushlogin`<br>`-rw-r--r-- 1 safescale safescale  655 May 16  2017 .profile`<br>`drwx------ 2 safescale safescale 4096 Jun  5 13:00 .ssh`</td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] ssh copy &lt;src&gt; &lt;dest&gt;</code></td>
  <td>Copy a local file/directory to a host or copy from host to local<br><br>Example:<br><br>`$ safescale ssh copy /my/local/file example_host:/remote/path`</td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] ssh connect &lt;host_name_or_id&gt;</code></td>
  <td>Connect to the host with interactive shell<br><br>Example:<br><br> `$  safescale ssh connect example_host`<br>response:`safescale@example-Host:~$`</td>
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
  <td>List clusters<br><br>
      example:
      <pre>$ safescale cluster list</pre>
      response on success:
      <pre>{"result":[{"cidr":"192.168.0.0/16","complexity":1,"complexity_label":"Small","default_route_ip":"192.168.2.245","endpoint_ip":"51.83.34.144","flavor":2,"flavor_label":"K8S","last_state":5,"last_state_label":"Created","name":"mycluster","primary_gateway_ip":"192.168.2.245","primary_public_ip":"51.83.34.144","remote_desktop":{"mycluster-master-1":["https://51.83.34.144/_platform/remotedesktop/mycluster-master-1/"]},"tenant":"TestOVH"}],"status":"success"}</pre>
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
        <li><code>--os value</code> Image name for the servers (default: "Ubuntu 18.04", may be overriden by a cluster flavor)</li>
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
      <pre>{"result":{"admin_login":"cladm","admin_password":"xxxxxxxxxxxx","cidr":"192.168.0.0/16","complexity":1,"complexity_label":"Small","default_route_ip":"192.168.2.245","endpoint_ip":"51.83.34.144","features":{"disabled":{"proxycache":{}},"installed":{}},"flavor":2,"flavor_label":"K8S","gateway_ip":"192.168.2.245","last_state":5,"last_state_label":"Created","name":"mycluster","network_id":"6669a8db-db31-4272-9acd-da49dca07e14","nodes":{"masters":[{"id":"9874cbc6-bd17-4473-9552-1f7c9c7a2d6f","name":"mycluster-master-1","private_ip":"192.168.0.86","public_ip":""}],"nodes":[{"id":"019d2bcc-9d8c-4c76-a638-cf5612322dfa","name":"mycluster-node-1","private_ip":"192.168.1.74","public_ip":""}]},"primary_gateway_ip":"192.168.2.245","primary_public_ip":"51.83.34.144","remote_desktop":{"mycluster-master-1":["https://51.83.34.144/_platform/remotedesktop/mycluster-master-1/"]},"tenant":"XXXX"},"status":"success"}</pre>
      response on failure (cluster already exists):
      <pre>{"error":{"exitcode":8,"message":"Cluster 'mycluster' already exists.\n"},"result":null,"status":"failure"}</pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] cluster inspect &lt;cluster_name&gt;</code></td>
  <td>Get info about a cluster<br><br>
      example:
      <pre>$ safescale cluster inspect mycluster</pre>
      response on success:
      <pre>{"result":{"admin_login":"cladm","admin_password":"xxxxxxxxxxxxxx","cidr":"192.168.0.0/16","complexity":1,"complexity_label":"Small","default_route_ip":"192.168.2.245","defaults":{"gateway":{"max_cores":4,"max_ram_size":16,"min_cores":2,"min_disk_size":50,"min_gpu":-1,"min_ram_size":7},"image":"Ubuntu 18.04","master":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15},"node":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15}},"endpoint_ip":"51.83.34.144","features":{"disabled":{"proxycache":{}},"installed":{}},"flavor":2,"flavor_label":"K8S","gateway_ip":"192.168.2.245","last_state":5,"last_state_label":"Created","name":"mycluster","network_id":"6669a8db-db31-4272-9acd-da49dca07e14","nodes":{"masters":[{"id":"9874cbc6-bd17-4473-9552-1f7c9c7a2d6f","name":"mycluster-master-1","private_ip":"192.168.0.86","public_ip":""}],"nodes":[{"id":"019d2bcc-9d8c-4c76-a638-cf5612322dfa","name":"mycluster-node-1","private_ip":"192.168.1.74","public_ip":""}]},"primary_gateway_ip":"192.168.2.245","primary_public_ip":"51.83.34.144","remote_desktop":{"mycluster-master-1":["https://51.83.34.144/_platform/remotedesktop/mycluster-master-1/"]},"tenant":"XXXX"},"status":"success"}</pre>
      response on failure:
      <pre>{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}</pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] cluster state &lt;cluster_name&gt;</code></td>
  <td>REVIEW_ME: Get current state of a Cluster<br><br>
      example:
      <pre>$ safescale cluster state mycluster</pre>
      response on success:
      <pre>{"result":{</pre>
      response on failure:
      <pre>{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}</pre>
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
      <pre>{"result":null,"status":"success"}</pre>
      response on failure:
      <pre>{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}</pre>
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
      <pre>{"result":"Feature 'docker' found on cluster 'mycluster'","status":"success"}</pre>
      response on failure:
      <pre>{"error":{"exitcode":4,"message":"Feature 'docker' not found on cluster 'mycluster'"},"result":null,"status":"failure"}</pre>
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
      <pre>{"result":null,"status":"success"}</pre>
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
      <pre>{"result":null,"status":"success"}</pre>
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
      <pre>{"result":{</pre>
      response on failure:
      <pre>{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}</pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] cluster shrink [command_options] &lt;cluster_name&gt;</code></td>
  <td>REVIEW_ME: Reduce the numbers of Cluster nodes and deletes the chosen ones<br><br>
      example:
      <pre>$ safescale cluster shrink mycluster</pre>
      response on success:
      <pre>{"result":{</pre>
      response on failure:
      <pre>{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}</pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] cluster stop [command_options] &lt;cluster_name&gt;</code></td>
  <td>Stop all Hosts composing a Cluster<br><br>
      example:
      <pre>$ safescale cluster stop mycluster</pre>
      response on success:
      <pre>{"result":null,"status":"success"}</pre>
      response on failure:
      <pre>{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}</pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] cluster start [command_options] &lt;cluster_name&gt;</code></td>
  <td>Start all Hosts composing a Cluster<br><br>
      example:
      <pre>$ safescale cluster start mycluster</pre>
      response on success:
      <pre>{"result":null,"status":"success"}</pre>
      response on failure:
      <pre>{"error":{"exitcode":6,"message":"Cannot start cluster: failed to find Cluster 'mycluster'"},"result":null,"status":"failure"}</pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] cluster kubectl [command_options] &lt;cluster_name&gt; -- &lt;kubectl_parameters&gt;</code></td>
  <td>Executes <code>kubectl</code> command on Cluster<br><br>
      example:
      <pre>$  safescale cluster kubectl mycluster -- get nodes</pre>
      response on success:
      <pre>NAME               STATUS   ROLES    AGE   VERSION
gw-mycluster         Ready    &lt;none&gt;   11m   v1.18.5
mycluster-master-1   Ready    master   11m   v1.18.5
mycluster-node-1     Ready    &lt;none&gt;   10m   v1.18.5
      </pre>
      response on failure:
      <pre>{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}</pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] cluster helm [command_options] &lt;cluster_name&gt; -- &lt;helm_parameters&gt;</code></td>
  <td>REVIEW_ME: Executes helm command on Cluster<br><br>
      example:
      <pre>$ safescale cluster helm mycluster -- install nginx</pre>
      response on success:
      <pre>{"result":{</pre>
      response on failure:
     <pre>{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}</pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] cluster master list [command_options] &lt;cluster_name&gt;</code></td>
  <td>List the masters of a cluster<br><br>
      example:
      <pre>$ safescale cluster master list mycluster</pre>
      response on success:
      <pre>{"result":[{"id":"53c56611-5d96-4019-b012-354de282dd33","name":"mycluster-master-1"}],"status":"success"}</pre>
      response on failure:
      <pre>{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}</pre>
  </td>
</tr>
<!-- <tr>
  <td valign="top"><code>safescale [global_options] cluster master inspect [command_options] &lt;cluster_name&gt; &lt;master_name&gt;</code></td>
  <td>REVIEW_ME: List the masters of a cluster<br><br>
      example:
      <pre>$ safescale cluster master inspect mycluster mycluster-master-1</pre>
      response on success:
      <pre>{"result":</pre>
      response on failure (cluster not found):
      <pre>{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}</pre>
  </td>
</tr> -->
<tr>
  <td valign="top"><code>safescale [global_options] cluster node list [command_options] &lt;cluster_name&gt;</code></td>
  <td>List nodes in a Cluster<br><br>
      example:
      <pre>$ safescale cluster node list mycluster</pre>
      response on success:
      <pre>{"result":[{"id":"7bb5bb44-9c7f-4ec3-9b19-435095c610c6","name":"mycluster-node-1"}],"status":"success"}</pre>
      response on failure: <!-- note for dev: simplify this error message -->
      <pre>{"error":{"exitcode":1,"message":"rpc error: code = NotFound desc = cannot list cluster nodes: failed to find Cluster 'mycluster': rpc error: code = NotFound desc = cannot list cluster nodes: failed to find Cluster 'mycluster'"},"result":null,"status":"failure"}</pre>
  </td>
</tr>
<!-- <tr>
  <td valign="top"><code>safescale [global_options] cluster node inspect [command_options] &lt;cluster_name&gt; &lt;node_name_or_id&gt;</code></td>
  <td>REVIEW_ME: Get info about a specific Cluster Node<br><br>
      example:
      <pre>$ safescale cluster node inspect mycluster mycluster-node-4</pre>
      response on success:
      <pre>{"result":{"cpu":4,"disk":100,"id":"7bb5bb44-9c7f-4ec3-9b19-435095c610c6","name":"mycluster-node-1","password":"XXXXXXXXXX","private_ip":"192.168.3.145","private_key":"-----BEGIN RSA PRIVATE KEY-----\nXXXXXXXXX\n-----END RSA PRIVATE KEY-----","ram":15,"state":2},"status":"success"}
</pre>
      response on failure (node not found):
      <pre>{"error":{"exitcode":6,"message":"rpc error: code = NotFound desc = cannot inspect host: failed to find host 'vpl-net-node-2'"},"result":null,"status":"failure"}</pre>
      response on failure (cluster not found):
      <pre>{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}</pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale [global_options] cluster node state [command_options] &lt;cluster_name&gt; &lt;node_name_or_id&gt;</code></td>
  <td>REVIEW_ME: Get the state of a specific Cluster node<br><br>
      example:
      <pre>$ safescale cluster node state mycluster mycluster-node-4</pre>
      response on success:
      <pre>{"result":{</pre>
      response on failure (cluster not found):
      <pre>{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}</pre>
      response on failure (node not found):
      <pre>{"error":{"exitcode":4,"message":"failed to find node 'mycluster-node-4' in Cluster 'mycluster'.\n"},"result":null,"status":"failure"}</pre>
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
      <pre>{"result":</pre>
      response on failure:
      <pre>{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}</pre>
 </tr>
<tr>
  <td valign="top"><code>safescale [global_options] cluster node start [command_options] &lt;cluster_name&gt; &lt;node_name_or_id&gt;</code></td>
  <td>REVIEW_ME: Start a specific Cluster node and enable it for duty<br><br>
      example:
      <pre>$ safescale cluster node start mycluster mycluster-node-4</pre>
      response on success:
      <pre>{"result":</pre>
      response on failure:
      <pre>{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}</pre>
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
      <pre>{"result":null,"status":"success"}</pre>
      response on failure:
      <pre>{"error":{"exitcode":6,"message":"rpc error: code = NotFound desc = cannot inspect host: failed to find host 'mycluster-node-4'"},"result":null,"status":"failure"}
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
