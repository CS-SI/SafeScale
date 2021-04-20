# SafeScale usage
<br>

## Content

- [SafeScale usage](#safescale-usage)
  - [Content](#content)
  - [safescaled](#safescaled)
      - [Configuration](#configuration)
      - [Usage](#usage)
  - [safescale](#safescale)
      - [Global options](#global-options)
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
      - [env](#env)

___

SafeScale is composed of 2 parts:

 - a daemon working in background, called [`safescaled`](#safescaled)
 - a client interacting with the daemon, called [`safescale`](#safescale)
<br>

## safescaled

`safescaled` is a daemon and you only need to launch it on your own computer.
The purpose of this daemon is to execute requests ordered by `safescale` client on the providers.
<br>
It is composed internally of 2 layers:
- `Infra` which manages Cloud Provider resources with an abstraction layer
- `Platform` which allows to create and manage clusters

#### Configuration

To dialog with the different providers, the daemon needs authentication parameters to be able to connect to the underlying provider's API. These credentials are given in the file `tenants.toml` (may also be `tenants.json` or `tenants.yaml`, in their respective corresponding format). This file is searched in order (first file found is used) in the folowing directories:

> - . (current directory)
> - $HOME/.safescale
> - $HOME/.config/safescale
> - /etc/safescale

The content of this configuration file is explained in [TENANTS.md](TENANTS.md).

Each `tenants` section contains specific authentication parameters for each Cloud Provider.
> - `client` can be one of the available provider's drivers in
>    - aws
>    - cloudferro
>    - flexibleengine
>    - gcp
>    - local (unstable, not compiled by default, cf this [documentation](LIBVIRT_PROVIDER.md))
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

A more detailed description of the content of the file `tenants.toml` can be found in [TENANTS.md](TENANTS.md).
<br>

#### Usage

If you built SafeScale from source, ```make install``` will have installed the binaries in $GOPATH/bin.
To launch the SafeScale daemon, simply execute the following command (from a regular user, no need to be root):

```bash
${GOPATH}/bin/safescaled &
```

It should display in your terminal something like this:

```bash
Safescaled version: 21.03.0, build f3973fb5a642b7d93b0f20417631e2706a86c211 (2021/03/25-14:49)
Ready to serve :-)
```

By default, ```safescaled``` displays only warnings and errors messages. To have more information, you can use ```-v``` to increase verbosity, and ```-d``` to use debug mode (```-d -v``` will produce A LOT of messages, it's for debug purposes).
<br><br>

#### Options

<table cellpadding="4" cellspacing="0">
<thead><tr><th align="left">Option</th><th align="left">description</th></tr></thead>
<tbody>
<tr valign="top">
  <td><code>--verbose, -v</code>code></td>
  <td>Increase the verbosity.<br><br>ex: <code>safescale -v host create ...</code></td>
</tr>
<tr valign="top">
  <td><code>--debug, -d</code></td>
  <td>Displays debugging information.<br><br>ex: <code>safescale -d host create ...</code></td></td>
</tr>
<tr valign="top">
  <td><code>--listen, -l</code></td>
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

Note: `-d -v` will display far more debugging information than simply `-d` (used to trace what is going on in details)

You can also set some parameters of `safescaled` using environment variables, which are :
- SAFESCALED_LISTEN: equivalent to `--listen`, allows to define on what interface and/or what port ``afescaled` has to listen on; used also by `safescale` to reach the daemon
- SAFESCALE_METADATA_SUFFIX: allows to specify a suffix to add to the name of the Object Storage bucket used to store SafeScale metadata on the tenant.
  This allows to "isolate" metadata between different users of SafeScale (practical in development for example). There is no equivalent command line parameter.
 
## safescale

`safescale` is the client part of SafeScale. It consists of a CLI to interact with the safescale daemon to manage cloud infrastructures.

The different available commands can be obtained via the **`--help`** option on each command and are listed hereafter. _Note that, despite of our efforts, the help got by the CLI might be more accurate and up-to-date than the following descriptions._

Each command returns its results on the standard output in 2 forms according to the expected result type:

- no result is expected: a simple comment about the execution of the command
- a result is expected: the result is formatted in **JSON** (or null if no result is produced); for eye-candy formatting, you can use `| jq` at the end of the command.
- outputs are expected: the outputs are displayed in sync with the work done on the remote side (for example, ```safescale platform kubectl``` command)

Each command has an exit status which is 0 if it succeeded, and !=0 if failed. If the command displays a result in JSON format, the JSON code contains the same exit code.

The commands are presented in logical order as if the user wanted to create some servers with a shared storage space.
<br>

#### Global options

``safescale`` accepts global_options just before the subcommand, which are :

<table>
<thead><tr><td>Option</td><td>Description</td></tr></thead>
<tbody>
<tr><td valign="top"><code>-v</code></td><td>Increase the verbosity.<br><br>ex: <code>safescale -v host create ...</code></td></tr>
<tr><td valign="top"><code>-d</code>+</td><td>Displays debugging information.<br><br>ex: <code>`safescale -d host create ...</code></td></tr>
</tbody>
</table>

Example:
```bash
$ safescale -v network create --cidr 192.168.1.0/24 mynetwork 
```
<br>

#### Commands

There are 3 categories of commands:
- the one dealing with tenants (aka cloud providers): [tenant](#tenant)
- the ones dealing with infrastructure resources: [network](#network), [subnet](#subnet), [host](#host), [volume](#volume), [share](#share), [bucket](#bucket), [ssh](#ssh)
- the one dealing with clusters: [cluster](#cluster)

#### tenant

A tenant must be set before using any other command as it indicates to SafeScale which tenant the command must be executed on. _Note that if only one tenant is defined in the `tenants.toml`, it will be automatically selected while invoking any other command.<br>
<!-- A storage tenant represents the credentials needed to connect an object storage they are used to select one or several object storage for [data](#safecale_data) commands<br> -->
The following actions are proposed:

<table>
<thead><td><div style="width:350px">Action</div></td><td><div style="min-width: 650px">Description</div></td></thead>
<tbody>
<tr>
  <td valign="top"><code>safescale tenant list</code></td>
  <td>List available tenants i.e. those found in the <code>tenants.toml</code>code> file.<br><br>
      example:
      <pre>$ safescale tenant list</pre>
      response:
      <pre>{"result":[{"name":"TestOVH"}],"status":"success"}]</pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale tenant get</code></td>
  <td>Display the current tenant used for action commands.<br><br>
      example:
      <pre>$ safescale tenant get</pre>
      response when tenant set:
      <pre>{"result":{"name":"TestOVH"},"status":"success"}</pre>
      response when tenant not set:
      <pre>{"error":{"exitcode":6,"message":"Cannot get tenant: no tenant set"},"result":null,"status":"failure"}</pre>
  </td>
</tr>
<tr>
  <td><code>safescale tenant set &lt;tenant_name&gt;</code></td>
  <td>Set the tenant to use by the next commands. The <code>&lt;tenant_name&gt;</code> must match one of those present in
      the <code>tenants.toml</code> file, from key <code>name</code>). The name is case sensitive.<br><br>
      Example:
      <div class="highlight highlight-source-bash">
      <pre>$ safescale tenant set TestOvh</pre>
      </div>
      response on success:
      <pre>{"result":null,"status":"success"}</pre>
      response on failure:
      <pre>{"error":{"exitcode":6,"message":"Unable to set tenant 'TestOVH': tenant 'TestOVH' not found in configuration"},"result":null,"status":"failure"}</pre>
  </td>
</tr>
<tr>
  <td><code>safescale tenant scan &lt;tenant_name&gt;</code></td>
  <td>REVIEW_ME: Scan the given tenant's templates. (See <a href="SCANNER.md">scanner</a> doc)</td>
</tr>
</tbody>
</table>

---
#### template

A tenant must be set before using any other command as it indicates to SafeScale which tenant the command must be executed on. _Note that if only one tenant is defined in the `tenants.toml`, it will be automatically selected while invoking any other command.<br>
<!-- A storage tenant represents the credentials needed to connect an object storage they are used to select one or several object storage for [data](#safecale_data) commands<br> -->
The following actions are proposed:

<table>
<thead><td><div style="width:350px">Action</div></td><td><div style="min-width:650px">Description</div>div></td></thead>
<tbody>
<tr>
  <td><code>safescale template list</code></td>
  <td>List available templates from the current tenant.<br><br>
      example:
      <pre>$ safescale template list</pre>
      response:
      <pre>{"result": [{"cores": 16, "disk": 400, "id": "0526e13e-dad5-473f-ad61-2f15e0db2a15", "ram": 240}],"status": "success"}</pre>
  <td>
</tr>
<tr>
  <td><code>safescale template inspect</code></td>
  <td>Display templates with scanned information</td>
</tr>
</tbody>
</table>
<br>

--- 
#### network

This command manages `Networks`, `Subnets`and `SecurityGroups` on the provider side. In some Cloud Providers terminology, `Network` can be called **VPC** (FlexibleEngine, AWS, ...).

Before release v21.03, Cloud Provider networks and subnets were melted into a SafeScale `Network`. Since release v21.03, Subnets are introduced.
For compatibility reason, default behavior of `safescale network` has been maintained as before, creating by default a `Subnet` named as the `Network` with a CIDR derived from the one of the Network.
For example, `safescale network create --cidr 172.16.0.0/16 my-net` will create a `Network` with a CIDR of 172.16.0.0/16 <u>and</u> a `Subnet` inside the `Network` with a CIDR of 172.16.0.0/17.

Since v21.03, it's now possible to create a `Network` without default `Subnet`, using `--empty` flag, leaving the responsibility of `Subnet` creation to the user. If `--empty` is used, the flags `--gwname`, `--os`, `--gw-sizing` and `--failover` are meaningless.

A `Network` being the owner of a `SecurityGroup`, the commands relative to `SecurityGroup` resides inside `safescale network security group`.

The following actions are proposed:

<table>
<thead><td><div style="width:350px">Action</div></td><td><div style="min-width:650px">Description</div></td></thead>
<tbody>
<tr>
  <td valign="top"><code>safescale network create [command_options] &lt;network_name&gt;</code></td>
  <td>Creates a network with the given name.<br><br>
      <code>command_options</code>:
      <ul>
        <li><code>--cidr &lt;cidr&gt;</code><br>
            CIDR of the network (default: "192.168.0.0/24")</li>
        <li><code>--empty</code><br>
            do not create a default Subnet in the Network</li>
        <li><code>--gwname &lt;host_name&gt;</code><br>
            Name of the gateway (<code>gw-&lt;subnet_name&gt;</code> by default)</li>
        <li><code>--os "&lt;os_name&gt;"</code><br>
            Image name for the gateway (default: "Ubuntu 18.04")</li>
        <li><code>--failover</code><br>
            creates 2 gateways for the network with a VIP used as internal default route for the <code>Subnet</code> (when <code>--empty</code> is not used)</li>
        <li><code>-S|--sizing &lt;sizing&gt;</code><br>
            describes sizing of gateway in format <code>"&lt;component&gt;&lt;operator&gt;&lt;value&gt;[,...]"</code> (when <code>--empty</code> is not used) where:
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
            </li><br>
            <li><code>&lt;cpu&gt;</code> is expecting an integer as number of cpu cores, or an interval with minimum and maximum number of cpu cores</li>
            <li><code>&lt;cpufreq&gt;</code> is expecting an integer as minimum cpu frequency in MHz</li>
            <li><code>&lt;gpu&gt;</code> is expecting an integer as number of GPU (scanner would have been run first to be able to determine which template proposes GPU)</li>
            <li><code>&lt;ram&gt;</code> is expecting a float as memory size in GB, or an interval with minimum and maximum memory size</li>
            <li><code>&lt;disk&gt;</code> is expecting an integer as system disk size in GB</li>
          </ul><br>
          examples:
          <ul>
            <li><code>--sizing "cpu <= 4, ram <= 10, disk >= 100"</code></li>
            <li><code>--sizing "cpu ~ 4, ram = [14-32]"</code> (is identical to <code>--sizing "cpu=[4-8], ram=[14-32]"</code>)</li>
            <li><code>--sizing "cpu <= 8, ram ~ 16"</code></li>
          </ul>
        </li>
      </ul><br>
      example:
        <pre>$ safescale network create example_network</pre>
        response on success:
        <pre>{"result":{"cidr":"192.168.0.0/24","gateway_id":"48112419-3bc3-46f5-a64d-3634dd8bb1be","id":"76ee12d6-e0fa-4286-8da1-242e6e95844e","name":"example_network","virtual_ip":{}},"status":"success"}`</pre>
        response on failure:
        <pre>{"error":{"exitcode":6,"message":"Network 'example_network' already exists"},"result":null,"status":"failure"}</pre>
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
    examples:
    <ul>
      <li><pre>$ safescale network list</pre>
          response:
          <pre>{"result":[{"cidr":"192.168.0.0/24","gateway_id":"48112419-3bc3-46f5-a64d-3634dd8bb1be","id":"76ee12d6-e0fa-4286-8da1-242e6e95844e","name":"example_network","virtual_ip":{}}],"status":"success"}</pre>
      </li>
      <li>
       <pre>safescale network list --all</pre>
       response:
       <pre>{"result":[{"cidr":"192.168.0.0/24","id":"76ee12d6-e0fa-4286-8da1-242e6e95844e","name":"example_network","virtual_ip":{}},{"cidr":"10.0.0.0/16","id":"eb5979e8-6ac6-4436-88d6-c36e3a949083","name":"not_managed_by_safescale","virtual_ip":{}}],"status":"success"}</pre>
      </li>
    </ul>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale network inspect &lt;network_name_or_id&gt;</code></td>
  <td>Get info of a <code>Network</code>code><br><br>
      example:
      <div class="highlight highlight-source-bash"><pre>$ safescale network inspect example_network</pre></div>
      response on success:
      <pre>{"result":{"cidr":"192.168.0.0/24","gateway_id":"48112419-3bc3-46f5-a64d-3634dd8bb1be","gateway_name":"gw-example_network","id":"76ee12d6-e0fa-4286-8da1-242e6e95844e","name":"example_network"},"status":"success"}</pre>
      response on failure
      <pre>{"error":{"exitcode":6,"message":"Failed to find 'networks/byName/fake_network'"},"result":null,"status":"failure"}</pre>
  </td>
</tr>
<tr>
  <td valign="top"><code>safescale network delete &lt;network_name_or_id&gt;</code></td>
  <td>Delete the network whose name or id is given<br><br>
      example:
      <pre>$ safescale network delete example_network</pre>
      response on success:
      <pre>{"result":null,"status":"success"}</pre>
      response on failure (network does not exist):
      <pre>{"error":{"exitcode":6,"message":"Failed to find 'networks/byName/example_network'"},"result":null,"status":"failure"}`</pre>
      response on failure (hosts still attached to network):
      REVIEW_ME:<pre>{"error":{"exitcode":6,"message":"Cannot delete network 'example_network': 1 host is still attached to it: myhost"},"result":null,"status":"failure"}</pre>
  </td>
</tr>
<tr><td valign="top"><code>safescale network subnet create [command_options] &lt;network_name_or_id&gt; &lt;subnet_name></code></td><td>REVIEW_ME: <br>Creates a `Subnet` with the given name.<br>`command_options`:<ul><li>`--cidr <cidr>` cidr of the network (default: "192.168.0.0/24")</li><li>`--empty` do not create a default Subnet in the Network</li><li>`--gwname <name>` name of the gateway (`gw-<network_name>` by default)</li><li>`--os "<os name>"` Image name for the gateway (default: "Ubuntu 18.04")</li><li>`-S <sizing>, --sizing <sizing>` describes sizing of gateway in format `"<component><operator><value>[,...]"` where:<ul><li>`<component>` can be `cpu`, `cpufreq` ([scanner](SCANNER.md) needed), `gpu` ([scanner](SCANNER.md) needed), `ram`, `disk`</li><li>`<operator>` can be `=`,`~`,`<`,`<=`,`>`,`>=` (except for disk where valid operators are only `=` or `>=`):<ul><li>`=` means exactly `<value>`</li><li>`~` means between `<value>` and 2x`<value>`</li><li>`<` means strictly lower than `<value>`</li><li>`<=` means lower or equal to `<value>`</li><li>`>` means strictly greater than `<value>`</li><li>`>=` means greater or equal to `<value>`</li></ul></li><li>`<value>` can be an integer (for `cpu`, `cpufreq`, `gpu` and `disk`) or a float (for `ram`) or an including interval `[<lower value>-<upper value>]`</li><li>`<cpu>` is expecting an integer as number of cpu cores, or an interval with minimum and maximum number of cpu cores</li><li>`<cpufreq>` is expecting an integer as minimum cpu frequency in MHz</li><li>`<gpu>` is expecting an integer as number of GPU (scanner would have been run first to be able to determine which template proposes GPU)</li><li>`<ram>` is expecting a float as memory size in GB, or an interval with minimum and maximum memory size</li><li>`<disk>` is expecting an integer as system disk size in GB</li>examples:<ul><li>--sizing "cpu <= 4, ram <= 10, disk >= 100"</li><li>--sizing "cpu ~ 4, ram = [14-32]" (is identical to --sizing "cpu=[4-8], ram=[14-32]")</li><li>--sizing "cpu <= 8, ram ~ 16"</li></ul></ul></li><li>`--failover` creates 2 gateways for the network with a VIP used as internal default route</li></ul>example:<br><br>`$ safescale network create example_network`<br>response on success:<br>`{"result":{"cidr":"192.168.0.0/24","gateway_id":"48112419-3bc3-46f5-a64d-3634dd8bb1be","id":"76ee12d6-e0fa-4286-8da1-242e6e95844e","name":"example_network","virtual_ip":{}},"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":6,"message":"Network 'example_network' already exists"},"result":null,"status":"failure"}` |
<tr><td valign="top"><code>safescale network subnet list [command_options] &lt;network_name_or_id&gt;</code></td><td>REVIEW_ME: List `Subnets` created by SafeScale<br>`command_options`:<ul><li>`--all` List all network existing on the current tenant (not only those created by SafeScale)</li></ul>examples:<br><br>`$ safescale network list`<br>response:<br> `{"result":[{"cidr":"192.168.0.0/24","gateway_id":"48112419-3bc3-46f5-a64d-3634dd8bb1be","id":"76ee12d6-e0fa-4286-8da1-242e6e95844e","name":"example_network","virtual_ip":{}}],"status":"success"}`<br><br>`safescale network list --all`<br>response:<br>`{"result":[{"cidr":"192.168.0.0/24","id":"76ee12d6-e0fa-4286-8da1-242e6e95844e","name":"example_network","virtual_ip":{}},{"cidr":"10.0.0.0/16","id":"eb5979e8-6ac6-4436-88d6-c36e3a949083","name":"not_managed_by_safescale","virtual_ip":{}}],"status":"success"}`</td></tr>
<tr><td valign="top"><code>safescale network subnet inspect &lt;network_name_or_id&gt; &lt;subnet_name_or_id&gt;</code></td><td>REVIEW_ME: Get info about a `Subnet`<br><br>example:<br><br>`$ safescale network inspect example_network`<br>response on success:<br>`{"result":{"cidr":"192.168.0.0/24","gateway_id":"48112419-3bc3-46f5-a64d-3634dd8bb1be","gateway_name":"gw-example_network","id":"76ee12d6-e0fa-4286-8da1-242e6e95844e","name":"example_network"},"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":6,"message":"Failed to find 'networks/byName/fake_network'"},"result":null,"status":"failure"}`</td></tr>
<tr><td valign="top"><code>safescale network subnet delete &lt;network_name_or_id&gt; &lt;subnet_name_or_id&gt;</code></td><td>REVIEW_ME: Delete the network whose name or id is given<br><br>example:<br><br> `$ safescale network delete example_network`<br>response on success:<br>`{"result":null,"status":"success"}`<br>response on failure (network does not exist):<br>`{"error":{"exitcode":6,"message":"Failed to find 'networks/byName/example_network'"},"result":null,"status":"failure"}`<br>response on failure (hosts still attached to network):<br>`{"error":{"exitcode":6,"message":"Cannot delete network 'example_network': 1 host is still attached to it: myhost"},"result":null,"status":"failure"}`</td></tr>
<td><td valign="top"><code>safescale network security group create [command_options] &lt;network_name_or_id&gt; &lt;security_group_name&gt;</code></td><td>REVIEW_ME: <br>Creates a network with the given name.<br>`command_options`:<ul><li>`--cidr <cidr>` cidr of the network (default: "192.168.0.0/24")</li><li>`--empty` do not create a default Subnet in the Network</li><li>`--gwname <name>` name of the gateway (`gw-<network_name>` by default)</li><li>`--os "<os name>"` Image name for the gateway (default: "Ubuntu 18.04")</li><li>`-S <sizing>, --sizing <sizing>` describes sizing of gateway in format `"<component><operator><value>[,...]"` where:<ul><li>`<component>` can be `cpu`, `cpufreq` ([scanner](SCANNER.md) needed), `gpu` ([scanner](SCANNER.md) needed), `ram`, `disk`</li><li>`<operator>` can be `=`,`~`,`<`,`<=`,`>`,`>=` (except for disk where valid operators are only `=` or `>=`):<ul><li>`=` means exactly `<value>`</li><li>`~` means between `<value>` and 2x`<value>`</li><li>`<` means strictly lower than `<value>`</li><li>`<=` means lower or equal to `<value>`</li><li>`>` means strictly greater than `<value>`</li><li>`>=` means greater or equal to `<value>`</li></ul></li><li>`<value>` can be an integer (for `cpu`, `cpufreq`, `gpu` and `disk`) or a float (for `ram`) or an including interval `[<lower value>-<upper value>]`</li><li>`<cpu>` is expecting an integer as number of cpu cores, or an interval with minimum and maximum number of cpu cores</li><li>`<cpufreq>` is expecting an integer as minimum cpu frequency in MHz</li><li>`<gpu>` is expecting an integer as number of GPU (scanner would have been run first to be able to determine which template proposes GPU)</li><li>`<ram>` is expecting a float as memory size in GB, or an interval with minimum and maximum memory size</li><li>`<disk>` is expecting an integer as system disk size in GB</li>examples:<ul><li>--sizing "cpu <= 4, ram <= 10, disk >= 100"</li><li>--sizing "cpu ~ 4, ram = [14-32]" (is identical to --sizing "cpu=[4-8], ram=[14-32]")</li><li>--sizing "cpu <= 8, ram ~ 16"</li></ul></ul></li><li>`--failover` creates 2 gateways for the network with a VIP used as internal default route</li></ul>example:<br><br>`$ safescale network create example_network`<br>response on success:<br>`{"result":{"cidr":"192.168.0.0/24","gateway_id":"48112419-3bc3-46f5-a64d-3634dd8bb1be","id":"76ee12d6-e0fa-4286-8da1-242e6e95844e","name":"example_network","virtual_ip":{}},"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":6,"message":"Network 'example_network' already exists"},"result":null,"status":"failure"}` |
<td><td valign="top"><code>safescale network security group list [command_options] &lt;network_name_or_id&gt;</code></td><td>REVIEW_ME: List networks created by SafeScale<br>`command_options`:<ul><li>`--all` List all network existing on the current tenant (not only those created by SafeScale)</li></ul>examples:<br><br>`$ safescale network list`<br>response:<br> `{"result":[{"cidr":"192.168.0.0/24","gateway_id":"48112419-3bc3-46f5-a64d-3634dd8bb1be","id":"76ee12d6-e0fa-4286-8da1-242e6e95844e","name":"example_network","virtual_ip":{}}],"status":"success"}`<br><br>`safescale network list --all`<br>response:<br>`{"result":[{"cidr":"192.168.0.0/24","id":"76ee12d6-e0fa-4286-8da1-242e6e95844e","name":"example_network","virtual_ip":{}},{"cidr":"10.0.0.0/16","id":"eb5979e8-6ac6-4436-88d6-c36e3a949083","name":"not_managed_by_safescale","virtual_ip":{}}],"status":"success"}` |
<td><td valign="top"><code>safescale network security group inspect &lt;network_name_or_id&gt; &lt;security_group_name_or_id&gt;</code></td><td>REVIEW_ME: Get info of a network<br><br>example:<br><br>`$ safescale network inspect example_network`<br>response on success:<br>`{"result":{"cidr":"192.168.0.0/24","gateway_id":"48112419-3bc3-46f5-a64d-3634dd8bb1be","gateway_name":"gw-example_network","id":"76ee12d6-e0fa-4286-8da1-242e6e95844e","name":"example_network"},"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":6,"message":"Failed to find 'networks/byName/fake_network'"},"result":null,"status":"failure"}` |
<td><td valign="top"><code>safescale network security group delete &lt;network_name_or_id&gt; &lt;security_group_name_or_id&gt;</code></td><td>REVIEW_ME: Delete the network whose name or id is given<br><br>example:<br><br> `$ safescale network delete example_network`<br>response on success:<br>`{"result":null,"status":"success"}`<br>response on failure (network does not exist):<br>`{"error":{"exitcode":6,"message":"Failed to find 'networks/byName/example_network'"},"result":null,"status":"failure"}`<br>response on failure (hosts still attached to network):<br>`{"error":{"exitcode":6,"message":"Cannot delete network 'example_network': 1 host is still attached to it: myhost"},"result":null,"status":"failure"}` |
<td><td valign="top"><code>safescale network security group clear &lt;network_name_or_id&gt; &lt;security_group_name_or_id&gt;</code></td><td>REVIEW_ME: Delete the network whose name or id is given<br><br>example:<br><br> `$ safescale network delete example_network`<br>response on success:<br>`{"result":null,"status":"success"}`<br>response on failure (network does not exist):<br>`{"error":{"exitcode":6,"message":"Failed to find 'networks/byName/example_network'"},"result":null,"status":"failure"}`<br>response on failure (hosts still attached to network):<br>`{"error":{"exitcode":6,"message":"Cannot delete network 'example_network': 1 host is still attached to it: myhost"},"result":null,"status":"failure"}` |
<td><td valign="top"><code>safescale network security group bonds &lt;network_name_or_id&gt; &lt;security_group_name_or_id&gt;</code></td><td>REVIEW_ME: Delete the network whose name or id is given<br><br>example:<br><br> `$ safescale network delete example_network`<br>response on success:<br>`{"result":null,"status":"success"}`<br>response on failure (network does not exist):<br>`{"error":{"exitcode":6,"message":"Failed to find 'networks/byName/example_network'"},"result":null,"status":"failure"}`<br>response on failure (hosts still attached to network):<br>`{"error":{"exitcode":6,"message":"Cannot delete network 'example_network': 1 host is still attached to it: myhost"},"result":null,"status":"failure"}` |
<td><td valign="top"><code>safescale network security group rule add [command_options] &lt;network_name_or_id&gt; &lt;security_group_name_or_id&gt;</code></td><td>REVIEW_ME: Delete the network whose name or id is given<br><br>example:<br><br> `$ safescale network delete example_network`<br>response on success:<br>`{"result":null,"status":"success"}`<br>response on failure (network does not exist):<br>`{"error":{"exitcode":6,"message":"Failed to find 'networks/byName/example_network'"},"result":null,"status":"failure"}`<br>response on failure (hosts still attached to network):<br>`{"error":{"exitcode":6,"message":"Cannot delete network 'example_network': 1 host is still attached to it: myhost"},"result":null,"status":"failure"}` |
<td><td valign="top"><code>safescale network security group rule delete [command_options] &lt;network_name_or_id&gt; &lt;security_group_name_or_id&gt;</code></td><td>REVIEW_ME: Delete the network whose name or id is given<br><br>example:<br><br> `$ safescale network delete example_network`<br>response on success:<br>`{"result":null,"status":"success"}`<br>response on failure (network does not exist):<br>`{"error":{"exitcode":6,"message":"Failed to find 'networks/byName/example_network'"},"result":null,"status":"failure"}`<br>response on failure (hosts still attached to network):<br>`{"error":{"exitcode":6,"message":"Cannot delete network 'example_network': 1 host is still attached to it: myhost"},"result":null,"status":"failure"}</code></td>
</tbody>
</table>

Note: if <code>&lt;subnet_name_or_id&gt;</code> or <code>&lt;security_group_name_od_id&gt;</code> contain an ID, value can be empty string ("" or CHECK_THIS:`-`); the ID is sufficient to locate what resource is concerned.

<br><br>

##### `safescale network inspect <network_name_or_id>`
Inspect a Network, returning meaningful information about it.

example:
    
```bash
$ safescale network inspect example_network
```
response on success:
```json
{"result":{"cidr":"192.168.0.0/24","gateway_id":"48112419-3bc3-46f5-a64d-3634dd8bb1be","gateway_name":"gw-example_network","id":"76ee12d6-e0fa-4286-8da1-242e6e95844e","name":"example_network"},"status":"success"}
```
    
response on failure:
```json
{"error":{"exitcode":6,"message":"Failed to find 'networks/byName/fake_network'"},"result":null,"status":"failure"}
```

##### `safescale network delete <network_name_or_id>`
Delete the network whose name or id is given. If the Network was created with a default Subnet, this Subnet will be deleted also. Otherwise, if the Network still has Subnets in it, deletion will fail.

example:

    `$ safescale network delete example_network`
    
response on success:

    `{"result":null,"status":"success"}`
    
response on failure (network does not exist):

    `{"error":{"exitcode":6,"message":"Failed to find 'networks/byName/example_network'"},"result":null,"status":"failure"}`
    
response on failure (subnets still attached to network):

    `{"error":{"exitcode":6,"message":"Cannot delete network 'example_network': 1 Subnet is still attached to it"},"result":null,"status":"failure"}`

<br><br>
--- 

##### `safescale network subnet create [command_options] <network_name> <subnet_name>`

Creates a `Subnet` with the given name.

`command_options`:
  - `--cidr <cidr>` cidr of the network (default: "192.168.0.0/24")
  - `--gwname <name>` name of the gateway (`gw-<network_name>` by default)
  - `--os "<os name>"` Image name for the gateway (default: "Ubuntu 18.04")
  - `-S <sizing>, --sizing <sizing>` describes sizing of gateway in format `"<component><operator><value>[,...]"` where:
    - `<component>` can be `cpu`, `cpufreq` ([scanner](SCANNER.md) needed), `gpu` ([scanner](SCANNER.md) needed), `ram`, `disk`
    - `<operator>` can be `=`,`~`,`<`,`<=`,`>`,`>=` (except for disk where valid operators are only `=` or `>=`):
      - `=` means exactly `<value>`
      - `~` means between `<value>` and 2x`<value>`
      - `<` means strictly lower than `<value>`
      - `<=` means lower or equal to `<value>`
      - `>` means strictly greater than `<value>`
      - `>=` means greater or equal to `<value>`
    - `<value>` can be an integer (for `cpu`, `cpufreq`, `gpu` and `disk`) or a float (for `ram`) or an including interval `[<lower value>-<upper value>]`
      - `<cpu>` is expecting an integer as number of cpu cores, or an interval with minimum and maximum number of cpu cores
      - `<cpufreq>` is expecting an integer as minimum cpu frequency in MHz
      - `<gpu>` is expecting an integer as number of GPU (scanner would have been run first to be able to determine which template proposes GPU)
      - `<ram>` is expecting a float as memory size in GB, or an interval with minimum and maximum memory size
      - `<disk>` is expecting an integer as system disk size in GB
      
      examples:
        - --sizing "cpu <= 4, ram <= 10, disk >= 100"
        - --sizing "cpu ~ 4, ram = [14-32]" (is identical to --sizing "cpu=[4-8], ram=[14-32]")
        - --sizing "cpu <= 8, ram ~ 16"
  - `--failover` creates 2 gateways for the network with a VIP used as internal default route

##### `safescale network subnet list [command_options] <network_name_or_id>`
 
List networks created by SafeScale<br>`command_options`:<ul><li>`--all` List all network existing on the current tenant (not only those created by SafeScale)</li></ul>examples:<br><br>`$ safescale network list`<br>response:<br> `{"result":[{"cidr":"192.168.0.0/24","gateway_id":"48112419-3bc3-46f5-a64d-3634dd8bb1be","id":"76ee12d6-e0fa-4286-8da1-242e6e95844e","name":"example_network","virtual_ip":{}}],"status":"success"}`<br><br>`safescale network list --all`<br>response:<br>`{"result":[{"cidr":"192.168.0.0/24","id":"76ee12d6-e0fa-4286-8da1-242e6e95844e","name":"example_network","virtual_ip":{}},{"cidr":"10.0.0.0/16","id":"eb5979e8-6ac6-4436-88d6-c36e3a949083","name":"not_managed_by_safescale","virtual_ip":{}}],"status":"success"}` |

##### `safescale network subnet inspect <network_name_or_id> <subnet_name_or_id>`
Inspect a `Subnet`, returning meaningful information about it.

example:
    
```bash
$ safescale network subnet inspect example_network example_subnet
```
response on success:
```json
REVIEW_ME: {"result":{"cidr":"192.168.0.0/24","gateway_id":"48112419-3bc3-46f5-a64d-3634dd8bb1be","gateway_name":"gw-example_network","id":"76ee12d6-e0fa-4286-8da1-242e6e95844e","name":"example_subnet"},"status":"success"}
```
    
response on failure:
```json
{"error":{"exitcode":6,"message":"Failed to find 'networks/byName/fake_network'"},"result":null,"status":"failure"}
```

##### `safescale network subnet delete <network_name_or_id> <subnet_name_or_id>`
Delete the `Subnet` whose name or id is given.

example:

    `$ safescale network subnet delete example_network example_subnet`
    
response on success:

    `{"result":null,"status":"success"}`
    
response on failure (`Subnet` does not exist):

REVIEW_ME:    `{"error":{"exitcode":6,"message":"Failed to find 'subnets/byName/example_subnet'"},"result":null,"status":"failure"}`

##### `safescale network security group create <network_name_or_id> <security_group_name>`
TODO
##### `safescale network security group delete <network_name_or_id> <security_group_name_or_id>`
TODO
##### `safescale network security group inspect <network_name_or_id> <security_group_name_or_id>`
TODO
##### `safescale network security group list <network_name_or_id>`
TODO
##### `safescale network security group clear <network_name_or_id> <security_group_name_or_id>`
TODO
##### `safescale network security group bonds <network_name_or_id> <security_group_name_or_id>`
TODO
##### `safescale network security group rule add <network_name_or_id> <security_group_name_or_id>`
TODO
##### `safescale network security group rule delete <network_name_or_id> <security_group_name_or_id>`
TODO

<br><br>
--- 
#### host

This command family deals with host management: creation, list, connection, deletion...
The following actions are proposed:

| <div style="width:350px">actions</div> | description |
| --- | --- |
| `safescale [global_options] host create <host_name> [command_options] `|Creates a new host. This host will be attached on the given network. Note that by default this host is created with a private IP address.<br>`command_options`:<ul><li>`--net <network_name>` specifies the network to connect the host to. Can't be used with `--public`.</li><li>`--public` creates the host with public IP; cannot be used with `--net`.</li><li>`-S <sizing>, --sizing <sizing>` describes sizing of host in format `"<component><operator><value>[,...]"` where:<ul><li>`<component>` can be `cpu`, `cpufreq`, `gpu`, `ram`, `disk`</li><li>`<operator>` can be `=`,`~`,`<`,`<=`,`>`,`>=` (except for disk where valid operators are only `=` or `>=`):<ul><li>`=` means exactly `<value>`</li><li>`~` means between `<value>` and 2x`<value>`</li><li>`<` means strictly lower than `<value>`</li><li>`<=` means lower or equal to `<value>`</li><li>`>` means strictly greater than `<value>`</li><li>`>=` means greater or equal to `<value>`</li></ul></li><li>`<value>` can be an integer (for `cpu`, `cpufreq`, `gpu` and `disk`) or a float (for `ram`) or an including interval `[<lower value> - <upper value>]`</li><li>`<cpu>` is expecting an integer as number of cpu cores, or an interval with minimum and maximum number of cpu cores</li><li>`<cpufreq>` is expecting an integer as minimum cpu frequency in MHz</li><li>`<gpu>` is expecting an integer as number of GPU (scanner would have been run first to be able to determine which template proposes GPU)</li><li>`<ram>` is expecting a float as memory size in GB, or an interval with minimum and maximum memory size</li><li>`<disk>` is expecting an integer as system disk size in GB</li>examples:<ul><li>--sizing "cpu <= 4, ram <= 10, disk >= 100"</li><li>--sizing "cpu ~ 4, ram = [14-32]" (is identical to --sizing "cpu=[4-8], ram=[14-32]")</li><li>--sizing "cpu <= 8, ram ~ 16"</li></ul></ul></li><li>`--os value` Image name for the host (default: "Ubuntu 18.04")</li></ul>! DEPRECATED ! use `--sizing` instead<ul><li>`--cpu value` Number of CPU for the host (default: 1)</li><li>`--cpu-freq value` CPU frequence (default :0)  -----  [scanner](SCANNER.md) needed</li><li>`--ram value` RAM for the host (default: 1 Go)</li><li>`--disk value` Disk space for the host (default: 100 Mo)</li><li>`--gpu value` Number of GPU for the host (default :0)  ----- [scanner](SCANNER.md) needed</li></ul>Example:<br><br>`safescale host create --net example_network myhost`<br>response on success:<br>`{"result":{"cpu":1,"disk":10,"gateway_id":"48112419-3bc3-46f5-a64d-3634dd8bb1be","id":"8afd43aa-1747-4f7b-a0a5-1fc89a4ac7e3","name":"myhost","password":"xxxxxxxxxx","private_ip":"192.168.0.196","private_key":"-----BEGIN RSA PRIVATE KEY----- ... -----END RSA PRIVATE KEY-----\n","ram":2,"state":2},"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":1,"message":"Failed to create host 'example_host': name is already used","result":null,"status":"failure"}`
`safescale host list [options]` | List hosts<br>`command_options`:<ul><li>`--all` List all existing hosts on the current tenant (not only those created by SafeScale)</li></ul>Examples:<br><br>`$ safescale host list`<br>response:<br>`{"result":[{"cpu":1,"disk":10,"id":"39a5043a-1790-4a4f-bb87-788bb7252d13","name":"gw-example_network","password":"xxxxxxxxxxxxxxx","private_ip":"192.168.0.220","public_ip":"51.83.34.22","ram":2},{"cpu":1,"disk":10,"id":"abcaa3df-6f86-4533-9a29-6e20e16fd957","name":"myhost","password":"xxxxxxxxxx","private_ip":"192.168.0.169","ram":2}],"status":"success"}`<br><br>`$ safescale host list --all`<br>response:<br>`{"result":[{"id":"39b1706d-e2a1-4ecf-aa23-f2c990a5d5f1","name":"b2-7-sbg5"},{"id":"abcaa3df-6f86-4533-9a29-6e20e16fd957","name":"myhost"},{"id":"39a5043a-1790-4a4f-bb87-788bb7252d13","name":"gw-example_network","public_ip":"51.83.34.22"}],"status":"success"}`| Get detailed information about a host<br><br>Example:<br><br>`$ safescale host inspect example_host`<br>response on success:<br>`{"result":{"cpu":1,"disk":10,"gateway_id":"39a5043a-1790-4a4f-bb87-788bb7252d13","id":"abcaa3df-6f86-4533-9a29-6e20e16fd957","name":"myhost","password":"xxxxxxxxxxxx","private_ip":"192.168.0.169","private_key":"-----BEGIN RSA PRIVATE KEY----- ... -----END RSA PRIVATE KEY-----\n","ram":2,"state":2},"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":6,"message":"Cannot inspect host: failed to find host 'myhost'"},"result":null,"status":"failure"}` |
| `safescale host ssh <host_name_or_id>`| Get SSH configuration to connect to host (for use without SafeScale for example)<br><br>Example:<br><br>`$ safescale host ssh myhost`<br>response on success:<br>`{"result":{"GatewayConfig":{"GatewayConfig":null,"Host":"51.83.34.22","LocalPort":0,"Port":22,"PrivateKey":"-----BEGIN RSA PRIVATE KEY----- ... -----END RSA PRIVATE KEY-----\n","User":"safescale"},"Host":"192.168.0.169","LocalPort":0,"Port":22,"PrivateKey":"-----BEGIN RSA PRIVATE KEY----- ... -----END RSA PRIVATE KEY-----\n","User":"safescale"},"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":6,"message":"Failed to find 'hosts/byName/myhost'"},"result":null,"status":"failure"}` |
| `safescale host delete <host_name_or_id> [...]`| Delete host(s)<br><br>Example:<br><br>`$ safescale host delete myhost`<br>response on success:<br>`{"result":null,"status":"success"}`<br>response on failure :<br>`{"error":{"exitcode":6,"message":"Failed to find host 'myhost'"},"result":null,"status":"failure"}` |
| `safescale host check-feature <host_name_or_id> <feature_name> [command_options]`| Check if a feature is present on the host<br>`command_options`:<ul><li>`-p "<PARAM>=<VALUE>"` Sets the value of a parameter required by the feature</li></ul>Example:<br><br>`$ safescale host check-feature myhost docker`<br>response if feature is present:<br>`{"result":null,"status":"success"}`<br>response if feature is not present:<br>`{"error":{"exitcode":4,"message":"Feature 'docker' not found on host 'myhost'"},"result":null,"status":"failure"}` |
| `safescale [global_options] host add-feature <host_name_or_id> <feature_name> [command_options]`| Adds the feature to the host<br>`command_options`:<ul><li>`-p "<PARAM>=<VALUE>"` Sets the value of a parameter required by the feature</li><li>`--skip-proxy` disables the application of (optional) reverse proxy rules defined in the feature</ul>Example:<br><br>`$ safescale host add-feature myhost remotedesktop -p Username=<username> -p Password=<password>`<br>response on success:`{"result":null,"status":"success"}`<br>response on failure may vary. |
| `safescale host delete-feature <host_name_or_id> <feature_name> [command_options]`| Deletes the feature from the host<br>`command_options`:<ul><li>`-p "<PARAM>=<VALUE>"` Sets the value of a parameter required by the feature</li></ul>Example:<br><br>`$ safescale host delete-feature myhost remotedesktop -p Username=<username> -p Password=<password>`<br>response on success:<br>`{"result":null,"status":"success"}`<br>response on failure may vary. |

<br><br>

#### volume

This command family deals with volume (i.e. block storage) management: creation, list, attachment to a host, deletion...
The following actions are proposed:

| <div style="width:350px">actions</div> | description |
| --- | --- |
| `safescale volume create <volume_name> [command_options] `|Create a volume with the given name on the current tenant using default sizing values.<br>`command_options`:<br><ul><li>`--size value` Size of the volume (in Go) (default: 10)</li><li>`--speed value` Allowed values: SSD, HDD, COLD (default: "HDD")</li></ul>Example:<br><br>`$ safescale volume create myvolume`<br>response on success:<br>`{"result":{"ID":"c409033f-e569-42f5-927a-5b1c35029500","Name":"myvolume","Size":10,"Speed":"HDD"},"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":6,"message":"Volume 'myvolume' already exists"},"result":null,"status":"failure"}` |
| `safescale volume list`|List available volumes<br><br>Example:<br><br>`$ safescale volume list`<br>response:<br>`{"result":[{"id":"4463647d-035b-4e16-8ea9-b3c29acd1887","name":"myvolume","size":10,"speed":1}],"status":"success"}` |
| `safescale volume inspect <volume_name_or_id>`|Get info about a volume.<br><br>Example:<br><br>`$ safescale volume inspect myvolume`<br>response on success:<br>`{"result":{"Device":"03f6d07b-f0b1-47f5-9dce-6063ed0865da","Format":"nfs","Host":"myhost","ID":"4463647d-035b-4e16-8ea9-b3c29acd1887","MountPath":"/data/myvolume","Name":"myvolume","Size":10,"Speed":"HDD"},"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":6,"message":"Failed to find volume 'myvolume'"},"result":null,"status":"failure"}` |
| `safescale volume attach <volume_name_or_id> <host_name_or_id> [command_options] `|Attach the volume to a host. It mounts the volume on a directory of the host. The directory is created if it does not already exists. The volume is formatted by default.<br>`command_options`:<ul><li>`--path value` Mount point of the volume (default: "/shared/<volume_name>)</li><li>`--format value` Filesystem format (default: "ext4")</li><li>`--do-not-format` instructs not to format the volume.</li></ul>Example:<br><br>`$ safescale volume attach myvolume myhost`<br>response on success:<br>`{"result":null,"status":"success"}`<br>response on failure (volume not found):<br>`{"error":{"exitcode":6,"message":"Failed to find volume 'myvolume'"},"result":null,"status":"failure"}`<br>response on failure (host not found):<br>`{"error":{"exitcode":6,"message":"Failed to find host 'myhost2'"},"result":null,"status":"failure"}` |
| `safescale volume detach <volume_name_or_id> <host_name_or_id>`|Detach a volume from a host<br><br>Example:<br><br>`$ safescale volume detach myvolume myhost`<br>response on success:<br>`{"result":null,"status":"success"}`<br>response on failure (volume not found):<br>`{"error":{"exitcode":6,"message":"Failed to find volume 'myvolume'"},"result":null,"status":"failure"}`<br>response on failure (host not found):<br>`{"error":{"exitcode":6,"message":"Failed to find host 'myhost'"},"result":null,"status":"failure"}`<br>response on failure (volume not attached to host):<br>`{"error":{"exitcode":6,"message":"Cannot detach volume 'myvolume': not attached to host 'myhost'"},"result":null,"status":"failure"}` |
| `safescale volume delete <volume_name_or_id>`|Delete the volume with the given name.<br><br>Example:<br><br>`$ safescale volume delete myvolume`<br>response on success:<br>`{"result":null,"status":"success"}`<br>response on failure (volume attached):<br>`{"error":{"exitcode":6,"message":"Cannot delete volume 'myvolume': still attached to 1 host: myhost"},"result":null,"status":"failure"}`<br>response on failure (volume not found):<br>`{"error":{"exitcode":6,"message":"Cannot delete volume 'myvolume': failed to find volume 'myvolume'"},"result":null,"status":"failure"}` |

<br><br>

#### share

This command familly deals with share management: creation, list, deletion...
The following actions are proposed:

| <div style="width:350px">actions</div> | description |
| --- | --- |
| `safescale [global_options] share list`|List existing shares<br><br>Example:<br><br>`$ safescale share list`<br>response:<br>`{"result":[{"host":{"name":"myhost"},"id":"d8eed474-dc3b-4a4d-91e6-91dd03cd98dd","name":"myshare","path":"/shared/data","type":"nfs"}],"status":"success"}` |
| `safescale [global_options] share inspect <share_name>`|Get detailed information about the share.<br><br>Example:<br><br>`$ safescale share inspect myshare`<br>response on success:<br>`{"result":{"mount_list":[{"host":{"name":"myclient"},"path":"/shared","share":{"name":"myshare"},"type":"nfs"}],"share":{"host":{"name":"myhost"},"id":"d8eed474-dc3b-4a4d-91e6-91dd03cd98dd","name":"myshare","path":"/shared/data","type":"nfs"}},"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":6,"message":"cannot inspect share 'myshare' [caused by {failed to find share 'myshare'}]"},"result":null,"status":"failure"}` |
| `safescale [global_options] share create <share_name> <host_name_or_id> [command_options] `|Create a share on a host and export the corresponding folder<br>`command_options`:<ul><li>`--path value` Path to be exported (default: "/shared/data")</li></ul>Example:<br><br>`$ safescale share create myshare myhost`<br>response on success:<br>`{"result":null,"status":"success"}`<br>reponse on failure:<br>`{"error":{"exitcode":6,"message":"cannot create share 'myshare' [caused by {share 'myshare' already exists}]"},"result":null,"status":"failure"}` |
| `safescale [global_options] share mount <share_name> <host_name_or_id> [command_options] `|Mount an exported nfs directory on a host<br>`command_options`:<ul><li>`--path value` Path to mount nfs directory on (default: /data)</li></ul>Example:<br><br>`$ safescale share mount myshare myclient`<br>response on success:<br>`{"result":null,"status":"success"}`<br>response on failure (share not found):<br>`{"error":{"exitcode":6,"message":"cannot unmount share 'myshare' [caused by {failed to find share 'myshare'}]"},"result":null,"status":"failure"}`<br>response on failure (host not found):<br>`{"error":{"exitcode":6,"message":"cannot unmount share 'myshare' [caused by {failed to find host 'myclient'}]"},"result":null,"status":"failure"}` |
| `safescale [global_options] share umount <share_name> <host_name_or_id>`|Unmount an exported nfs directory on a host<br><br>Example:<br><br>`$ safescale share umount myshare myclient`<br>response on success:<br>`{"result":null,"status":"success"}`<br>response on failure (host not found):<br>`{"error":{"exitcode":6,"message":"cannot unmount share 'myshare' [caused by {failed to find host 'myclient'}]"},"result":null,"status":"failure"}`<br>response on failure (share not found):<br>`{"error":{"exitcode":6,"message":"cannot unmount share 'myshare' [caused by {failed to find share 'myshare'}]"},"result":null,"status":"failure"}` |
| `safescale [global_options] share delete <share_name>`|Delete a nfs server by unexposing directory<br><br>Example:<br><br>`$ safescale share delete myshare`<br>response on success:<br>`{"result":null,"status":"success"}`<br>response on failure (share still mounted):<br>`{"error":{"exitcode":6,"message":"error while deleting share myshare: Cannot delete share 'myshare' [caused by {still used by: 'myclient'}]"},"result":null,"status":"failure"}`<br>response on failure (share not found):<br>`{"error":{"exitcode":6,"message":"error while deleting share myshare: Failed to find share 'myshare'"},"result":null,"status":"failure"}` |

<br><br>

<!-- #### <a name="safescale_data"></a>data
This command familly aims to push data on object storage on a secured way with data encryption (AES-256/RSA-2048) and & data replication(erasure coding/ several object storage).<br>
As we want to push datas on several object storage we fist have to set [tenantStorage](#safescale_tenant)<br>
All the files are crypted with a key stored on $HOME/.safescale/rsa.key (if the key didn't exists, pushing a file will generate one)<br>
The following actions are proposed:

action | description
--- | ---
`safescale [global_options] data push [command-options] <file_path>`| Push a file on several object storage with encryption and erasure coding<br>`command_options`:<ul><li>`--file-name value`File name on the object storage</li></ul>
`safescale [global_options] data get [command-options] <file_name>`| Get a file pushed by 'safescale data push'<br>`command_options`:<ul><li>`--storage-path value` File where the datas will be stored</li></ul>
`safescale [global_options] data delete <file_name>`| Delete a files pushed by 'safescale data push'
`safescale [global_options] data list`| List all files pushed by 'safescale data push'
-->

#### bucket

This command familly deals with object storage management: creation, list, mounting as filesystem, deleting...
The following actions are proposed:

| <div style="width:350px;">actions</div> | description |
| --- | --- |
| `safescale [global_options] bucket create <bucket_name>`| Create a bucket<br><br>Example:<br><br>`$ safescale bucket create mybucket`<br>response on success:<br>`{"result":null,"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":6,"message":"Cannot create bucket [caused by {bucket 'mybucket' already exists}]"},"result":null,"status":"failure"}` |
| `safescale [global_options] bucket list`| List buckets<br><br>Example:<br><br>`$ safescale bucket list`<br>response:<br> `{"result":{"buckets":[{"name":"0.safescale-96d245d7cf98171f14f4bc0abd8f8019"},{"name":"mybucket"}]},"status":"success"}` |
| `safescale [global_options] bucket inspect <bucket_name>`| Get info about a bucket<br><br>Example:<br><br>`$ safescale bucket inspect mybucket`<br>response on success:<br>`{"result":{"bucket":"mybucket","host":{}},"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":6,"message":"Cannot inspect bucket [caused by {failed to find bucket 'mybucket'}]"},"result":null,"status":"failure"}` |
| `safescale [global_options] bucket mount <bucket_name> <host_name_or_id> [command_options] `| Mount a bucket as a filesystem on a host.<br>`command_options`:<ul><li>`--path value` Mount point of the bucket (default: "/buckets/<bucket_name>"</li></ul>Example:<br><br>`$ safescale bucket mount mybucket myhost`<br>response on success:<br>`{"result":null,"status":"success"}`<br>response on failure (host not found):<br>`{"error":{"exitcode":6,"message":"No host found with name or id 'myhost2'"},"result":null,"status":"failure"}`<br><br>response on failure (bucket not found):<br>`{"error":{"exitcode":6,"message":"Not found"},"result":null,"status":"failure"}` |
| `safescale [global_options] bucket umount <bucket_name> <host_name_or_id>`| Umount a bucket from the filesystem of a host.<br><br>Example:<br><br>`$ safescale bucket umount mybucket myhost`<br>response on success:<br>`{"result":null,"status":"success"}`<br><br>response on failure (bucket not found):<br>`{"error":{"exitcode":6,"message":"Failed to find bucket 'mybucket'"},"result":null,"status":"failure"}`<br>response on failure (host not found):<br>`{"error":{"exitcode":6,"message":"Failed to find host 'myhost'"},"result":null,"status":"failure"}` |
| `safescale [global_options] bucket delete <bucket_name>`| Delete a bucket<br><br>Example:<br><br>`$ safescale bucket delete mybucket`<br>response on success:<br>`{"result":null,"status":"success"}`<br>response on failure (bucket not found):<br>`{"error":{"exitcode":6,"message":"cannot delete bucket [caused by {Container Not Found}]"},"result":null,"status":"failure"}`<br><br>response on failure (bucket mounted on hosts):<br>`{"error":{"exitcode":6,"message":"cannot delete bucket [caused by {Container Not Empty}]"},"result":null,"status":"failure"}` |

<br><br>

#### ssh

The following commands deals with ssh commands to be executed on a host.
The following actions are proposed:

| <div style="width:350px;">actions</div> |description |
| --- | --- |
| `safescale [global_options] ssh run -c "<command>" <host_name_or_id>`|Run a command on the host<br><br>`parameters`:<ul><li>`command` is the command to execute remotely.</li></ul>Example:<br><br>`$ safescale ssh run -c "ls -la ~" example_host`<br>response:<br>`total 32`<br>`drwxr-xr-x 4 safescale safescale 4096 Jun  5 13:25 .`<br>`drwxr-xr-x 4 root root 4096 Jun  5 13:00 ..`<br>`-rw------- 1 safescale safescale   15 Jun  5 13:25 .bash_history`<br>`-rw-r--r-- 1 safescale safescale  220 Aug 31  2015 .bash_logout`<br>`-rw-r--r-- 1 safescale safescale 3771 Aug 31  2015 .bashrc`<br>`drwx------ 2 safescale safescale 4096 Jun  5 13:01 .cache`<br>`-rw-r--r-- 1 safescale safescale    0 Jun  5 13:00 .hushlogin`<br>`-rw-r--r-- 1 safescale safescale  655 May 16  2017 .profile`<br>`drwx------ 2 safescale safescale 4096 Jun  5 13:00 .ssh` |
| `safescale [global_options] ssh copy <src> <dest>`|Copy a local file/directory to a host or copy from host to local<br><br>Example:<br><br>`$ safescale ssh copy /my/local/file example_host:/remote/path` |
| `safescale [global_options] ssh connect <host_name_or_id>`|Connect to the host with interactive shell<br><br>Example:<br><br> `$  safescale ssh connect example_host`<br>response:`safescale@example-Host:~$` |

<br><br>

#### cluster

This command family deals with cluster management: creation, inspection, deletion, ...
`cluster` has synonyms: `platform`, `datacenter`, `dc`.

The following actions are proposed:

| <div style="width:350px;">actions</div> | description |
| --- | --- |
| `safescale [global_options] cluster create <cluster_name> [command_options]`|Creates a new cluster.<br><br>`command_options`:<ul><li>`-F\|--flavor <flavor>` defines the "flavor" of the cluster. `<flavor>` can be `BOH` (Bunch Of Hosts, without any cluster management layer), `SWARM` (Docker Swarm cluster), `K8S` (Kubernetes, default)</li><li>`-N\|--cidr <network_CIDR>` defines the CIDR of the network for the cluster.</li><li>`-C\|--complexity <complexity>` defines the "complexity" of the cluster, ie how many masters/nodes will be created (depending of cluster flavor). Valid values are `small`, `normal`, `large`.</li><li>`--disable <value>` Allows to disable addition of default features (must be used several times to disable several features)<br>Accepted `<value>`s are:<ul><li>`remotedesktop` (all flavors)</li><li>`reverseproxy` (all flavors)</li><li>`gateway-failover` (all flavors with Normal or Large complexity)</li><li>`hardening` (flavor K8S)</li><li>`helm` (flavor K8S)</li></ul></li><li>`--os value` Image name for the servers (default: "Ubuntu 18.04", may be overriden by a cluster flavor)</li><li>`-k` keeps infrastructure created on failure; default behavior is to delete resources<li>`-S|--sizing <sizing>` describes sizing of all hosts in format `"<component><operator><value>[,...]"` where:<ul><li>`<component>` can be `cpu`, `cpufreq`, `gpu`, `ram`, `disk`</li><li>`<operator>` can be `=`,`~`,`<`,`<=`,`>`,`>=` (except for disk where valid operators are only `=` or `>=`):<ul><li>`=` means exactly `<value>`</li><li>`~` means between `<value>` and 2x`<value>`</li><li>`<` means strictly lower than `<value>`</li><li>`<=` means lower or equal to `<value>`</li><li>`>` means strictly greater than `<value>`</li><li>`>=` means greater or equal to `<value>`</li></ul></li><li>`<value>` can be an integer (for `cpu`, `cpufreq`, `gpu` and `disk`) or a float (for `ram`) or an including interval `[<lower value>-<upper value>]`</li><li>`<cpu>` is expecting an integer as number of cpu cores, or an interval with minimum and maximum number of cpu cores</li><li>`<cpufreq>` is expecting an integer of CPU frequency in MHz</li><li>`<gpu>` is expecting an integer as number of GPU (scanner would have been run first to be able to determine which template proposes GPU)</li><li>`<ram>` is expecting a float as memory size in GB, or an interval with minimum and maximum memory size</li><li>`<disk>` is expecting an integer as system disk size in GB</li>examples:<ul><li>--sizing "cpu <= 4, ram <= 10, disk >= 100"</li><li>--sizing "cpu ~ 4, ram = [14-32]" (is identical to --sizing "cpu=[4-8], ram=[14-32]")</li><li>--sizing "cpu <= 8, ram ~ 16"</li></ul></ul></li><li>`--gw-sizing <sizing>` Describes gateway sizing specifically (following `--sizing` format)</li><li>`--master-sizing <sizing>` Describes master sizing specifically (following `--sizing` format)</li><li>`--node-sizing <sizing>` Describes node sizing specifically (following `--sizing` format)</li></ul>! DEPRECATED ! use `--sizing`, `--gw-sizing`, `--master-sizing` and `--node-sizing` instead<ul><li>`--cpu <value>` Number of CPU for masters and nodes (default depending of cluster flavor)</li><li>`--ram value` RAM for the host (default: 1 Go)</li><li>`--disk value` Disk space for the host (default depending of cluster flavor)</li></ul><br>Example:<br><br>`$ safescale cluster create mycluster -F k8s -C small -N 192.168.22.0/24`<br>response on success:<br>`{"result":{"admin_login":"cladm","admin_password":"xxxxxxxxxxxx","cidr":"192.168.0.0/16","complexity":1,"complexity_label":"Small","default_route_ip":"192.168.2.245","endpoint_ip":"51.83.34.144","features":{"disabled":{"proxycache":{}},"installed":{}},"flavor":2,"flavor_label":"K8S","gateway_ip":"192.168.2.245","last_state":5,"last_state_label":"Created","name":"mycluster","network_id":"6669a8db-db31-4272-9acd-da49dca07e14","nodes":{"masters":[{"id":"9874cbc6-bd17-4473-9552-1f7c9c7a2d6f","name":"vpl-k8s-master-1","private_ip":"192.168.0.86","public_ip":""}],"nodes":[{"id":"019d2bcc-9d8c-4c76-a638-cf5612322dfa","name":"vpl-k8s-node-1","private_ip":"192.168.1.74","public_ip":""}]},"primary_gateway_ip":"192.168.2.245","primary_public_ip":"51.83.34.144","remote_desktop":{"vpl-k8s-master-1":["https://51.83.34.144/_platform/remotedesktop/vpl-k8s-master-1/"]},"tenant":"TestOVH"},"status":"success"}`<br>response on failure (cluster already exists):<br>`{"error":{"exitcode":8,"message":"Cluster 'mycluster' already exists.\n"},"result":null,"status":"failure"}` |
| `safescale [global_options] cluster list` | List clusters<br><br>Example:<br><br>`$ safescale cluster list`<br>response:<br>`{"result":[{"cidr":"192.168.0.0/16","complexity":1,"complexity_label":"Small","default_route_ip":"192.168.2.245","endpoint_ip":"51.83.34.144","flavor":2,"flavor_label":"K8S","last_state":5,"last_state_label":"Created","name":"mycluster","primary_gateway_ip":"192.168.2.245","primary_public_ip":"51.83.34.144","remote_desktop":{"mycluster-master-1":["https://51.83.34.144/_platform/remotedesktop/mycluster-master-1/"]},"tenant":"TestOVH"}],"status":"success"}` |
| `safescale [global_options] cluster inspect <cluster_name>`| Get info about a cluster<br><br>Example:<br><br>`$ safescale cluster inspect mycluster`<br>response on success:<br>`{"result":{"admin_login":"cladm","admin_password":"xxxxxxxxxxxxxx","cidr":"192.168.0.0/16","complexity":1,"complexity_label":"Small","default_route_ip":"192.168.2.245","defaults":{"gateway":{"max_cores":4,"max_ram_size":16,"min_cores":2,"min_disk_size":50,"min_gpu":-1,"min_ram_size":7},"image":"Ubuntu 18.04","master":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15},"node":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15}},"endpoint_ip":"51.83.34.144","features":{"disabled":{"proxycache":{}},"installed":{}},"flavor":2,"flavor_label":"K8S","gateway_ip":"192.168.2.245","last_state":5,"last_state_label":"Created","name":"mycluster","network_id":"6669a8db-db31-4272-9acd-da49dca07e14","nodes":{"masters":[{"id":"9874cbc6-bd17-4473-9552-1f7c9c7a2d6f","name":"mycluster-master-1","private_ip":"192.168.0.86","public_ip":""}],"nodes":[{"id":"019d2bcc-9d8c-4c76-a638-cf5612322dfa","name":"mycluster-node-1","private_ip":"192.168.1.74","public_ip":""}]},"primary_gateway_ip":"192.168.2.245","primary_public_ip":"51.83.34.144","remote_desktop":{"mycluster-master-1":["https://51.83.34.144/_platform/remotedesktop/mycluster-master-1/"]},"tenant":"TestOVH"},"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}` |
| `safescale [global_options] cluster state <cluster_name>`| REVIEW_ME: Get info about a cluster<br><br>Example:<br><br>`$ safescale cluster inspect mycluster`<br>response on success:<br>`{"result":{"admin_login":"cladm","admin_password":"xxxxxxxxxxxxxx","cidr":"192.168.0.0/16","complexity":1,"complexity_label":"Small","default_route_ip":"192.168.2.245","defaults":{"gateway":{"max_cores":4,"max_ram_size":16,"min_cores":2,"min_disk_size":50,"min_gpu":-1,"min_ram_size":7},"image":"Ubuntu 18.04","master":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15},"node":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15}},"endpoint_ip":"51.83.34.144","features":{"disabled":{"proxycache":{}},"installed":{}},"flavor":2,"flavor_label":"K8S","gateway_ip":"192.168.2.245","last_state":5,"last_state_label":"Created","name":"mycluster","network_id":"6669a8db-db31-4272-9acd-da49dca07e14","nodes":{"masters":[{"id":"9874cbc6-bd17-4473-9552-1f7c9c7a2d6f","name":"mycluster-master-1","private_ip":"192.168.0.86","public_ip":""}],"nodes":[{"id":"019d2bcc-9d8c-4c76-a638-cf5612322dfa","name":"mycluster-node-1","private_ip":"192.168.1.74","public_ip":""}]},"primary_gateway_ip":"192.168.2.245","primary_public_ip":"51.83.34.144","remote_desktop":{"mycluster-master-1":["https://51.83.34.144/_platform/remotedesktop/mycluster-master-1/"]},"tenant":"TestOVH"},"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}` |
| `safescale [global_options] cluster delete <cluster_name> [command_options]`| Delete a cluster. By default, ask for user confirmation before doing anything<br><br>`command_options`:<ul><li>`-y` disables the confirmation</li></ul>Example:<br><br>`$ safescale cluster delete mycluster -y`<br>response on success:<br>`{"result":null,"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}` |
| `safescale [global_options] cluster feature check <cluster_name> <feature_name> [command_options]`|Check if a feature is present on the cluster<br><br>`command_options`:<ul><li>`-p "<PARAM>=<VALUE>"` Sets the value of a parameter required by the feature</li></ul>Example:<br>`$ safescale cluster check-feature mycluster docker`<br>response on success:<br>`{"result":"Feature 'docker' found on cluster 'mycluster'","status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":4,"message":"Feature 'docker' not found on cluster 'mcluster'"},"result":null,"status":"failure"}` |
| `safescale [global_options] cluster feature add <cluster_name> <feature_name> [command_options]`|Adds a feature to the cluster<br><br>`command_options`:<ul><li>`-p "<PARAM>=<VALUE>"` Sets the value of a parameter required by the feature</li><li>`--skip-proxy` disables the application of (optional) reverse proxy rules inside the feature</ul>Example:<br><br>`$ safescale cluster add-feature mycluster remotedesktop`<br>response on success: `{"result":null,"status":"success"}`<br>response on failure may vary |
| `safescale [global_options] cluster feature delete <cluster_name> <feature_name> [command_options]`|Deletes a feature from a cluster<br><br>`command_options`:<ul><li>`-p "<PARAM>=<VALUE>"` Sets the value of a parameter required by the feature</li></ul>Example:<br><br>`$ safescale cluster delete-feature my-cluster remote-desktop`<br>response on success:<br>`{"result":null,"status":"success"}`<br>response on failure may vary |
| `safescale [global_options] cluster expand [command_options] <cluster_name>`| REVIEW_ME:Get info about a cluster<br><br>Example:<br><br>`$ safescale cluster inspect mycluster`<br>response on success:<br>`{"result":{"admin_login":"cladm","admin_password":"xxxxxxxxxxxxxx","cidr":"192.168.0.0/16","complexity":1,"complexity_label":"Small","default_route_ip":"192.168.2.245","defaults":{"gateway":{"max_cores":4,"max_ram_size":16,"min_cores":2,"min_disk_size":50,"min_gpu":-1,"min_ram_size":7},"image":"Ubuntu 18.04","master":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15},"node":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15}},"endpoint_ip":"51.83.34.144","features":{"disabled":{"proxycache":{}},"installed":{}},"flavor":2,"flavor_label":"K8S","gateway_ip":"192.168.2.245","last_state":5,"last_state_label":"Created","name":"mycluster","network_id":"6669a8db-db31-4272-9acd-da49dca07e14","nodes":{"masters":[{"id":"9874cbc6-bd17-4473-9552-1f7c9c7a2d6f","name":"mycluster-master-1","private_ip":"192.168.0.86","public_ip":""}],"nodes":[{"id":"019d2bcc-9d8c-4c76-a638-cf5612322dfa","name":"mycluster-node-1","private_ip":"192.168.1.74","public_ip":""}]},"primary_gateway_ip":"192.168.2.245","primary_public_ip":"51.83.34.144","remote_desktop":{"mycluster-master-1":["https://51.83.34.144/_platform/remotedesktop/mycluster-master-1/"]},"tenant":"TestOVH"},"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}` |
| `safescale [global_options] cluster shrink [command_options] <cluster_name>`| REVIEW_ME: Get info about a cluster<br><br>Example:<br><br>`$ safescale cluster inspect mycluster`<br>response on success:<br>`{"result":{"admin_login":"cladm","admin_password":"xxxxxxxxxxxxxx","cidr":"192.168.0.0/16","complexity":1,"complexity_label":"Small","default_route_ip":"192.168.2.245","defaults":{"gateway":{"max_cores":4,"max_ram_size":16,"min_cores":2,"min_disk_size":50,"min_gpu":-1,"min_ram_size":7},"image":"Ubuntu 18.04","master":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15},"node":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15}},"endpoint_ip":"51.83.34.144","features":{"disabled":{"proxycache":{}},"installed":{}},"flavor":2,"flavor_label":"K8S","gateway_ip":"192.168.2.245","last_state":5,"last_state_label":"Created","name":"mycluster","network_id":"6669a8db-db31-4272-9acd-da49dca07e14","nodes":{"masters":[{"id":"9874cbc6-bd17-4473-9552-1f7c9c7a2d6f","name":"mycluster-master-1","private_ip":"192.168.0.86","public_ip":""}],"nodes":[{"id":"019d2bcc-9d8c-4c76-a638-cf5612322dfa","name":"mycluster-node-1","private_ip":"192.168.1.74","public_ip":""}]},"primary_gateway_ip":"192.168.2.245","primary_public_ip":"51.83.34.144","remote_desktop":{"mycluster-master-1":["https://51.83.34.144/_platform/remotedesktop/mycluster-master-1/"]},"tenant":"TestOVH"},"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}` |
| `safescale [global_options] cluster stop [command_options] <cluster_name>`| REVIEW_ME:Get info about a cluster<br><br>Example:<br><br>`$ safescale cluster inspect mycluster`<br>response on success:<br>`{"result":{"admin_login":"cladm","admin_password":"xxxxxxxxxxxxxx","cidr":"192.168.0.0/16","complexity":1,"complexity_label":"Small","default_route_ip":"192.168.2.245","defaults":{"gateway":{"max_cores":4,"max_ram_size":16,"min_cores":2,"min_disk_size":50,"min_gpu":-1,"min_ram_size":7},"image":"Ubuntu 18.04","master":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15},"node":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15}},"endpoint_ip":"51.83.34.144","features":{"disabled":{"proxycache":{}},"installed":{}},"flavor":2,"flavor_label":"K8S","gateway_ip":"192.168.2.245","last_state":5,"last_state_label":"Created","name":"mycluster","network_id":"6669a8db-db31-4272-9acd-da49dca07e14","nodes":{"masters":[{"id":"9874cbc6-bd17-4473-9552-1f7c9c7a2d6f","name":"mycluster-master-1","private_ip":"192.168.0.86","public_ip":""}],"nodes":[{"id":"019d2bcc-9d8c-4c76-a638-cf5612322dfa","name":"mycluster-node-1","private_ip":"192.168.1.74","public_ip":""}]},"primary_gateway_ip":"192.168.2.245","primary_public_ip":"51.83.34.144","remote_desktop":{"mycluster-master-1":["https://51.83.34.144/_platform/remotedesktop/mycluster-master-1/"]},"tenant":"TestOVH"},"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}` |
| `safescale [global_options] cluster start [command_options] <cluster_name>`| REVIEW_ME:Get info about a cluster<br><br>Example:<br><br>`$ safescale cluster inspect mycluster`<br>response on success:<br>`{"result":{"admin_login":"cladm","admin_password":"xxxxxxxxxxxxxx","cidr":"192.168.0.0/16","complexity":1,"complexity_label":"Small","default_route_ip":"192.168.2.245","defaults":{"gateway":{"max_cores":4,"max_ram_size":16,"min_cores":2,"min_disk_size":50,"min_gpu":-1,"min_ram_size":7},"image":"Ubuntu 18.04","master":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15},"node":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15}},"endpoint_ip":"51.83.34.144","features":{"disabled":{"proxycache":{}},"installed":{}},"flavor":2,"flavor_label":"K8S","gateway_ip":"192.168.2.245","last_state":5,"last_state_label":"Created","name":"mycluster","network_id":"6669a8db-db31-4272-9acd-da49dca07e14","nodes":{"masters":[{"id":"9874cbc6-bd17-4473-9552-1f7c9c7a2d6f","name":"mycluster-master-1","private_ip":"192.168.0.86","public_ip":""}],"nodes":[{"id":"019d2bcc-9d8c-4c76-a638-cf5612322dfa","name":"mycluster-node-1","private_ip":"192.168.1.74","public_ip":""}]},"primary_gateway_ip":"192.168.2.245","primary_public_ip":"51.83.34.144","remote_desktop":{"mycluster-master-1":["https://51.83.34.144/_platform/remotedesktop/mycluster-master-1/"]},"tenant":"TestOVH"},"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}` |
| `safescale [global_options] cluster kubectl [command_options] <cluster_name> -- <kubectl_parameters>` | REVIEW_ME:Get info about a cluster<br><br>Example:<br><br>`$ safescale cluster inspect mycluster`<br>response on success:<br>`{"result":{"admin_login":"cladm","admin_password":"xxxxxxxxxxxxxx","cidr":"192.168.0.0/16","complexity":1,"complexity_label":"Small","default_route_ip":"192.168.2.245","defaults":{"gateway":{"max_cores":4,"max_ram_size":16,"min_cores":2,"min_disk_size":50,"min_gpu":-1,"min_ram_size":7},"image":"Ubuntu 18.04","master":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15},"node":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15}},"endpoint_ip":"51.83.34.144","features":{"disabled":{"proxycache":{}},"installed":{}},"flavor":2,"flavor_label":"K8S","gateway_ip":"192.168.2.245","last_state":5,"last_state_label":"Created","name":"mycluster","network_id":"6669a8db-db31-4272-9acd-da49dca07e14","nodes":{"masters":[{"id":"9874cbc6-bd17-4473-9552-1f7c9c7a2d6f","name":"mycluster-master-1","private_ip":"192.168.0.86","public_ip":""}],"nodes":[{"id":"019d2bcc-9d8c-4c76-a638-cf5612322dfa","name":"mycluster-node-1","private_ip":"192.168.1.74","public_ip":""}]},"primary_gateway_ip":"192.168.2.245","primary_public_ip":"51.83.34.144","remote_desktop":{"mycluster-master-1":["https://51.83.34.144/_platform/remotedesktop/mycluster-master-1/"]},"tenant":"TestOVH"},"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}` |
| `safescale [global_options] cluster helm [command_options] <cluster_name> -- <helm_parameters` | REVIEW_ME: Get info about a cluster<br><br>Example:<br><br>`$ safescale cluster inspect mycluster`<br>response on success:<br>`{"result":{"admin_login":"cladm","admin_password":"xxxxxxxxxxxxxx","cidr":"192.168.0.0/16","complexity":1,"complexity_label":"Small","default_route_ip":"192.168.2.245","defaults":{"gateway":{"max_cores":4,"max_ram_size":16,"min_cores":2,"min_disk_size":50,"min_gpu":-1,"min_ram_size":7},"image":"Ubuntu 18.04","master":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15},"node":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15}},"endpoint_ip":"51.83.34.144","features":{"disabled":{"proxycache":{}},"installed":{}},"flavor":2,"flavor_label":"K8S","gateway_ip":"192.168.2.245","last_state":5,"last_state_label":"Created","name":"mycluster","network_id":"6669a8db-db31-4272-9acd-da49dca07e14","nodes":{"masters":[{"id":"9874cbc6-bd17-4473-9552-1f7c9c7a2d6f","name":"mycluster-master-1","private_ip":"192.168.0.86","public_ip":""}],"nodes":[{"id":"019d2bcc-9d8c-4c76-a638-cf5612322dfa","name":"mycluster-node-1","private_ip":"192.168.1.74","public_ip":""}]},"primary_gateway_ip":"192.168.2.245","primary_public_ip":"51.83.34.144","remote_desktop":{"mycluster-master-1":["https://51.83.34.144/_platform/remotedesktop/mycluster-master-1/"]},"tenant":"TestOVH"},"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}` |
| `safescale [global_options] cluster master list [command_options] <cluster_name>` | REVIEW_ME: Get info about a cluster<br><br>Example:<br><br>`$ safescale cluster inspect mycluster`<br>response on success:<br>`{"result":{"admin_login":"cladm","admin_password":"xxxxxxxxxxxxxx","cidr":"192.168.0.0/16","complexity":1,"complexity_label":"Small","default_route_ip":"192.168.2.245","defaults":{"gateway":{"max_cores":4,"max_ram_size":16,"min_cores":2,"min_disk_size":50,"min_gpu":-1,"min_ram_size":7},"image":"Ubuntu 18.04","master":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15},"node":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15}},"endpoint_ip":"51.83.34.144","features":{"disabled":{"proxycache":{}},"installed":{}},"flavor":2,"flavor_label":"K8S","gateway_ip":"192.168.2.245","last_state":5,"last_state_label":"Created","name":"mycluster","network_id":"6669a8db-db31-4272-9acd-da49dca07e14","nodes":{"masters":[{"id":"9874cbc6-bd17-4473-9552-1f7c9c7a2d6f","name":"mycluster-master-1","private_ip":"192.168.0.86","public_ip":""}],"nodes":[{"id":"019d2bcc-9d8c-4c76-a638-cf5612322dfa","name":"mycluster-node-1","private_ip":"192.168.1.74","public_ip":""}]},"primary_gateway_ip":"192.168.2.245","primary_public_ip":"51.83.34.144","remote_desktop":{"mycluster-master-1":["https://51.83.34.144/_platform/remotedesktop/mycluster-master-1/"]},"tenant":"TestOVH"},"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}` |
| `safescale [global_options] cluster node list [command_options] <cluster_name>` | REVIEW_ME: Get info about a cluster<br><br>Example:<br><br>`$ safescale cluster inspect mycluster`<br>response on success:<br>`{"result":{"admin_login":"cladm","admin_password":"xxxxxxxxxxxxxx","cidr":"192.168.0.0/16","complexity":1,"complexity_label":"Small","default_route_ip":"192.168.2.245","defaults":{"gateway":{"max_cores":4,"max_ram_size":16,"min_cores":2,"min_disk_size":50,"min_gpu":-1,"min_ram_size":7},"image":"Ubuntu 18.04","master":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15},"node":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15}},"endpoint_ip":"51.83.34.144","features":{"disabled":{"proxycache":{}},"installed":{}},"flavor":2,"flavor_label":"K8S","gateway_ip":"192.168.2.245","last_state":5,"last_state_label":"Created","name":"mycluster","network_id":"6669a8db-db31-4272-9acd-da49dca07e14","nodes":{"masters":[{"id":"9874cbc6-bd17-4473-9552-1f7c9c7a2d6f","name":"mycluster-master-1","private_ip":"192.168.0.86","public_ip":""}],"nodes":[{"id":"019d2bcc-9d8c-4c76-a638-cf5612322dfa","name":"mycluster-node-1","private_ip":"192.168.1.74","public_ip":""}]},"primary_gateway_ip":"192.168.2.245","primary_public_ip":"51.83.34.144","remote_desktop":{"mycluster-master-1":["https://51.83.34.144/_platform/remotedesktop/mycluster-master-1/"]},"tenant":"TestOVH"},"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}` |
| `safescale [global_options] cluster node inspect [command_options] <cluster_name> <node_name_or_id>` | REVIEW_ME: Get info about a cluster<br><br>Example:<br><br>`$ safescale cluster inspect mycluster`<br>response on success:<br>`{"result":{"admin_login":"cladm","admin_password":"xxxxxxxxxxxxxx","cidr":"192.168.0.0/16","complexity":1,"complexity_label":"Small","default_route_ip":"192.168.2.245","defaults":{"gateway":{"max_cores":4,"max_ram_size":16,"min_cores":2,"min_disk_size":50,"min_gpu":-1,"min_ram_size":7},"image":"Ubuntu 18.04","master":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15},"node":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15}},"endpoint_ip":"51.83.34.144","features":{"disabled":{"proxycache":{}},"installed":{}},"flavor":2,"flavor_label":"K8S","gateway_ip":"192.168.2.245","last_state":5,"last_state_label":"Created","name":"mycluster","network_id":"6669a8db-db31-4272-9acd-da49dca07e14","nodes":{"masters":[{"id":"9874cbc6-bd17-4473-9552-1f7c9c7a2d6f","name":"mycluster-master-1","private_ip":"192.168.0.86","public_ip":""}],"nodes":[{"id":"019d2bcc-9d8c-4c76-a638-cf5612322dfa","name":"mycluster-node-1","private_ip":"192.168.1.74","public_ip":""}]},"primary_gateway_ip":"192.168.2.245","primary_public_ip":"51.83.34.144","remote_desktop":{"mycluster-master-1":["https://51.83.34.144/_platform/remotedesktop/mycluster-master-1/"]},"tenant":"TestOVH"},"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}` |
| `safescale [global_options] cluster node state [command_options] <cluster_name> <node_name_or_id>` | REVIEW_ME: Get info about a cluster<br><br>Example:<br><br>`$ safescale cluster inspect mycluster`<br>response on success:<br>`{"result":{"admin_login":"cladm","admin_password":"xxxxxxxxxxxxxx","cidr":"192.168.0.0/16","complexity":1,"complexity_label":"Small","default_route_ip":"192.168.2.245","defaults":{"gateway":{"max_cores":4,"max_ram_size":16,"min_cores":2,"min_disk_size":50,"min_gpu":-1,"min_ram_size":7},"image":"Ubuntu 18.04","master":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15},"node":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15}},"endpoint_ip":"51.83.34.144","features":{"disabled":{"proxycache":{}},"installed":{}},"flavor":2,"flavor_label":"K8S","gateway_ip":"192.168.2.245","last_state":5,"last_state_label":"Created","name":"mycluster","network_id":"6669a8db-db31-4272-9acd-da49dca07e14","nodes":{"masters":[{"id":"9874cbc6-bd17-4473-9552-1f7c9c7a2d6f","name":"mycluster-master-1","private_ip":"192.168.0.86","public_ip":""}],"nodes":[{"id":"019d2bcc-9d8c-4c76-a638-cf5612322dfa","name":"mycluster-node-1","private_ip":"192.168.1.74","public_ip":""}]},"primary_gateway_ip":"192.168.2.245","primary_public_ip":"51.83.34.144","remote_desktop":{"mycluster-master-1":["https://51.83.34.144/_platform/remotedesktop/mycluster-master-1/"]},"tenant":"TestOVH"},"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}` |
| `safescale [global_options] cluster node stop [command_options] <cluster_name> <node_name_or_id>` | REVIEW_ME: Get info about a cluster<br><br>Example:<br><br>`$ safescale cluster inspect mycluster`<br>response on success:<br>`{"result":{"admin_login":"cladm","admin_password":"xxxxxxxxxxxxxx","cidr":"192.168.0.0/16","complexity":1,"complexity_label":"Small","default_route_ip":"192.168.2.245","defaults":{"gateway":{"max_cores":4,"max_ram_size":16,"min_cores":2,"min_disk_size":50,"min_gpu":-1,"min_ram_size":7},"image":"Ubuntu 18.04","master":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15},"node":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15}},"endpoint_ip":"51.83.34.144","features":{"disabled":{"proxycache":{}},"installed":{}},"flavor":2,"flavor_label":"K8S","gateway_ip":"192.168.2.245","last_state":5,"last_state_label":"Created","name":"mycluster","network_id":"6669a8db-db31-4272-9acd-da49dca07e14","nodes":{"masters":[{"id":"9874cbc6-bd17-4473-9552-1f7c9c7a2d6f","name":"mycluster-master-1","private_ip":"192.168.0.86","public_ip":""}],"nodes":[{"id":"019d2bcc-9d8c-4c76-a638-cf5612322dfa","name":"mycluster-node-1","private_ip":"192.168.1.74","public_ip":""}]},"primary_gateway_ip":"192.168.2.245","primary_public_ip":"51.83.34.144","remote_desktop":{"mycluster-master-1":["https://51.83.34.144/_platform/remotedesktop/mycluster-master-1/"]},"tenant":"TestOVH"},"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}` |
| `safescale [global_options] cluster node start [command_options] <cluster_name> <node_name_or_id>` | REVIEW_ME: Get info about a cluster<br><br>Example:<br><br>`$ safescale cluster inspect mycluster`<br>response on success:<br>`{"result":{"admin_login":"cladm","admin_password":"xxxxxxxxxxxxxx","cidr":"192.168.0.0/16","complexity":1,"complexity_label":"Small","default_route_ip":"192.168.2.245","defaults":{"gateway":{"max_cores":4,"max_ram_size":16,"min_cores":2,"min_disk_size":50,"min_gpu":-1,"min_ram_size":7},"image":"Ubuntu 18.04","master":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15},"node":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15}},"endpoint_ip":"51.83.34.144","features":{"disabled":{"proxycache":{}},"installed":{}},"flavor":2,"flavor_label":"K8S","gateway_ip":"192.168.2.245","last_state":5,"last_state_label":"Created","name":"mycluster","network_id":"6669a8db-db31-4272-9acd-da49dca07e14","nodes":{"masters":[{"id":"9874cbc6-bd17-4473-9552-1f7c9c7a2d6f","name":"mycluster-master-1","private_ip":"192.168.0.86","public_ip":""}],"nodes":[{"id":"019d2bcc-9d8c-4c76-a638-cf5612322dfa","name":"mycluster-node-1","private_ip":"192.168.1.74","public_ip":""}]},"primary_gateway_ip":"192.168.2.245","primary_public_ip":"51.83.34.144","remote_desktop":{"mycluster-master-1":["https://51.83.34.144/_platform/remotedesktop/mycluster-master-1/"]},"tenant":"TestOVH"},"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}` |
| `safescale [global_options] cluster node delete [command_options] <cluster_name> <node_name_or_id>` | REVIEW_ME: Get info about a cluster<br><br>Example:<br><br>`$ safescale cluster inspect mycluster`<br>response on success:<br>`{"result":{"admin_login":"cladm","admin_password":"xxxxxxxxxxxxxx","cidr":"192.168.0.0/16","complexity":1,"complexity_label":"Small","default_route_ip":"192.168.2.245","defaults":{"gateway":{"max_cores":4,"max_ram_size":16,"min_cores":2,"min_disk_size":50,"min_gpu":-1,"min_ram_size":7},"image":"Ubuntu 18.04","master":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15},"node":{"max_cores":8,"max_ram_size":32,"min_cores":4,"min_disk_size":80,"min_gpu":-1,"min_ram_size":15}},"endpoint_ip":"51.83.34.144","features":{"disabled":{"proxycache":{}},"installed":{}},"flavor":2,"flavor_label":"K8S","gateway_ip":"192.168.2.245","last_state":5,"last_state_label":"Created","name":"mycluster","network_id":"6669a8db-db31-4272-9acd-da49dca07e14","nodes":{"masters":[{"id":"9874cbc6-bd17-4473-9552-1f7c9c7a2d6f","name":"mycluster-master-1","private_ip":"192.168.0.86","public_ip":""}],"nodes":[{"id":"019d2bcc-9d8c-4c76-a638-cf5612322dfa","name":"mycluster-node-1","private_ip":"192.168.1.74","public_ip":""}]},"primary_gateway_ip":"192.168.2.245","primary_public_ip":"51.83.34.144","remote_desktop":{"mycluster-master-1":["https://51.83.34.144/_platform/remotedesktop/mycluster-master-1/"]},"tenant":"TestOVH"},"status":"success"}`<br>response on failure:<br>`{"error":{"exitcode":4,"message":"Cluster 'mycluster' not found.\n"},"result":null,"status":"failure"}` |

<br><br>

#### env

Some parameters of `safescale`can be set using environment variables:
- SAFESCALED_LISTEN: equivalent to `--server`, allows to tell `safescale` how to reach the daemon `safescaled`.
- SAFESCALE_METADATA_SUFFIX: allows to specify a suffix to add to the name of the Object Storage bucket used to store SafeScale metadata on the tenant.
  This allows to "isolate" metadata between different users of SafeScale (practical in development for example). There is no equivalent command line parameter.
  This environment variable must be on par between `safescale` and `safescaled`, otherwise strange things may happen...
