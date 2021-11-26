# Safescale Scanner

Some providers do not provide all the information (CPU frequency, GPU availability, ...) through API about a Host template. So in order to allow the Host selection to be more precise, the SafeScale Scanner will investigate a given set of templates to register some useful information in a local database.

SafeScale Scanner used to be a separate binary. Starting with release v21.11, it's now a service included into `safescaled` that can be requested using `safescale` command (you can find usage [here](USAGE.md#tenant_scan) or directly through gRPC API.

## Basic usage

To launch the scan, just launch the command `safescale tenant scan <tenant_name>`.

To be scanned, a Tenant should have the field Scannable set to true

```
[[tenants]]
    name    = "ovh_tenant"
    client  = "ovh"
    [tenants.compute]
        Scannable = true
        WhitelistTemplateRegexp = "<regex>"  # Ex: "s1-*"
        BlacklistTemplateRegexp = "<regex>"
        ...
...

```

## Specific template(s) scan

To scan one or more specific templates from a given tenant, you can use the `--template <template_name>` (alias: `-t`) option.<br>


## Result

A database of all templates scanned (with the added details) will then be stored in $HOME/.safescale/ of the `safescaled` command, allowing SafeScale to create hosts more precisely. (not implemented yet)<br>

To filter templates to scan (forbid some templates and/or allow some others), you can set the `WhitelistTemplateRegexp`and/or `BlacklistTemplateRegexp` keywords of tenants file (`tenants.{toml|json|yaml}`), with regular expressions.
<br>
Please be aware that a scan is specific to a provider and to a region, as templates can vary with regions and providers.
