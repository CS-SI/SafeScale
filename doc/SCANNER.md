# Safescale Scanner

Some providers don't provide all the informations (cpu frequency, gpu, ...) about a host template. So in order to allow the host selection to be more precise, the scanner will investigate a given set of templates to register some useful informations.

## Basic usage

To launch the scan just launch the command ```safescale tenant scan <tenant_name>```.


To be scanned, a tenant should have the field Scannable set to true

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

To scan one or more specific templates from a given tenant, you can use the `--template <template_name>` (alias: `-t`) option. <br>


## Result

A database of all templates choosen with the added details will then be stored in $HOME/.safescale/ allowing SafeScale to create hosts more precisely. (not implemented yet)<br>

To prevent some templates, or to allow only scanning specific templates, set the __WhitelistTemplateRegexp__ or __BlacklistTemplateRegexp__ fields with regular expressions.
<br>
Please be aware that a scan is specific to a provider and to a region, as templates can vary with regions and providers.
