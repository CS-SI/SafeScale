# Safescale Scanner

Some providers don't provide all the informations (cpu frequency, gpu, ...) about a host template. So in order to allow the host selection to be more precise, the scanner will investigate all templates to register some useful informations.

## Scanner usage

To launch the scan just launch the command ```scanner```.


To be scanned, a tenant should have the field Scannable set to true

```
[[tenants]]
    name    = "ovh_tenant"
    client  = "ovh"
    [tenants.compute]
        Scannable = true
        ...
...

```

A database of all templates availables will then be stored in $HOME/.safescale/ allowing SafeScale to create hosts more precisely.<br>
Please be aware that a scan is specific to a provider and to a region, as templates can vary with regions and providers.
