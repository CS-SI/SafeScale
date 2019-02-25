# Safescale Scanner

Some providers didn't provide all the informations (cpu frequency, gpu, ...) about a host template. So in order to allow the host selection to be more precise, the scanner will investigate all templates to register some useful informations.

## Scanner usage

To launch the scan just launch the command scanner.
```
scanner
```

To be scanned, a tenant name should be followed by scannable

```
[[tenants]]
    name    = "ovh_tenant-scannable"
    client  = "ovh"
.
.
.
```

A database of all templates availables will then be strored in $HOME/.Safescale/ allowing SafeScale to create hosts more precisely.<br>
Please be aware than a scan is specific to a provider and to a region, as templates can be differents betwen regions and providers.