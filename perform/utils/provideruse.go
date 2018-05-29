package utils

import (
	"github.com/SafeScale/providers"

	_ "github.com/SafeScale/providers/cloudwatt"      // Imported to initialise tenants
	_ "github.com/SafeScale/providers/flexibleengine" // Imported to initialise tenants
	_ "github.com/SafeScale/providers/ovh"            // Imported to initialise tenants
)

//GetProviderService returns the service provider corresponding to the current Tenant
func GetProviderService() (*providers.Service, error) {
	tenant, err := GetCurrentTenant()
	if err != nil {
		return nil, err
	}
	svc, err := providers.GetService(tenant)
	if err != nil {
		return nil, err
	}
	return svc, nil
}
