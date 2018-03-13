package providers

import (
	"fmt"

	"github.com/SafeScale/providers/api"
	"github.com/spf13/viper"
)

//ServiceFactory instantiate services described in tenants configuration file
type ServiceFactory struct {
	providers map[string]api.ClientAPI
	Services  map[string]*Service
}

//NewFactory creates a new service factory
func NewFactory() *ServiceFactory {
	return &ServiceFactory{
		providers: make(map[string]api.ClientAPI),
		Services:  make(map[string]*Service),
	}
}

//RegisterClient register a client
func (f *ServiceFactory) RegisterClient(name string, client api.ClientAPI) {
	f.providers[name] = client
}

//Load loads services described in tenant configuration file
func (f *ServiceFactory) Load() error {
	v := viper.New()
	v.AddConfigPath("/etc/safescale")
	v.AddConfigPath("$HOME/.safescale")
	v.AddConfigPath(".")
	v.SetConfigName("tenants")

	if err := v.ReadInConfig(); err != nil { // Handle errors reading the config file
		return fmt.Errorf("Error reading configuration file: %s", err.Error())
	}
	settings := v.AllSettings()
	tenants, _ := settings["tenants"].([]interface{})
	for _, t := range tenants {
		tenant, _ := t.(map[string]interface{})
		if client, ok := tenant["client"].(string); ok {
			name, _ := tenant["name"].(string)
			if p, ok := f.providers[client]; ok {
				c, err := p.Build(tenant)
				if err != nil {
					return fmt.Errorf("Error creating tenant %s with client %s: %s", name, client, err.Error())
				}
				f.Services[name] = &Service{
					ClientAPI: c,
				}
			}
		} else {
			return fmt.Errorf("Client %s not registered", client)
		}
	}
	return nil
}
