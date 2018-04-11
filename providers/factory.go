package providers

import (
	"fmt"
	"sync"

	"github.com/SafeScale/providers/api"
	"github.com/spf13/viper"
)

var (
	lock      sync.RWMutex
	loaded    = false
	providers = map[string]api.ClientAPI{}
	services  = map[string]*Service{}
)

//Register a ClientAPI referenced by the provider name. Ex: "ovh", &ovh.Client{}
// This function shoud be called by the init function of each provider to be registered in SafeScale
func Register(name string, client api.ClientAPI) {
	lock.Lock()
	defer lock.Unlock()
	// if already registered, leave
	if _, ok := providers[name]; ok {
		return
	}
	providers[name] = client
	loaded = false
}

// Services returns all available services
func Services() map[string]*Service {
	lock.Lock()
	defer lock.Unlock()
	load()
	return services
}

// GetService return the service referenced by the given name.
// If necessary, this function try to load serviec from configuration file
func GetService(name string) (*Service, error) {
	lock.Lock()
	defer lock.Unlock()
	service, ok := services[name]
	if !ok {
		// Try to load service
		load()
	}

	service, ok = services[name]
	if !ok {
		return nil, ResourceNotFoundError("Service", name)
	}
	return service, nil
}

func load() error {
	if loaded {
		return nil
	}

	v := viper.New()
	v.AddConfigPath("/etc/safescale")
	v.AddConfigPath("$HOME/.config/safescale")
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
			if p, ok := providers[client]; ok {
				c, err := p.Build(tenant)
				if err != nil {
					return fmt.Errorf("Error creating tenant %s with client %s: %s", name, client, err.Error())
				}
				services[name] = &Service{
					ClientAPI: c,
				}
			}
		} else {
			return fmt.Errorf("Client %s not registered", client)
		}
	}
	loaded = true
	return nil
}
