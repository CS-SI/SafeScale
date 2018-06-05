/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package providers

import (
	"fmt"
	"log"

	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/spf13/viper"
)

var (
	// providers[clientName]clientAPI
	providers = map[string]api.ClientAPI{}
	// tenants[tenantName]clientName
	tenants = map[string]string{}
)

//Register a ClientAPI referenced by the provider name. Ex: "ovh", &ovh.Client{}
// This function shoud be called by the init function of each provider to be registered in SafeScale
func Register(name string, client api.ClientAPI) {
	// if already registered, leave
	if _, ok := providers[name]; ok {
		return
	}
	providers[name] = client
}

// Tenants returns all known tenants
func Tenants() map[string]string {
	loadConfig()
	return tenants
}

// GetService return the service referenced by the given name.
// If necessary, this function try to load service from configuration file
func GetService(tenantName string) (*Service, error) {
	tenants := getTenantsFromCfg()
	tenantInCfg := false
	clientProvider := "__not_found__"
	for _, t := range tenants {
		tenant, _ := t.(map[string]interface{})
		if name, ok := tenant["name"].(string); ok {
			if name == tenantName {
				tenantInCfg = true
				if provider, ok := tenant["client"].(string); ok {
					clientProvider = provider
					if client, ok := providers[provider]; ok {
						service, err := client.Build(tenant)
						if err != nil {
							return nil, fmt.Errorf("Error creating tenant %s on provider %s: %s", tenantName, provider, err.Error())
						}
						return &Service{
							ClientAPI: service,
						}, nil
					}
				}
			}
		}
	}

	if !tenantInCfg {
		return nil, fmt.Errorf("Tenant '%s' not found in configuration", tenantName)
	}
	return nil, ResourceNotFoundError("Client builder", clientProvider)
}

func loadConfig() error {
	tenantsCfg := getTenantsFromCfg()
	for _, t := range tenantsCfg {
		tenant, _ := t.(map[string]interface{})
		if name, ok := tenant["name"].(string); ok {
			if provider, ok := tenant["client"].(string); ok {
				tenants[name] = provider
			} else {
				return fmt.Errorf("Invalid configuration file. Tenant '%s' has no client type", name)
			}
		} else {
			return fmt.Errorf("Invalid configuration file. A tenant has no 'name' entry")
		}
	}
	return nil
}

func getTenantsFromCfg() []interface{} {
	v := viper.New()
	v.AddConfigPath(".")
	v.AddConfigPath("$HOME/.safescale")
	v.AddConfigPath("$HOME/.config/safescale")
	v.AddConfigPath("/etc/safescale")
	v.SetConfigName("tenants")

	if err := v.ReadInConfig(); err != nil { // Handle errors reading the config file
		log.Printf("Error reading configuration file: %s", err.Error())
		return nil
	}
	settings := v.AllSettings()
	tenantsCfg, _ := settings["tenants"].([]interface{})
	return tenantsCfg
}
