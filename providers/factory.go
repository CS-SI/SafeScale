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

	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/providers/api"
<<<<<<< develop
	"github.com/CS-SI/SafeScale/providers/model"
||||||| ancestor
=======
	"github.com/CS-SI/SafeScale/providers/object"
>>>>>>> Update object storage management
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
func Tenants() (map[string]string, error) {
	err := loadConfig()
	return tenants, err
}

// GetService return the service referenced by the given name.
// If necessary, this function try to load service from configuration file
func GetService(tenantName string) (*Service, error) {
	log.Infof("Getting service from tenant: %s", tenantName)
	tenants, err := getTenantsFromCfg()
	if err != nil {
		return nil, err
	}
	tenantInCfg := false
	clientProvider := "__not_found__"
	for _, t := range tenants {
		tenant, _ := t.(map[string]interface{})
		tenantconfig, _ := tenant["config"].(map[string]interface{})
		tenantobject, _ := tenant["object"].(map[string]interface{})
		// Merge tenantconfig and tenantobject
		for k, v := range tenantconfig {
			tenantobject[k] = v
		}
		tenantmerged := tenantobject
		if name, ok := tenantconfig["name"].(string); ok {
			if name == tenantName {
				tenantInCfg = true
				if provider, ok := tenantmerged["client"].(string); ok {
					clientProvider = provider
					if client, ok := providers[provider]; ok {
<<<<<<< develop
						clientAPI, err := client.Build(tenant)
||||||| ancestor
						service, err := client.Build(tenant)
=======
						location := new(object.Location)
						Config := setConfig(tenantobject)
						err = location.Connect(Config)
						service, err := client.Build(tenantmerged)
>>>>>>> Update object storage management
						if err != nil {
							return nil, fmt.Errorf("Error creating tenant %s on provider %s: %s", tenantName, provider, err.Error())
						}
						return &Service{
<<<<<<< develop
							ClientAPI: clientAPI,
||||||| ancestor
							ClientAPI: service,
=======
							ClientAPI: service,
							Location:  location,
>>>>>>> Update object storage management
						}, nil
					}
				}
			}
		}
	}

	if !tenantInCfg {
		return nil, fmt.Errorf("Tenant '%s' not found in configuration", tenantName)
	}
	return nil, model.ResourceNotFoundError("Client builder", clientProvider)
}

func setConfig(tenant map[string]interface{}) object.Config {

	var Config object.Config
	Config.Domain = "default"
	Config.Auth = tenant["OstAuth"].(string)
	Config.Endpoint = tenant["OstAuth"].(string)
	Config.User = tenant["OstUsername"].(string)
	Config.Tenant = tenant["OstProjectID"].(string)
	Config.Region = tenant["OstRegion"].(string)
	if tenant["OstSecretKey"] != nil {
		Config.Secretkey = tenant["OstSecretKey"].(string)
	}
	Config.Key = tenant["OstPassword"].(string)
	Config.Types = tenant["OstTypes"].(string)
	return Config
}

func loadConfig() error {
	tenantsCfg, err := getTenantsFromCfg()
	if err != nil {
		return err
	}
	for _, t := range tenantsCfg {
		tenant, _ := t.(map[string]interface{})
		tenantconfig, _ := tenant["config"].(map[string]interface{})
		if name, ok := tenantconfig["name"].(string); ok {
			if provider, ok := tenantconfig["client"].(string); ok {
				tenants[name] = provider
			} else {
				return fmt.Errorf("Invalid configuration file '%s'. Tenant '%s' has no client type", v.ConfigFileUsed(), name)
			}
		} else {
			return fmt.Errorf("Invalid configuration file. A tenant has no 'name' entry in '%s'", v.ConfigFileUsed())
		}
	}
	return nil
}

var v *viper.Viper

func getTenantsFromCfg() ([]interface{}, error) {
	v = viper.New()
	v.AddConfigPath(".")
	v.AddConfigPath("$HOME/.safescale")
	v.AddConfigPath("$HOME/.config/safescale")
	v.AddConfigPath("/etc/safescale")
	v.SetConfigName("tenants")

	if err := v.ReadInConfig(); err != nil { // Handle errors reading the config file
		msg := fmt.Sprintf("Error reading configuration file: %s", err.Error())
		log.Printf(msg)
		return nil, fmt.Errorf(msg)
	}
	settings := v.AllSettings()
	tenantsCfg, _ := settings["tenants"].([]interface{})
	return tenantsCfg, nil
}
