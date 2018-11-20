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
	"github.com/spf13/viper"

	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/objectstorage"
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
	var (
		tenantInCfg    = false
		found          = false
		name           string
		client         api.ClientAPI
		clientProvider = "__not_found__"
	)

	for _, t := range tenants {
		tenant, _ := t.(map[string]interface{})
		name, found = tenant["name"].(string)
		if !found {
			log.Errorf("tenant found without 'name'")
			continue
		}
		if name != tenantName {
			continue
		}

		tenantInCfg = true
		provider, found := tenant["client"].(string)
		if !found {
			log.Errorf("Missing field 'client' in tenant '%s'")
			continue
		}

		clientProvider = provider
		client, found = providers[provider]
		if !found {
			log.Errorf("Failed to find client '%s' for tenant '%s'", clientProvider, name)
			continue
		}

		tenantIdentity, found := tenant["identity"].(map[string]interface{})
		tenantCompute, found := tenant["compute"].(map[string]interface{})
		tenantNetwork, found := tenant["network"].(map[string]interface{})
		// Merge identity compute and network in single map
		tenantClient := map[string]interface{}{
			"identity": tenantIdentity,
			"compute":  tenantCompute,
			"network":  tenantNetwork,
		}
		tenantObjectStorage, found := tenant["objectstorage"].(map[string]interface{})
		tenantMetadata, found := tenant["metadata"].(map[string]interface{})
		if !found {
			tenantMetadata = tenantObjectStorage
		}

		clientAPI, err := client.Build(tenantClient)
		if err != nil {
			return nil, fmt.Errorf("Error creating tenant %s on provider %s: %s", tenantName, provider, err.Error())
		}
		clientCfg, err := clientAPI.GetCfgOpts()
		if err != nil {
			return nil, err
		}
		objectStorageConfig := fillObjectStorageConfig(tenantObjectStorage)
		objectStorageLocation := objectstorage.NewLocation(objectStorageConfig)
		err = objectStorageLocation.Connect()
		if err != nil {
			return nil, fmt.Errorf("Error connecting to Object Storage Location: %s", err.Error())
		}
		metadataLocationConfig := fillObjectStorageConfig(tenantMetadata)
		metadataLocation := objectstorage.NewLocation(metadataLocationConfig)
		err = metadataLocation.Connect()
		if err != nil {
			return nil, fmt.Errorf("Error connecting to Object Storage Location to store metadata: %s", err.Error())
		}
		anon, found := clientCfg.Get("MetadataBucketName")
		if !found {
			return nil, fmt.Errorf("missing configuration option 'MetadataBucketName'")
		}
		bucketName := anon.(string)
		var bucket objectstorage.Bucket
		found, err = metadataLocation.FindBucket(bucketName)
		if found {
			bucket, err = metadataLocation.GetBucket(bucketName)
		} else {
			bucket, err = metadataLocation.CreateBucket(bucketName)
		}
		return &Service{
			Client:         clientAPI,
			ObjectStorage:  objectStorageLocation,
			MetadataBucket: bucket,
		}, nil
	}

	if !tenantInCfg {
		return nil, fmt.Errorf("Tenant '%s' not found in configuration", tenantName)
	}
	return nil, model.ResourceNotFoundError("Client builder", clientProvider)
}

// fillObjectStorageConfig initializes objectstorage.Config struct with map
func fillObjectStorageConfig(tenant map[string]interface{}) objectstorage.Config {
	var config objectstorage.Config
	config.Domain = "default"
	config.Auth = tenant["Auth"].(string)
	config.Endpoint = tenant["Auth"].(string)
	config.User = tenant["Username"].(string)
	config.Tenant = tenant["ProjectID"].(string)
	config.Region = tenant["Region"].(string)
	if tenant["SecretKey"] != nil {
		config.Secretkey = tenant["SecretKey"].(string)
	}
	config.Key = tenant["Password"].(string)
	config.Types = tenant["Types"].(string)
	return config
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
