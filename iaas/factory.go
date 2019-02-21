/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package iaas

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/spf13/viper"

	"github.com/CS-SI/SafeScale/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/iaas/providers"
	"github.com/CS-SI/SafeScale/iaas/resources"
	"github.com/CS-SI/SafeScale/utils/crypt"
)

var (
	allProviders = map[string]*Service{}
	allTenants   = map[string]string{}
)

// Register a Client referenced by the provider name. Ex: "ovh", ovh.New()
// This function shoud be called by the init function of each provider to be registered in SafeScale
func Register(name string, provider providers.Provider) {
	// if already registered, leave
	if _, ok := allProviders[name]; ok {
		return
	}
	allProviders[name] = &Service{Provider: provider}
}

// GetTenants returns all known tenants
func GetTenants() (map[string]string, error) {
	err := loadConfig()
	return allTenants, err
}

// UseService return the service referenced by the given name.
// If necessary, this function try to load service from configuration file
func UseService(tenantName string) (*Service, error) {
	tenants, err := getTenantsFromCfg()
	if err != nil {
		return nil, err
	}
	var (
		tenantInCfg = false
		found       = false
		name        string
		svc         *Service
		svcProvider = "__not_found__"
	)

	for _, t := range tenants {
		tenant, _ := t.(map[string]interface{})
		name, found = tenant["name"].(string)
		if !found {
			log.Error("tenant found without 'name'")
			continue
		}
		if name != tenantName {
			continue
		}

		tenantInCfg = true
		provider, found := tenant["provider"].(string)
		if !found {
			provider, found = tenant["client"].(string)
			if !found {
				log.Error("Missing field 'provider' in tenant")
				continue
			}
		}

		svcProvider = provider
		svc, found = allProviders[provider]
		if !found {
			log.Errorf("Failed to find client '%s' for tenant '%s'", svcProvider, name)
			continue
		}

		tenantIdentity, found := tenant["identity"].(map[string]interface{})
		if !found {
			log.Debugf("No section 'identity' found in tenant '%s', continuing.", name)
		}
		tenantCompute, found := tenant["compute"].(map[string]interface{})
		if !found {
			log.Debugf("No section 'compute' found in tenant '%s', continuing.", name)
		}
		tenantNetwork, found := tenant["network"].(map[string]interface{})
		if !found {
			log.Debugf("No section 'network' found in tenant '%s', continuing.", name)
		}
		tenantClient := map[string]interface{}{
			"identity": tenantIdentity,
			"compute":  tenantCompute,
			"network":  tenantNetwork,
		}
		_, tenantObjectStorageFound := tenant["objectstorage"]
		_, tenantMetadataFound := tenant["metadata"]

		// Initializes Provider
		providerInstance, err := svc.Build(tenantClient)
		if err != nil {
			return nil, fmt.Errorf("Error creating tenant '%s' on provider '%s': %s", tenantName, provider, err.Error())
		}
		serviceCfg, err := providerInstance.GetCfgOpts()
		if err != nil {
			return nil, err
		}

		// Initializes Object Storage
		var objectStorageLocation objectstorage.Location
		if tenantObjectStorageFound {
			objectStorageConfig, err := initObjectStorageLocationConfig(tenant)
			if err != nil {
				return nil, err
			}
			objectStorageLocation, err = objectstorage.NewLocation(objectStorageConfig)
			if err != nil {
				return nil, fmt.Errorf("Error connecting to Object Storage Location: %s", err.Error())
			}
		} else {
			log.Warnf("missing section 'objectstorage' in configuration file for tenant '%s'", tenantName)
		}

		// Initializes Metadata Object Storage (may be different than the Object Storage)
		var (
			metadataBucket   objectstorage.Bucket
			metadataCryptKey *crypt.Key
		)
		if tenantMetadataFound || tenantObjectStorageFound {
			metadataLocationConfig, err := initMetadataLocationConfig(tenant)
			if err != nil {
				return nil, err
			}
			metadataLocation, err := objectstorage.NewLocation(metadataLocationConfig)
			if err != nil {
				return nil, fmt.Errorf("Error connecting to Object Storage Location to store metadata: %s", err.Error())
			}
			anon, found := serviceCfg.Get("MetadataBucketName")
			if !found {
				panic("missing configuration option 'MetadataBucketName'!")
			}
			bucketName := anon.(string)
			found, err = metadataLocation.FindBucket(bucketName)
			if err != nil {
				return nil, fmt.Errorf("Error accessing metadata location: %s", err.Error())
			}
			if found {
				metadataBucket, err = metadataLocation.GetBucket(bucketName)
				if err != nil {
					return nil, err
				}
			} else {
				metadataBucket, err = metadataLocation.CreateBucket(bucketName)
				if err != nil {
					return nil, err
				}
			}
			if metadataConfig, ok := tenant["metadata"].(map[string]interface{}); ok {
				metadataCryptKey = crypt.NewEncryptionKey([]byte(metadataConfig["CryptKey"].(string)))
			}
		} else {
			return nil, fmt.Errorf("failed to build service: 'metadata' section (and 'objectstorage' as fallback) is missing in configuration file for tenant '%s'", tenantName)
		}

		// Service is ready
		return &Service{
			Provider:       providerInstance,
			Location:       objectStorageLocation,
			MetadataBucket: metadataBucket,
			MetadataKey:    metadataCryptKey,
		}, nil
	}

	if !tenantInCfg {
		return nil, fmt.Errorf("Tenant '%s' not found in configuration", tenantName)
	}
	return nil, resources.ResourceNotFoundError("provider builder for", svcProvider)
}

// initObjectStorageLocationConfig initializes objectstorage.Config struct with map
func initObjectStorageLocationConfig(tenant map[string]interface{}) (objectstorage.Config, error) {
	var (
		config objectstorage.Config
		ok     bool
	)

	identity, _ := tenant["identity"].(map[string]interface{})
	compute, _ := tenant["compute"].(map[string]interface{})
	objectstorage, _ := tenant["objectstorage"].(map[string]interface{})

	if config.Type, ok = objectstorage["Type"].(string); !ok {
		return config, fmt.Errorf("missing setting 'Type' in 'metadata' section")
	}

	if config.Domain, ok = objectstorage["Domain"].(string); !ok {
		if config.Domain, ok = objectstorage["DomainName"].(string); !ok {
			if config.Domain, ok = compute["Domain"].(string); !ok {
				if config.Domain, ok = compute["DomainName"].(string); !ok {
					if config.Domain, ok = identity["Domain"].(string); !ok {
						config.Domain, _ = identity["DomainName"].(string)
					}
				}
			}
		}
	}
	config.TenantDomain = config.Domain

	if config.Tenant, ok = objectstorage["Tenant"].(string); !ok {
		if config.Tenant, ok = objectstorage["ProjectName"].(string); !ok {
			if config.Tenant, ok = objectstorage["ProjectID"].(string); !ok {
				if config.Tenant, ok = compute["ProjectName"].(string); !ok {
					config.Tenant, _ = compute["ProjectID"].(string)
				}
			}
		}
	}

	config.AuthURL, _ = objectstorage["AuthURL"].(string)
	config.Endpoint, _ = objectstorage["Endpoint"].(string)

	if config.User, ok = objectstorage["AccessKey"].(string); !ok {
		if config.User, ok = objectstorage["OpenStackID"].(string); !ok {
			if config.User, ok = objectstorage["Username"].(string); !ok {
				if config.User, ok = identity["OpenstackID"].(string); !ok {
					config.User, _ = identity["Username"].(string)
				}
			}
		}
	}

	if config.Key, ok = objectstorage["ApplicationKey"].(string); !ok {
		config.Key, _ = identity["ApplicationKey"].(string)
	}

	if config.SecretKey, ok = objectstorage["SecretKey"].(string); !ok {
		if config.SecretKey, ok = objectstorage["OpenstackPassword"].(string); !ok {
			if config.SecretKey, ok = objectstorage["Password"].(string); !ok {
				if config.SecretKey, ok = identity["SecretKey"].(string); !ok {
					if config.SecretKey, ok = identity["OpenstackPassword"].(string); !ok {
						config.SecretKey, _ = identity["Password"].(string)
					}
				}
			}
		}
	}

	if config.Region, ok = objectstorage["Region"].(string); !ok {
		config.Region, _ = compute["Region"].(string)
	}

	return config, nil
}

// initMetadataLocationConfig initializes objectstorage.Config struct with map
func initMetadataLocationConfig(tenant map[string]interface{}) (objectstorage.Config, error) {
	var (
		config objectstorage.Config
		ok     bool
	)

	identity, _ := tenant["identity"].(map[string]interface{})
	compute, _ := tenant["compute"].(map[string]interface{})
	objectstorage, _ := tenant["objectstorage"].(map[string]interface{})
	metadata, _ := tenant["metadata"].(map[string]interface{})

	if config.Type, ok = metadata["Type"].(string); !ok {
		if config.Type, ok = objectstorage["Type"].(string); !ok {
			return config, fmt.Errorf("missing setting 'Type' in 'metadata' section")
		}
	}

	if config.Domain, ok = metadata["Domain"].(string); !ok {
		if config.Domain, ok = metadata["DomainName"].(string); !ok {
			if config.Domain, ok = objectstorage["Domain"].(string); !ok {
				if config.Domain, ok = objectstorage["DomainName"].(string); !ok {
					if config.Domain, ok = compute["Domain"].(string); !ok {
						if config.Domain, ok = compute["DomainName"].(string); !ok {
							if config.Domain, ok = identity["Domain"].(string); !ok {
								config.Domain, _ = identity["DomainName"].(string)
							}
						}
					}
				}
			}
		}
	}
	config.TenantDomain = config.Domain

	if config.Tenant, ok = metadata["Tenant"].(string); !ok {
		if config.Tenant, ok = metadata["ProjectName"].(string); !ok {
			if config.Tenant, ok = metadata["ProjectID"].(string); !ok {
				if config.Tenant, ok = objectstorage["Tenant"].(string); !ok {
					if config.Tenant, ok = objectstorage["ProjectName"].(string); !ok {
						if config.Tenant, ok = objectstorage["ProjectID"].(string); !ok {
							if config.Tenant, ok = compute["Tenant"].(string); !ok {
								if config.Tenant, ok = compute["ProjectName"].(string); !ok {
									config.Tenant, _ = compute["ProjectID"].(string)
								}
							}
						}
					}
				}
			}
		}
	}

	if config.AuthURL, ok = metadata["AuthURL"].(string); !ok {
		config.AuthURL, _ = objectstorage["AuthURL"].(string)
	}

	if config.Endpoint, ok = metadata["Endpoint"].(string); !ok {
		config.Endpoint, _ = objectstorage["Endpoint"].(string)
	}

	if config.User, ok = metadata["AccessKey"].(string); !ok {
		if config.User, ok = metadata["OpenstackID"].(string); !ok {
			if config.User, ok = metadata["Username"].(string); !ok {
				if config.User, ok = objectstorage["AccessKey"].(string); !ok {
					if config.User, ok = objectstorage["OpenStackID"].(string); !ok {
						if config.User, ok = objectstorage["Username"].(string); !ok {
							if config.User, ok = identity["Username"].(string); !ok {
								config.User, _ = identity["OpenstackID"].(string)
							}
						}
					}
				}
			}
		}
	}

	if config.Key, ok = metadata["ApplicationKey"].(string); !ok {
		if config.Key, ok = objectstorage["ApplicationKey"].(string); !ok {
			config.Key, _ = identity["ApplicationKey"].(string)
		}
	}

	if config.SecretKey, ok = metadata["SecretKey"].(string); !ok {
		if config.SecretKey, ok = metadata["AccessPassword"].(string); !ok {
			if config.SecretKey, ok = metadata["OpenstackPassword"].(string); !ok {
				if config.SecretKey, ok = metadata["Password"].(string); !ok {
					if config.SecretKey, ok = objectstorage["SecretKey"].(string); !ok {
						if config.SecretKey, ok = objectstorage["AccessPassword"].(string); !ok {
							if config.SecretKey, ok = objectstorage["OpenstackPassword"].(string); !ok {
								if config.SecretKey, ok = objectstorage["Password"].(string); !ok {
									if config.SecretKey, ok = identity["SecretKey"].(string); !ok {
										if config.SecretKey, ok = identity["AccessPassword"].(string); !ok {
											if config.SecretKey, ok = identity["Password"].(string); !ok {
												config.SecretKey, _ = identity["OpenstackPassword"].(string)
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if config.Region, ok = metadata["Region"].(string); !ok {
		if config.Region, ok = objectstorage["Region"].(string); !ok {
			config.Region, _ = compute["Region"].(string)
		}
	}

	return config, nil
}

func loadConfig() error {
	tenantsCfg, err := getTenantsFromCfg()
	if err != nil {
		return err
	}
	for _, t := range tenantsCfg {
		tenant, _ := t.(map[string]interface{})
		if name, ok := tenant["name"].(string); ok {
			if provider, ok := tenant["client"].(string); ok {
				allTenants[name] = provider
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
