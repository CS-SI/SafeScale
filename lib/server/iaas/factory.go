/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/crypt"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

var (
	allProviders = map[string]Service{}
	allTenants   = map[string]string{}
)

// Register a Client referenced by the provider name. Ex: "ovh", ovh.New()
// This function shoud be called by the init function of each provider to be registered in SafeScale
func Register(name string, provider providers.Provider) {
	// if already registered, leave
	if _, ok := allProviders[name]; ok {
		return
	}
	allProviders[name] = &service{
		Provider: provider,
	}
}

// GetTenantNames returns all known tenants names
func GetTenantNames() (map[string]string, fail.Error) {
	err := loadConfig()
	return allTenants, err
}

// GetTenants returns all known tenants
func GetTenants() ([]interface{}, fail.Error) {
	tenants, _, err := getTenantsFromCfg()
	if err != nil {
		return nil, err
	}
	return tenants, err
}

// UseService return the service referenced by the given name.
// If necessary, this function try to load service from configuration file
func UseService(tenantName, metadataVersion string) (newService Service, xerr fail.Error) {
	defer fail.OnExitLogError(&xerr)
	defer fail.OnPanic(&xerr)

	tenants, _, err := getTenantsFromCfg()
	if err != nil {
		return NullService(), err
	}

	var (
		tenantInCfg    bool
		found          bool
		name, provider string
		svc            Service
		svcProvider    = "__not_found__"
	)

	for _, t := range tenants {
		tenant, _ := t.(map[string]interface{})
		name, found = tenant["name"].(string)
		if !found {
			logrus.Error("tenant found without 'name'")
			continue
		}
		if name != tenantName {
			continue
		}

		tenantInCfg = true
		provider, found = tenant["provider"].(string)
		if !found {
			provider, found = tenant["client"].(string)
			if !found {
				logrus.Error("Missing field 'provider' in tenant")
				continue
			}
		}

		svcProvider = provider
		svc, found = allProviders[provider]
		if !found {
			logrus.Errorf("failed to find client '%s' for tenant '%s'", svcProvider, name)
			continue
		}

		_, found = tenant["identity"].(map[string]interface{})
		if !found {
			logrus.Debugf("No section 'identity' found in tenant '%s', continuing.", name)
		}
		_, found = tenant["compute"].(map[string]interface{})
		if !found {
			logrus.Debugf("No section 'compute' found in tenant '%s', continuing.", name)
		}
		_, found = tenant["network"].(map[string]interface{})
		if !found {
			logrus.Debugf("No section 'network' found in tenant '%s', continuing.", name)
		}

		_, tenantObjectStorageFound := tenant["objectstorage"]
		_, tenantMetadataFound := tenant["metadata"]

		// Initializes Provider
		providerInstance, xerr := svc.Build(tenant)
		if xerr != nil {
			return NullService(), fail.Wrap(xerr, "error initializing tenant '%s' on provider '%s'", tenantName, provider)
		}
		serviceCfg, xerr := providerInstance.GetConfigurationOptions()
		if xerr != nil {
			return NullService(), xerr
		}

		// Initializes Object Storage
		var (
			objectStorageLocation objectstorage.Location
			authOpts              providers.Config
		)
		if tenantObjectStorageFound {
			authOpts, xerr = providerInstance.GetAuthenticationOptions()
			if xerr != nil {
				return NullService(), xerr
			}
			objectStorageConfig, xerr := initObjectStorageLocationConfig(authOpts, tenant)
			if xerr != nil {
				return NullService(), xerr
			}
			objectStorageLocation, xerr = objectstorage.NewLocation(objectStorageConfig)
			if xerr != nil {
				return NullService(), fail.Wrap(xerr, "error connecting to Object Storage location")
			}
		} else {
			logrus.Warnf("missing section 'objectstorage' in configuration file for tenant '%s'", tenantName)
		}

		// Initializes Metadata Object Storage (may be different than the Object Storage)
		var (
			metadataBucket   abstract.ObjectStorageBucket
			metadataCryptKey *crypt.Key
		)
		if tenantMetadataFound || tenantObjectStorageFound {
			// FIXME: This requires tuning too
			metadataLocationConfig, err := initMetadataLocationConfig(authOpts, tenant)
			if err != nil {
				return NullService(), err
			}

			metadataLocation, err := objectstorage.NewLocation(metadataLocationConfig)
			if err != nil {
				return NullService(), fail.Wrap(err, "error connecting to Object Storage location to store metadata")
			}

			anon, found := serviceCfg.Get("MetadataBucketName")
			if !found {
				return NullService(), fail.SyntaxError("missing configuration option 'MetadataBucketName'")
			}
			bucketName, ok := anon.(string)
			if !ok {
				return NullService(), fail.InvalidRequestError("invalid bucket name, it's not a string")
			}
			found, err = metadataLocation.FindBucket(bucketName)
			if err != nil {
				return NullService(), fail.Wrap(err, "error accessing metadata location: %s")
			}

			if found {
				metadataBucket, err = metadataLocation.InspectBucket(bucketName)
				if err != nil {
					return NullService(), err
				}
			} else {
				// create bucket
				metadataBucket, err = metadataLocation.CreateBucket(bucketName)
				if err != nil {
					return NullService(), err
				}

				// Creates metadata version file
				if metadataVersion != "" {
					content := bytes.NewBuffer([]byte(metadataVersion))
					_, xerr := metadataLocation.WriteObject(bucketName, "version", content, int64(content.Len()), nil)
					if xerr != nil {
						return NullService(), fail.Wrap(xerr, "failed to create version object in metadata Bucket")
					}
				}
			}
			if metadataConfig, ok := tenant["metadata"].(map[string]interface{}); ok {
				if key, ok := metadataConfig["CryptKey"].(string); ok {
					ek, err := crypt.NewEncryptionKey([]byte(key))
					if err != nil {
						return NullService(), fail.ConvertError(err)
					}
					metadataCryptKey = ek
				}
			}
			logrus.Infof("Setting default Tenant to '%s'; storing metadata in bucket '%s'", tenantName, metadataBucket.GetName())
		} else {
			return NullService(), fail.SyntaxError("failed to build service: 'metadata' section (and 'objectstorage' as fallback) is missing in configuration file for tenant '%s'", tenantName)
		}

		// service is ready
		newS := &service{
			Provider:       providerInstance,
			Location:       objectStorageLocation,
			metadataBucket: metadataBucket,
			metadataKey:    metadataCryptKey,
			cache:          serviceCache{map[string]*ResourceCache{}},
			cacheLock:      &sync.Mutex{},
			tenantName:     tenantName,
		}
		return newS, validateRegexps(newS /*tenantClient*/, tenant)
	}

	if !tenantInCfg {
		return NullService(), fail.NotFoundError("tenant '%s' not found in configuration", tenantName)
	}
	return NullService(), fail.NotFoundError("provider builder for '%s'", svcProvider)
}

// validateRegexps validates regexp values from tenants file
func validateRegexps(svc *service, tenant map[string]interface{}) fail.Error {
	compute, ok := tenant["compute"].(map[string]interface{})
	if !ok {
		return fail.InvalidParameterError("tenant['compute']", "is not a map")
	}

	res, xerr := validateRegexpsOfKeyword("WhilelistTemplateRegexp", compute["WhitelistTemplateRegexp"])
	if xerr != nil {
		return xerr
	}
	svc.whitelistTemplateREs = res

	res, xerr = validateRegexpsOfKeyword("BlacklistTemplateRegexp", compute["BlacklistTemplateRegexp"])
	if xerr != nil {
		return xerr
	}
	svc.blacklistTemplateREs = res

	res, xerr = validateRegexpsOfKeyword("WhilelistImageRegexp", compute["WhitelistImageRegexp"])
	if xerr != nil {
		return xerr
	}
	svc.whitelistImageREs = res

	res, xerr = validateRegexpsOfKeyword("BlacklistImageRegexp", compute["BlacklistImageRegexp"])
	if xerr != nil {
		return xerr
	}
	svc.blacklistImageREs = res

	return nil
}

// validateRegexpsOfKeyword reads the content of the keyword passed as parameter and returns an array of compiled regexps
func validateRegexpsOfKeyword(keyword string, content interface{}) (out []*regexp.Regexp, _ fail.Error) {
	var emptySlice []*regexp.Regexp

	if str, ok := content.(string); ok {
		re, err := regexp.Compile(str)
		if err != nil {
			return emptySlice, fail.SyntaxError("invalid value '%s' for keyword '%s': %s", str, keyword, err.Error())
		}
		out = append(out, re)
		return out, nil
	}

	if list, ok := content.([]interface{}); ok {
		for _, v := range list {
			re, err := regexp.Compile(v.(string))
			if err != nil {
				return emptySlice, fail.SyntaxError("invalid value '%s' for keyword '%s': %s", v, keyword, err.Error())
			}
			out = append(out, re)
		}
		return out, nil
	}

	return out, nil
}

// initObjectStorageLocationConfig initializes objectstorage.Config struct with map
func initObjectStorageLocationConfig(authOpts providers.Config, tenant map[string]interface{}) (objectstorage.Config, fail.Error) {
	var (
		config objectstorage.Config
		ok     bool
	)

	identity, _ := tenant["identity"].(map[string]interface{})
	compute, _ := tenant["compute"].(map[string]interface{})
	ostorage, _ := tenant["objectstorage"].(map[string]interface{})

	if config.Type, ok = ostorage["Type"].(string); !ok {
		return config, fail.SyntaxError("missing setting 'Type' in 'objectstorage' section")
	}

	if config.Domain, ok = ostorage["Domain"].(string); !ok {
		if config.Domain, ok = ostorage["DomainName"].(string); !ok {
			if config.Domain, ok = compute["Domain"].(string); !ok {
				if config.Domain, ok = compute["DomainName"].(string); !ok {
					if config.Domain, ok = identity["Domain"].(string); !ok {
						if config.Domain, ok = identity["DomainName"].(string); !ok {
							config.Domain = authOpts.GetString("DomainName")
						}
					}
				}
			}
		}
	}
	config.TenantDomain = config.Domain

	if config.Tenant, ok = ostorage["Tenant"].(string); !ok {
		if config.Tenant, ok = ostorage["ProjectName"].(string); !ok {
			if config.Tenant, ok = ostorage["ProjectID"].(string); !ok {
				if config.Tenant, ok = compute["ProjectName"].(string); !ok {
					if config.Tenant, ok = compute["ProjectID"].(string); !ok {
						config.Tenant = authOpts.GetString("ProjectName")
					}
				}
			}
		}
	}

	config.AuthURL, _ = ostorage["AuthURL"].(string)
	config.Endpoint, _ = ostorage["Endpoint"].(string)

	if config.User, ok = ostorage["AccessKey"].(string); !ok {
		if config.User, ok = ostorage["OpenStackID"].(string); !ok {
			if config.User, ok = ostorage["Username"].(string); !ok {
				if config.User, ok = identity["OpenstackID"].(string); !ok {
					config.User, _ = identity["Username"].(string)
				}
			}
		}
	}

	if config.Key, ok = ostorage["ApplicationKey"].(string); !ok {
		config.Key, _ = identity["ApplicationKey"].(string)
	}

	if config.SecretKey, ok = ostorage["SecretKey"].(string); !ok {
		if config.SecretKey, ok = ostorage["OpenstackPassword"].(string); !ok {
			if config.SecretKey, ok = ostorage["Password"].(string); !ok {
				if config.SecretKey, ok = identity["SecretKey"].(string); !ok {
					if config.SecretKey, ok = identity["OpenstackPassword"].(string); !ok {
						config.SecretKey, _ = identity["Password"].(string)
					}
				}
			}
		}
	}

	if config.Region, ok = ostorage["Region"].(string); !ok {
		config.Region, _ = compute["Region"].(string)
		if err := validateOVHObjectStorageRegionNaming("objectstorage", config.Region, config.AuthURL); err != nil {
			return config, err
		}
	}

	if config.AvailabilityZone, ok = ostorage["AvailabilityZone"].(string); !ok {
		config.AvailabilityZone, _ = compute["AvailabilityZone"].(string)
	}

	// FIXME: Remove google custom code
	if config.Type == "google" {
		keys := []string{"project_id", "private_key_id", "private_key", "client_email", "client_id", "auth_uri", "token_uri", "auth_provider_x509_cert_url", "client_x509_cert_url"}
		for _, key := range keys {
			if _, ok = identity[key].(string); !ok {
				return config, fail.SyntaxError("problem parsing %s", key)
			}
		}

		config.ProjectID = identity["project_id"].(string)

		googleCfg := stacks.GCPConfiguration{
			Type:         "service_account",
			ProjectID:    identity["project_id"].(string),
			PrivateKeyID: identity["private_key_id"].(string),
			PrivateKey:   identity["private_key"].(string),
			ClientEmail:  identity["client_email"].(string),
			ClientID:     identity["client_id"].(string),
			AuthURI:      identity["auth_uri"].(string),
			TokenURI:     identity["token_uri"].(string),
			AuthProvider: identity["auth_provider_x509_cert_url"].(string),
			ClientCert:   identity["client_x509_cert_url"].(string),
		}

		d1, jserr := json.MarshalIndent(googleCfg, "", "  ")
		if jserr != nil {
			return config, fail.ConvertError(jserr)
		}

		config.Credentials = string(d1)
	}
	return config, nil
}

func validateOVHObjectStorageRegionNaming(context, region, authURL string) fail.Error {
	// If AuthURL contains OVH, special treatment due to change in object storage 'region'-ing since 2020/02/17
	// Object Storage regions don't contain anymore an index like compute regions
	if strings.Contains(authURL, "ovh.") {
		rLen := len(region)
		if _, err := strconv.Atoi(region[rLen-1:]); err == nil {
			region = region[:rLen-1]
			return fail.InvalidRequestError(fmt.Sprintf(`region names for OVH Object Storage have changed since 2020/02/17. Please set or update the %s tenant definition with 'Region = "%s"'.`, context, region))
		}
	}
	return nil
}

// initMetadataLocationConfig initializes objectstorage.Config struct with map
func initMetadataLocationConfig(authOpts providers.Config, tenant map[string]interface{}) (objectstorage.Config, fail.Error) {
	var (
		config objectstorage.Config
		ok     bool
	)

	identity, _ := tenant["identity"].(map[string]interface{})
	compute, _ := tenant["compute"].(map[string]interface{})
	ostorage, _ := tenant["objectstorage"].(map[string]interface{})
	metadata, _ := tenant["metadata"].(map[string]interface{})

	if config.Type, ok = metadata["Type"].(string); !ok {
		if config.Type, ok = ostorage["Type"].(string); !ok {
			return config, fail.SyntaxError("missing setting 'Type' in 'metadata' section")
		}
	}

	if config.Domain, ok = metadata["Domain"].(string); !ok {
		if config.Domain, ok = metadata["DomainName"].(string); !ok {
			if config.Domain, ok = ostorage["Domain"].(string); !ok {
				if config.Domain, ok = ostorage["DomainName"].(string); !ok {
					if config.Domain, ok = compute["Domain"].(string); !ok {
						if config.Domain, ok = compute["DomainName"].(string); !ok {
							if config.Domain, ok = identity["Domain"].(string); !ok {
								if config.Domain, ok = identity["DomainName"].(string); !ok {
									config.Domain = authOpts.GetString("DomainName")
								}
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
				if config.Tenant, ok = ostorage["Tenant"].(string); !ok {
					if config.Tenant, ok = ostorage["ProjectName"].(string); !ok {
						if config.Tenant, ok = ostorage["ProjectID"].(string); !ok {
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
		config.AuthURL, _ = ostorage["AuthURL"].(string)
	}

	if config.Endpoint, ok = metadata["Endpoint"].(string); !ok {
		config.Endpoint, _ = ostorage["Endpoint"].(string)
	}

	if config.User, ok = metadata["AccessKey"].(string); !ok {
		if config.User, ok = metadata["OpenstackID"].(string); !ok {
			if config.User, ok = metadata["Username"].(string); !ok {
				if config.User, ok = ostorage["AccessKey"].(string); !ok {
					if config.User, ok = ostorage["OpenStackID"].(string); !ok {
						if config.User, ok = ostorage["Username"].(string); !ok {
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
		if config.Key, ok = ostorage["ApplicationKey"].(string); !ok {
			config.Key, _ = identity["ApplicationKey"].(string)
		}
	}

	if config.SecretKey, ok = metadata["SecretKey"].(string); !ok {
		if config.SecretKey, ok = metadata["AccessPassword"].(string); !ok {
			if config.SecretKey, ok = metadata["OpenstackPassword"].(string); !ok {
				if config.SecretKey, ok = metadata["Password"].(string); !ok {
					if config.SecretKey, ok = ostorage["SecretKey"].(string); !ok {
						if config.SecretKey, ok = ostorage["AccessPassword"].(string); !ok {
							if config.SecretKey, ok = ostorage["OpenstackPassword"].(string); !ok {
								if config.SecretKey, ok = ostorage["Password"].(string); !ok {
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
		if config.Region, ok = ostorage["Region"].(string); !ok {
			config.Region, _ = compute["Region"].(string)
		}
		if err := validateOVHObjectStorageRegionNaming("objectstorage", config.Region, config.AuthURL); err != nil {
			return config, err
		}
	}

	if config.AvailabilityZone, ok = metadata["AvailabilityZone"].(string); !ok {
		if config.AvailabilityZone, ok = ostorage["AvailabilityZone"].(string); !ok {
			config.AvailabilityZone, _ = compute["AvailabilityZone"].(string)
		}
	}

	// FIXME: Remove google custom code
	if config.Type == "google" {
		keys := []string{"project_id", "private_key_id", "private_key", "client_email", "client_id", "auth_uri", "token_uri", "auth_provider_x509_cert_url", "client_x509_cert_url"}
		for _, key := range keys {
			if _, ok = identity[key].(string); !ok {
				return config, fail.SyntaxError("problem parsing %s", key)
			}
		}

		config.ProjectID = identity["project_id"].(string)

		googleCfg := stacks.GCPConfiguration{
			Type:         "service_account",
			ProjectID:    identity["project_id"].(string),
			PrivateKeyID: identity["private_key_id"].(string),
			PrivateKey:   identity["private_key"].(string),
			ClientEmail:  identity["client_email"].(string),
			ClientID:     identity["client_id"].(string),
			AuthURI:      identity["auth_uri"].(string),
			TokenURI:     identity["token_uri"].(string),
			AuthProvider: identity["auth_provider_x509_cert_url"].(string),
			ClientCert:   identity["client_x509_cert_url"].(string),
		}

		d1, jserr := json.MarshalIndent(googleCfg, "", "  ")
		if jserr != nil {
			return config, fail.ConvertError(jserr)
		}

		config.Credentials = string(d1)
	}

	return config, nil
}

func loadConfig() fail.Error {
	tenantsCfg, v, err := getTenantsFromCfg()
	if err != nil {
		return err
	}
	for _, t := range tenantsCfg {
		tenant, _ := t.(map[string]interface{})
		if name, ok := tenant["name"].(string); ok {
			if provider, ok := tenant["client"].(string); ok {
				allTenants[name] = provider
			} else {
				return fail.SyntaxError("invalid configuration file '%s'. Tenant '%s' has no client type", v.ConfigFileUsed(), name)
			}
		} else {
			return fail.SyntaxError("invalid configuration file. A tenant has no 'name' entry in '%s'", v.ConfigFileUsed())
		}
	}
	return nil
}

func getTenantsFromCfg() ([]interface{}, *viper.Viper, fail.Error) {
	v := viper.New()
	v.AddConfigPath(".")
	v.AddConfigPath("$HOME/.safescale")
	v.AddConfigPath("$HOME/.config/safescale")
	v.AddConfigPath("/etc/safescale")
	v.SetConfigName("tenants")

	if err := v.ReadInConfig(); err != nil { // Handle errors reading the config file
		msg := fmt.Sprintf("error reading configuration file: %s", err.Error())
		logrus.Errorf(msg)
		return nil, v, fail.SyntaxError(msg)
	}
	settings := v.AllSettings()
	tenantsCfg, _ := settings["tenants"].([]interface{})
	return tenantsCfg, v, nil
}
