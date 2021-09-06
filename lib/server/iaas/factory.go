/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers/api"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/utils/crypt"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

var (
	allProviders = map[string]Service{}
	allTenants   = map[string]string{}
)

// Register a Client referenced by the provider name. Ex: "ovh", ovh.New()
// This function shoud be called by the init function of each provider to be registered in SafeScale
func Register(name string, provider api.Provider) {
	// if already registered, leave
	if _, ok := allProviders[name]; ok {
		return
	}
	allProviders[name] = &service{
		Provider: provider,
	}
}

// GetTenantNames returns all known tenants names
func GetTenantNames() (map[string]string, error) {
	err := loadConfig()
	return allTenants, err
}

// GetTenants returns all known tenants
func GetTenants() ([]interface{}, error) {
	tenants, err := getTenantsFromCfg()
	if err != nil {
		return nil, err
	}
	return tenants, err
}

// UseService return the service referenced by the given name.
// If necessary, this function try to load service from configuration file
func UseService(tenantName string) (newService Service, err error) {
	defer fail.OnPanic(&err)()

	tenants, err := getTenantsFromCfg()
	if err != nil {
		return nil, err
	}

	var (
		tenantInCfg bool
		found       bool
		name        string
		svc         Service
		svcProvider = "__not_found__"
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
		provider, found := tenant["provider"].(string)
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

		// tenantIdentity, found := tenant["identity"].(map[string]interface{})
		// if !found {
		// 	logrus.Debugf("No section 'identity' found in tenant '%s', continuing.", name)
		// }
		// tenantCompute, found := tenant["compute"].(map[string]interface{})
		// if !found {
		// 	logrus.Debugf("No section 'compute' found in tenant '%s', continuing.", name)
		// }
		// tenantNetwork, found := tenant["network"].(map[string]interface{})
		// if !found {
		// 	logrus.Debugf("No section 'network' found in tenant '%s', continuing.", name)
		// }
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
		// tenantClient := map[string]interface{}{
		// 	"identity": tenantIdentity,
		// 	"compute":  tenantCompute,
		// 	"network":  tenantNetwork,
		// }
		_, tenantObjectStorageFound := tenant["objectstorage"]
		_, tenantMetadataFound := tenant["metadata"]

		// Initializes Provider
		providerInstance, err := svc.Build( /*tenantClient*/ tenant)
		if err != nil {
			return nil, fail.Errorf(
				fmt.Sprintf(
					"error creating tenant '%s' on provider '%s': %s", tenantName, provider, err.Error(),
				), nil,
			)
		}
		serviceCfg, err := providerInstance.GetConfigurationOptions()
		if err != nil {
			return nil, err
		}

		// Initializes Object Storage
		var (
			objectStorageLocation objectstorage.Location
			authOpts              providers.Config
		)
		if tenantObjectStorageFound {
			authOpts, err = providerInstance.GetAuthenticationOptions()
			if err != nil {
				return nil, err
			}
			objectStorageConfig, err := initObjectStorageLocationConfig(authOpts, tenant)
			if err != nil {
				return nil, err
			}
			objectStorageLocation, err = objectstorage.NewLocation(objectStorageConfig)
			if err != nil {
				return nil, fail.Errorf(
					fmt.Sprintf("error connecting to Object Storage Location: %s", err.Error()), nil,
				)
			}
		} else {
			logrus.Warnf("missing section 'objectstorage' in configuration file for tenant '%s'", tenantName)
		}

		// Initializes Metadata Object Storage (may be different from the Object Storage)
		var (
			metadataBucket   objectstorage.Bucket
			metadataCryptKey *crypt.Key
		)
		if tenantMetadataFound || tenantObjectStorageFound {
			// FIXME: This requires tuning too
			metadataLocationConfig, err := initMetadataLocationConfig(authOpts, tenant)
			if err != nil {
				return nil, err
			}
			metadataLocation, err := objectstorage.NewLocation(metadataLocationConfig)
			if err != nil {
				return nil, fail.Errorf(
					fmt.Sprintf(
						"error connecting to Object Storage Location to store metadata: %s", err.Error(),
					), nil,
				)
			}
			anon, found := serviceCfg.Get("MetadataBucketName")
			if !found {
				return nil, fail.Errorf(fmt.Sprintf("missing configuration option 'MetadataBucketName'"), nil)
			}
			bucketName, ok := anon.(string)
			if !ok {
				return nil, fail.Errorf(fmt.Sprintf("invalid bucket name, it's not a string"), nil)
			}
			found, err = metadataLocation.FindBucket(bucketName)
			if err != nil {
				return nil, fail.Errorf(fmt.Sprintf("error accessing metadata location: %s", err.Error()), nil)
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
				if key, ok := metadataConfig["CryptKey"]; ok {
					ek, err := crypt.NewEncryptionKey([]byte(key.(string)))
					if err != nil {
						return nil, err
					}
					metadataCryptKey = ek
				}
			}
		} else {
			return nil, fail.Errorf(
				fmt.Sprintf(
					"failed to build service: 'metadata' section (and 'objectstorage' as fallback) is missing in configuration file for tenant '%s'",
					tenantName,
				), nil,
			)
		}

		// Service is ready
		newS := &service{
			Provider:       providerInstance,
			Location:       objectStorageLocation,
			metadataBucket: metadataBucket,
			metadataKey:    metadataCryptKey,
		}

		// validate metadata version
		err = checkMetadataVersion(newS)
		if err != nil {
			return nil, err
		}

		return newS, validateRegexps(newS /*tenantClient*/, tenant)
	}

	if !tenantInCfg {
		return nil, fail.Errorf(fmt.Sprintf("tenant '%s' not found in configuration", tenantName), nil)
	}
	return nil, abstract.ResourceNotFoundError("provider builder for", svcProvider)
}

// validateRegionName validates the availability of the region passed as parameter
func validateRegionName(provider Service, name string) fail.Error {
	validRegions, xerr := provider.ListRegions()
	if xerr != nil && len(validRegions) > 0 {
		return xerr
	}

	if len(validRegions) > 0 {
		regionIsValidInput := false
		for _, vr := range validRegions {
			if name == vr {
				regionIsValidInput = true
			}
		}
		if !regionIsValidInput {
			return fail.NotFoundError("invalid Region in objectstorage section: '%s': not found", name)
		}
	}

	return nil
}

//checkMetadataVersion checks metadata version, if it's not our version, we stop
func checkMetadataVersion(s *service) error {
	var buffer bytes.Buffer
	_, err := s.GetMetadataBucket().ReadObject("version", &buffer, 0, 0)
	if err != nil {
		return nil
        }
	data := string(buffer.Bytes())

	ourVersion := fmt.Sprintf("v%s", Version)
	if strings.HasPrefix(data, ourVersion) {
		return nil
	}

	if strings.Contains(ourVersion, ".") {
		if strings.HasPrefix(data, ourVersion[0:strings.LastIndex(ourVersion, ".")]) {
			return nil
		}
	}

	return fmt.Errorf("cannot continue: the minimum version of Safescale binaries needed to work correctly with this bucket is '%s'. (current binary '%s')", data, ourVersion)
}

// validateRegexps validates regexp values from tenants file
func validateRegexps(svc *service, tenant map[string]interface{}) fail.Error {
	compute, ok := tenant["compute"].(map[string]interface{})
	if !ok {
		return fail.InvalidParameterError("tenant['compute']", "is not a map")
	}
	data := string(buffer.Bytes())

	ourVersion := fmt.Sprintf("v%s", Version)
	if strings.HasPrefix(data, ourVersion) {
		return nil
	}

	if strings.Contains(ourVersion, ".") {
		if strings.HasPrefix(data, ourVersion[0:strings.LastIndex(ourVersion, ".")]) {
			return nil
		}
	}

	return fmt.Errorf("cannot continue: the minimum version of Safescale binaries needed to work correctly with this bucket is '%s'. (current binary '%s')", data, ourVersion)
}

// validateRegexps validates regexp values from tenants file
func validateRegexps(svc *service, tenant map[string]interface{}) error {
	compute, ok := tenant["compute"].(map[string]interface{})
	if !ok {
		return fail.InvalidParameterError("tenant['compute']", "is not a map")
	}

	if reStr, ok := compute["WhitelistTemplateRegexp"].(string); ok {
		// Validate regular expression
		re, err := regexp.Compile(reStr)
		if err != nil {
			return fail.Errorf(
				fmt.Sprintf(
					"invalid value '%s' for field 'WhitelistTemplateRegexp': %s", reStr, err.Error(),
				), nil,
			)
		}
		svc.whitelistTemplateRE = re
	}
	if reStr, ok := compute["BlacklistTemplateRegexp"].(string); ok {
		// Validate regular expression
		re, err := regexp.Compile(reStr)
		if err != nil {
			return fail.Errorf(
				fmt.Sprintf(
					"invalid value '%s' for field 'BlacklistTemplateRegexp': %s", reStr, err.Error(),
				), nil,
			)
		}
		svc.blacklistTemplateRE = re
	}
	if reStr, ok := compute["WhitelistImageRegexp"].(string); ok {
		// Validate regular expression
		re, err := regexp.Compile(reStr)
		if err != nil {
			return fail.Errorf(
				fmt.Sprintf(
					"invalid value '%s' for field 'WhitelistImageRegexp': %s", reStr, err.Error(),
				), nil,
			)
		}
		svc.whitelistImageRE = re
	}
	if reStr, ok := compute["BlacklistImageRegexp"].(string); ok {
		// Validate regular expression
		re, err := regexp.Compile(reStr)
		if err != nil {
			return fail.Errorf(
				fmt.Sprintf(
					"invalid value '%s' for field 'BlacklistImageRegexp': %s", reStr, err.Error(),
				), nil,
			)
		}
		svc.blacklistImageRE = re
	}
	return nil
}

// initObjectStorageLocationConfig initializes objectstorage.Config struct with map
func initObjectStorageLocationConfig(authOpts providers.Config, tenant map[string]interface{}) (objectstorage.Config, error) {
	var (
		config objectstorage.Config
		ok     bool
	)

	identity, _ := tenant["identity"].(map[string]interface{})
	compute, _ := tenant["compute"].(map[string]interface{})
	ostorage, _ := tenant["objectstorage"].(map[string]interface{})

	if config.Type, ok = ostorage["Type"].(string); !ok {
		return config, fail.Errorf(fmt.Sprintf("missing setting 'Type' in 'objectstorage' section"), nil)
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
		keys := []string{
			"project_id", "private_key_id", "private_key", "client_email", "client_id", "auth_uri", "token_uri",
			"auth_provider_x509_cert_url", "client_x509_cert_url",
		}
		for _, key := range keys {
			if _, ok = identity[key].(string); !ok {
				return config, fail.Errorf(fmt.Sprintf("problem parsing %s", key), nil)
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

		d1, err := json.MarshalIndent(googleCfg, "", "  ")
		if err != nil {
			return config, err
		}

		config.Credentials = string(d1)
	}
	return config, nil
}

func validateOVHObjectStorageRegionNaming(context, region, authURL string) error {
	// If AuthURL contains OVH, special treatment due to change in object storage 'region'-ing since 2020/02/17
	// Object Storage regions don't contain anymore an index like compute regions
	if strings.Contains(authURL, "ovh.") {
		rLen := len(region)
		if _, err := strconv.Atoi(region[rLen-1:]); err == nil {
			region = region[:rLen-1]
			return fail.InvalidRequestError(
				fmt.Sprintf(
					`region names for OVH Object Storage have changed since 2020/02/17. Please set or update the %s tenant definition with 'Region = "%s"'.`,
					context, region,
				),
			)
		}
	}
	return nil
}

// initMetadataLocationConfig initializes objectstorage.Config struct with map
func initMetadataLocationConfig(authOpts providers.Config, tenant map[string]interface{}) (_ objectstorage.Config, err error) {
	defer fail.OnPanic(&err)()

	var (
		config objectstorage.Config
		ok     bool
	)

	identity, ok := tenant["identity"].(map[string]interface{})
	if !ok {
		return config, fail.Errorf(fmt.Sprintf("problem parsing tenants.toml"), nil)
	}
	compute, ok := tenant["compute"].(map[string]interface{})
	if !ok {
		return config, fail.Errorf(fmt.Sprintf("problem parsing tenants.toml"), nil)
	}
	ostorage, ok := tenant["objectstorage"].(map[string]interface{})
	if !ok {
		return config, fail.Errorf(fmt.Sprintf("problem parsing tenants.toml"), nil)
	}
	metadata, _ := tenant["metadata"].(map[string]interface{})

	if config.Type, ok = metadata["Type"].(string); !ok {
		if config.Type, ok = ostorage["Type"].(string); !ok {
			return config, fail.Errorf(fmt.Sprintf("missing setting 'Type' in 'metadata' section"), nil)
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
		keys := []string{
			"project_id", "private_key_id", "private_key", "client_email", "client_id", "auth_uri", "token_uri",
			"auth_provider_x509_cert_url", "client_x509_cert_url",
		}
		for _, key := range keys {
			if _, ok = identity[key].(string); !ok {
				return config, fail.Errorf(fmt.Sprintf("problem parsing %s", key), nil)
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

		d1, err := json.MarshalIndent(googleCfg, "", "  ")
		if err != nil {
			return config, err
		}

		config.Credentials = string(d1)
	}

	return config, nil
}

func loadConfig() error {
	tenantsCfg, err := getTenantsFromCfg()
	if err != nil {
		return err
	}
	for _, t := range tenantsCfg {
		tenant, ok := t.(map[string]interface{})
		if !ok {
			return fail.Errorf(fmt.Sprintf("invalid configuration file '%s'.", v.ConfigFileUsed()), nil)
		}

		if name, ok := tenant["name"].(string); ok {
			if provider, ok := tenant["client"].(string); ok {
				allTenants[name] = provider
			} else if provider, ok := tenant["provider"].(string); ok {
				allTenants[name] = provider

			} else {
				return fail.Errorf(
					fmt.Sprintf(
						"invalid configuration file '%s'. Tenant '%s' has no client type", v.ConfigFileUsed(), name,
					), nil,
				)
			}
		} else {
			return fail.Errorf(
				fmt.Sprintf(
					"invalid configuration file. A tenant has no 'name' entry in '%s'", v.ConfigFileUsed(),
				), nil,
			)
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
		msg := fmt.Sprintf("error reading configuration file: %s", err.Error())
		return nil, fail.Errorf(fmt.Sprintf(msg), nil)
	}
	settings := v.AllSettings()
	tenantsCfg, ok := settings["tenants"].([]interface{})

	if !ok {
		return nil, fail.Errorf("invalid tenants.toml configuration file", nil)
	}

	return tenantsCfg, nil
}
