/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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
	"context"
	"expvar"
	"fmt"
	"os"
	"regexp"
	"time"

	stackoptions "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/options"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/terraformer"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/dgraph-io/ristretto"
	"github.com/eko/gocache/v2/cache"
	"github.com/eko/gocache/v2/store"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/crypt"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

var (
	// allProviders = map[string]Service{}
	allProviderProfiles = map[string]*providers.Profile{}
)

// // Register a service referenced by the provider name. Ex: "ovh", ovh.New()
// // This function should be called by the init function of each provider to be registered in SafeScale
// func Register(name string, provider providers.Provider) {
// 	// if already registered, leave
// 	if _, ok := allProviders[name]; ok {
// 		return
// 	}
// 	allProviders[name] = &service{
// 		Provider: provider,
// 	}
// 	allProviderProfiles[name] = providers.NewProfile(provider.Capabilities())
// }

// Register a service referenced by the provider name. Ex: "ovh", ovh.New()
// This function should be called by the init function of each provider to be registered in SafeScale
func Register(name string, profile *providers.Profile) {
	// if already registered, leave
	if _, ok := allProviderProfiles[name]; ok {
		return
	}

	allProviderProfiles[name] = profile
}

// GetTenantNames returns all known tenants names
func GetTenantNames() (map[string]string, fail.Error) {
	out, err := loadConfig()
	return out, err
}

// GetTenants returns all known tenants
func GetTenants() ([]map[string]interface{}, fail.Error) {
	tenants, _, err := getTenantsFromCfg()
	if err != nil {
		return nil, err
	}
	return tenants, err
}

// FindProfile returns a Profile corresponding to provider name passed as parameter
func FindProfile(providerName string) (*providers.Profile, fail.Error) {
	if providerName == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("providerName")
	}

	p, ok := allProviderProfiles[providerName]
	if !ok {
		return nil, fail.NotFoundError("failed to find a Profile for Provider '%s'", providerName)
	}

	return p, nil
}

type (
	Options struct {
		tenantName               string
		terraformerConfiguration terraformer.Configuration
	}

	OptionsMutator func(o *Options) fail.Error
)

func WithTenant(name string) OptionsMutator {
	return func(o *Options) fail.Error {
		if name == "" {
			return fail.InvalidParameterCannotBeEmptyStringError("name")
		}

		o.tenantName = name
		return nil
	}
}

// WithTerraformer allows to indicate what terraformer.Configuration has to be used
func WithTerraformer(config terraformer.Configuration) OptionsMutator {
	return func(o *Options) fail.Error {
		if valid.IsNull(config) {
			return fail.InvalidParameterError("config", "must be a valid 'terraformer.Configuration' in WithTerraformer()")
		}

		o.terraformerConfiguration = config
		return nil
	}
}

// UseService return the service referenced by the given name.
// If necessary, this function try to load service from configuration file
func UseService(opts ...OptionsMutator) (newService Service, ferr fail.Error) {
	ctx := context.Background() // FIXME: Check context
	defer fail.OnExitLogError(ctx, &ferr)
	defer fail.OnPanic(&ferr)

	var settings Options
	for k, v := range opts {
		xerr := v(&settings)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to apply option #%d", k)
		}
	}

	tenants, _, err := getTenantsFromCfg()
	if err != nil {
		return NullService(), err
	}

	var (
		tenantInCfg    bool
		found          bool
		name, provider string
		svcProvider    = "__not_found__"
	)

	for _, currentTenant := range tenants {
		name, found = currentTenant["name"].(string)
		if !found {
			logrus.WithContext(ctx).Error("found tenant without 'name' parameter")
			continue
		}
		if name != settings.tenantName {
			continue
		}

		tenantInCfg = true
		provider, found = currentTenant["provider"].(string)
		if !found {
			provider, found = currentTenant["client"].(string)
			if !found {
				logrus.WithContext(ctx).Error("Missing field 'provider' or 'client' in currentTenant")
				continue
			}
		}

		svcProvider = provider
		svcProviderProfile, xerr := FindProfile(provider)
		if xerr != nil {
			logrus.WithContext(ctx).Errorf(xerr.Error())
			continue
		}

		_, found = currentTenant["identity"].(map[string]interface{})
		if !found {
			logrus.WithContext(ctx).Debugf("No section 'identity' found in currentTenant '%s', continuing.", name)
		}
		_, found = currentTenant["compute"].(map[string]interface{})
		if !found {
			logrus.WithContext(ctx).Debugf("No section 'compute' found in currentTenant '%s', continuing.", name)
		}
		_, found = currentTenant["network"].(map[string]interface{})
		if !found {
			logrus.WithContext(ctx).Debugf("No section 'network' found in currentTenant '%s', continuing.", name)
		}

		_, tenantObjectStorageFound := currentTenant["objectstorage"]
		_, tenantMetadataFound := currentTenant["metadata"]

		// Initializes provider
		var providerInstance providers.Provider
		referenceProviderInstance := svcProviderProfile.ReferenceInstance()
		if svcProviderProfile.Capabilities().UseTerraformer {
			providerInstance, xerr = referenceProviderInstance.BuildWithTerraformer(currentTenant, settings.terraformerConfiguration)
		} else {
			providerInstance, xerr = referenceProviderInstance.Build(currentTenant)
		}
		if xerr != nil {
			return NullService(), fail.Wrap(xerr, "error initializing currentTenant '%s' on provider '%s'", settings.tenantName, provider)
		}

		ristrettoCache, err := ristretto.NewCache(&ristretto.Config{
			NumCounters: 1000,
			MaxCost:     100,
			BufferItems: 1024,
		})
		if err != nil {
			return nil, fail.ConvertError(err)
		}

		newS := &service{
			Provider:     providerInstance,
			tenantName:   settings.tenantName,
			cacheManager: NewWrappedCache(cache.New(store.NewRistretto(ristrettoCache, &store.Options{Expiration: 1 * time.Minute}))),
		}

		if beta := os.Getenv("SAFESCALE_CACHE"); beta != "" {
			logrus.WithContext(ctx).Infof("Created a cache in: %p", newS.cacheManager)
		}

		// allRegions, xerr := newS.ListRegions()
		// if xerr != nil {
		// 	switch xerr.(type) {
		// 	case *fail.ErrNotFound:
		// 		break
		// 	default:
		// 		return NullService(), xerr
		// 	}
		// }

		authOpts, xerr := providerInstance.AuthenticationOptions()
		if xerr != nil {
			return NullService(), xerr
		}

		// Validate region parameter in compute section
		// VPL: does not work with Outscale "cloudgouv"...
		// computeRegion := authOpts.GetString("Region")
		// xerr = validateRegionName(computeRegion, allRegions)
		// if xerr != nil {
		// 	return NullService(), fail.Wrap(xerr, "invalid region in section 'compute'")
		// }

		// Initializes Object Storage
		var objectStorageLocation objectstorage.Location
		if tenantObjectStorageFound {
			objectStorageConfig, xerr := initObjectStorageLocationConfig(authOpts, currentTenant)
			if xerr != nil {
				return NullService(), xerr
			}

			// VPL: disable region validation, may need to update allRegions for objectstorage/metadata)
			// xerr = validateRegionName(objectStorageConfig.Region, allRegions)
			// if xerr != nil {
			// 	return nil, fail.Wrap(xerr, "invalid region in section 'objectstorage")
			// }

			objectStorageLocation, xerr = objectstorage.NewLocation(objectStorageConfig)
			if xerr != nil {
				return NullService(), fail.Wrap(xerr, "error connecting to Object Storage location")
			}
		} else {
			logrus.WithContext(ctx).Warnf("missing section 'objectstorage' in configuration file for currentTenant '%s'", settings.tenantName)
		}

		// Initializes Metadata Object Storage (maybe different from the Object Storage)
		var (
			metadataBucket   abstract.ObjectStorageBucket
			metadataCryptKey *crypt.Key
		)
		if tenantMetadataFound || tenantObjectStorageFound {
			metadataLocationConfig, err := initMetadataLocationConfig(authOpts, currentTenant)
			if err != nil {
				return NullService(), err
			}

			// VPL: disable region validation, may need to update allRegions for objectstorage/metadata)
			// xerr = validateRegionName(metadataLocationConfig.Region, allRegions)
			// if xerr != nil {
			// 	return nil, fail.Wrap(xerr, "invalid region in section 'metadata'")
			// }

			metadataLocation, xerr := objectstorage.NewLocation(metadataLocationConfig)
			if xerr != nil {
				return NullService(), fail.Wrap(xerr, "error connecting to Object Storage location to store metadata")
			}

			if metadataLocationConfig.BucketName == "" {
				serviceCfg, xerr := providerInstance.ConfigurationOptions()
				if xerr != nil {
					return NullService(), xerr
				}

				metadataLocationConfig.BucketName = serviceCfg.MetadataBucketName
			}
			found, err = metadataLocation.FindBucket(ctx, metadataLocationConfig.BucketName)
			if err != nil {
				return NullService(), fail.Wrap(err, "error accessing metadata location: %s", metadataLocationConfig.BucketName)
			}

			if found {
				metadataBucket, err = metadataLocation.InspectBucket(ctx, metadataLocationConfig.BucketName)
				if err != nil {
					return NullService(), err
				}
			} else {
				// create bucket
				metadataBucket, err = metadataLocation.CreateBucket(ctx, metadataLocationConfig.BucketName)
				if err != nil {
					return NullService(), err
				}

				// // Creates metadata version file
				// if metadataVersion != "" {
				// 	content := bytes.NewBuffer([]byte(metadataVersion))
				// 	_, xerr := metadataLocation.WriteObject(ctx, metadataLocationConfig.BucketName, "version", content, int64(content.Len()), nil)
				// 	if xerr != nil {
				// 		return NullService(), fail.Wrap(xerr, "failed to create version object in metadata Bucket")
				// 	}
				// }
			}
			if metadataConfig, ok := currentTenant["metadata"].(map[string]interface{}); ok {
				if key, ok := metadataConfig["CryptKey"].(string); ok {
					ek, err := crypt.NewEncryptionKey([]byte(key))
					if err != nil {
						return NullService(), fail.ConvertError(err)
					}
					metadataCryptKey = ek
				}
			}
			logrus.WithContext(ctx).Infof("Setting default Tenant to '%s'; storing metadata in bucket '%s'", settings.tenantName, metadataBucket.GetName())
		} else {
			return NullService(), fail.SyntaxError("failed to build service: 'metadata' section (and 'objectstorage' as fallback) is missing in configuration file for currentTenant '%s'", settings.tenantName)
		}

		// service is ready
		newS.Location = objectStorageLocation
		newS.metadataBucket = metadataBucket
		newS.metadataKey = metadataCryptKey

		if xerr := validateRegexps(newS, currentTenant); xerr != nil {
			return NullService(), xerr
		}

		// increase currentTenant counter
		ts := expvar.Get("currentTenant.setted")
		if ts != nil {
			tsi, ok := ts.(*expvar.Int)
			if ok {
				tsi.Add(1)
			}
		}

		return newS, nil
	}

	if !tenantInCfg {
		return NullService(), fail.NotFoundError("currentTenant '%s' not found in configuration", settings.tenantName)
	}

	return NullService(), fail.NotFoundError("provider builder for '%s'", svcProvider)
}

// validateRegionName validates the availability of the region passed as parameter
func validateRegionName(name string, allRegions []string) fail.Error { // nolint
	// FIXME: Use this function
	if len(allRegions) > 0 {
		regionIsValidInput := false
		for _, vr := range allRegions {
			if name == vr {
				regionIsValidInput = true
			}
		}
		if !regionIsValidInput {
			return fail.NotFoundError("region '%s' not found", name)
		}
	}

	return nil
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
func initObjectStorageLocationConfig(authOpts stackoptions.Authentication, tenant map[string]interface{}) (
	objectstorage.Config, fail.Error,
) {
	var (
		config objectstorage.Config
		ok     bool
	)

	identity, _ := tenant["identity"].(map[string]interface{})      // nolint
	compute, _ := tenant["compute"].(map[string]interface{})        // nolint
	ostorage, _ := tenant["objectstorage"].(map[string]interface{}) // nolint

	if config.Type, ok = ostorage["Type"].(string); !ok {
		return config, fail.SyntaxError("missing setting 'Type' in 'objectstorage' section")
	}

	if config.Domain, ok = ostorage["Domain"].(string); !ok {
		if config.Domain, ok = ostorage["DomainName"].(string); !ok {
			if config.Domain, ok = compute["Domain"].(string); !ok {
				if config.Domain, ok = compute["DomainName"].(string); !ok {
					if config.Domain, ok = identity["Domain"].(string); !ok {
						if config.Domain, ok = identity["DomainName"].(string); !ok {
							config.Domain = authOpts.DomainName
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
						config.Tenant = authOpts.ProjectName
					}
				}
			}
		}
	}

	config.AuthURL, _ = ostorage["AuthURL"].(string)   // nolint
	config.Endpoint, _ = ostorage["Endpoint"].(string) // nolint
	if _, ok := ostorage["Direct"]; ok {
		config.Direct, _ = ostorage["Direct"].(bool) // nolint
	}

	if config.User, ok = ostorage["AccessKey"].(string); !ok {
		if config.User, ok = ostorage["OpenStackID"].(string); !ok {
			if config.User, ok = ostorage["Username"].(string); !ok {
				if config.User, ok = identity["OpenstackID"].(string); !ok {
					config.User, _ = identity["Username"].(string) // nolint
				}
			}
		}
	}

	if config.Key, ok = ostorage["ApplicationKey"].(string); !ok {
		config.Key, _ = identity["ApplicationKey"].(string) // nolint
	}

	if config.SecretKey, ok = ostorage["SecretKey"].(string); !ok {
		if config.SecretKey, ok = ostorage["OpenstackPassword"].(string); !ok {
			if config.SecretKey, ok = ostorage["Password"].(string); !ok {
				if config.SecretKey, ok = identity["SecretKey"].(string); !ok {
					if config.SecretKey, ok = identity["OpenstackPassword"].(string); !ok {
						config.SecretKey, _ = identity["Password"].(string) // nolint
					}
				}
			}
		}
	}

	if config.Region, ok = ostorage["Region"].(string); !ok {
		config.Region, _ = compute["Region"].(string) // nolint
		// if err := validateOVHObjectStorageRegionNaming("objectstorage", config.Region, config.AuthURL); err != nil {
		// 	return config, err
		// }
	}

	if config.AvailabilityZone, ok = ostorage["AvailabilityZone"].(string); !ok {
		config.AvailabilityZone, _ = compute["AvailabilityZone"].(string) // nolint
	}

	for k, v := range identity {
		if _, ok = v.(string); !ok {
			return config, fail.InconsistentError("'identity' it's a map[string]string, and the key %s is not a string: %v", k, v)
		}
	}
	for k, v := range compute {
		if _, ok = v.(string); !ok {
			if _, ok = v.(bool); ok {
				continue
			}
			if k == "DNSServers" {
				continue
			}
			return config, fail.InconsistentError("'compute' it's a map[string]string, and the key %s is not a string: %v", k, v)
		}
	}
	for k, v := range ostorage {
		if _, ok = v.(string); !ok {
			return config, fail.InconsistentError("'ostorage' it's a map[string]string, and the key %s is not a string: %v", k, v)
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

		config.ProjectID, ok = identity["project_id"].(string)
		if !ok {
			return config, fail.InconsistentError("'project_id' MUST be a string in tenants.toml: %v", identity["project_id"])
		}

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

// func validateOVHObjectStorageRegionNaming(context, region, authURL string) fail.Error {
// 	// If AuthURL contains OVH, special treatment due to change in object storage 'region'-ing since 2020/02/17
// 	// Object Storage regions don't contain anymore an index like compute regions
// 	if strings.Contains(authURL, "ovh.") {
// 		rLen := len(region)
// 		if _, err := strconv.Atoi(region[rLen-1:]); err == nil {
// 			region = region[:rLen-1]
// 			return fail.InvalidRequestError(fmt.Sprintf(`region names for OVH Object Storage have changed since 2020/02/17. Please set or update the %s tenant definition with 'Region = "%s"'.`, context, region))
// 		}
// 	}
// 	return nil
// }

// initMetadataLocationConfig initializes objectstorage.Config struct with map
func initMetadataLocationConfig(authOpts stackoptions.Authentication, tenant map[string]interface{}) (objectstorage.Config, fail.Error) {
	var (
		config objectstorage.Config
		ok     bool
	)

	// FIXME: This code is ancient and doesn't provide nor hints nor protection against formatting

	identity, _ := tenant["identity"].(map[string]interface{})      // nolint
	compute, _ := tenant["compute"].(map[string]interface{})        // nolint
	ostorage, _ := tenant["objectstorage"].(map[string]interface{}) // nolint
	metadata, _ := tenant["metadata"].(map[string]interface{})      // nolint

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
									config.Domain = authOpts.DomainName
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
									config.Tenant, _ = compute["ProjectID"].(string) // nolint
								}
							}
						}
					}
				}
			}
		}
	}

	if config.AuthURL, ok = metadata["AuthURL"].(string); !ok {
		config.AuthURL, _ = ostorage["AuthURL"].(string) // nolint
	}

	if config.Endpoint, ok = metadata["Endpoint"].(string); !ok {
		config.Endpoint, _ = ostorage["Endpoint"].(string) // nolint
	}

	if config.User, ok = metadata["AccessKey"].(string); !ok {
		if config.User, ok = metadata["OpenstackID"].(string); !ok {
			if config.User, ok = metadata["Username"].(string); !ok {
				if config.User, ok = ostorage["AccessKey"].(string); !ok {
					if config.User, ok = ostorage["OpenStackID"].(string); !ok {
						if config.User, ok = ostorage["Username"].(string); !ok {
							if config.User, ok = identity["Username"].(string); !ok {
								config.User, _ = identity["OpenstackID"].(string) // nolint
							}
						}
					}
				}
			}
		}
	}

	config.DNS, _ = compute["DNS"].(string) // nolint

	if config.Key, ok = metadata["ApplicationKey"].(string); !ok {
		if config.Key, ok = ostorage["ApplicationKey"].(string); !ok {
			config.Key, _ = identity["ApplicationKey"].(string) // nolint
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
												config.SecretKey, _ = identity["OpenstackPassword"].(string) // nolint
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
			config.Region, _ = compute["Region"].(string) // nolint
		}
		// FIXME: Wrong, this needs validation, but not ALL providers
		// if err := validateOVHObjectStorageRegionNaming("objectstorage", config.Region, config.AuthURL); err != nil {
		// 	return config, err
		// }
	}

	if config.AvailabilityZone, ok = metadata["AvailabilityZone"].(string); !ok {
		if config.AvailabilityZone, ok = ostorage["AvailabilityZone"].(string); !ok {
			config.AvailabilityZone, _ = compute["AvailabilityZone"].(string) // nolint
		}
	}

	// FIXME: Remove google custom code, it's a problem, think about delegation to providers
	if config.Type == "google" {
		keys := []string{"project_id", "private_key_id", "private_key", "client_email", "client_id", "auth_uri", "token_uri", "auth_provider_x509_cert_url", "client_x509_cert_url"}
		for _, key := range keys {
			if _, ok = identity[key].(string); !ok {
				return config, fail.SyntaxError("problem parsing %s", key)
			}
		}

		config.ProjectID, ok = identity["project_id"].(string)
		if !ok {
			return config, fail.NewError("'project_id' MUST be a string in tenants.toml: %v", identity["project_id"])
		}

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

	config.BucketName, _ = metadata["MetadataBucketName"].(string) // nolint
	return config, nil
}

// loadConfig loads the configuration from tenants file
// FIXME: use an approach allowing to refresh tenant list from file on file change, not at each call
func loadConfig() (map[string]string, fail.Error) {
	out := map[string]string{}
	tenantsCfg, v, err := getTenantsFromCfg()
	if err != nil {
		return nil, err
	}
	for _, tenant := range tenantsCfg {
		name, ok := tenant["name"].(string)
		if !ok {
			name, ok = tenant["Name"].(string)
		}
		if ok {
			provider, ok := tenant["client"].(string)
			if !ok {
				provider, ok = tenant["Client"].(string)
			}
			if ok {
				out[name] = provider
			} else {
				return nil, fail.SyntaxError("invalid configuration file '%s'. Tenant '%s' has no client type", v.ConfigFileUsed(), name)
			}
		} else {
			return nil, fail.SyntaxError("invalid configuration file. A tenant has no 'name' entry in '%s'", v.ConfigFileUsed())
		}
	}
	return out, nil
}

func getTenantsFromCfg() ([]map[string]interface{}, *viper.Viper, fail.Error) {
	v := viper.New()
	v.AddConfigPath(".")
	v.AddConfigPath("$HOME/.safescale")
	v.AddConfigPath(utils.AbsPathify("$HOME/.safescale"))
	v.AddConfigPath("$HOME/.config/safescale")
	v.AddConfigPath(utils.AbsPathify("$HOME/.config/safescale"))
	v.AddConfigPath("/etc/safescale")
	v.SetConfigName("tenants")
	return getTenantsFromViperCfg(v)
}

func getTenantsFromViperCfg(v *viper.Viper) ([]map[string]interface{}, *viper.Viper, fail.Error) {
	ctx := context.Background()

	if err := v.ReadInConfig(); err != nil { // Handle errors reading the config file
		msg := fmt.Sprintf("error reading configuration file: %s", err.Error())
		logrus.WithContext(ctx).Errorf(msg)
		return nil, v, fail.SyntaxError(msg)
	}

	var tenantsCfg []map[string]interface{}
	err := v.UnmarshalKey("tenants", &tenantsCfg)
	if err != nil {
		return nil, v, fail.SyntaxError("failed to convert tenants file to map[string]interface{}")
	}

	jsoned, err := json.Marshal(tenantsCfg)
	if err != nil {
		return nil, v, fail.ConvertError(err)
	}

	var out []map[string]interface{}
	err = json.Unmarshal(jsoned, &out)
	if err != nil {
		return nil, v, fail.ConvertError(err)
	}
	return out, v, nil
}
