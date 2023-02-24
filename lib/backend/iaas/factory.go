/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
	"context"
	"expvar"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

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
	allProviders = map[string]Service{}
)

// Register a Client referenced by the provider name. Ex: "ovh", ovh.New()
// This function should be called by the init function of each provider to be registered in SafeScale
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

// UseService return the service referenced by the given name.
// If necessary, this function try to load service from configuration file
func UseService(inctx context.Context, tenantName string, metadataVersion string) (newService Service, ferr fail.Error) {
	ctx := inctx

	defer fail.OnExitLogError(ctx, &ferr)
	defer fail.OnPanic(&ferr)

	tenants, _, err := getTenantsFromCfg()
	if err != nil {
		return nullService(), err
	}

	var (
		tenantInCfg    bool
		found          bool
		ok             bool
		name, provider string
		svc            Service
		svcProvider    = "__not_found__"
	)

	for _, tenant := range tenants {
		name, found = tenant["name"].(string)
		if !found {
			name, found = tenant["Name"].(string)
			if !found {
				logrus.WithContext(ctx).Error("tenant found without 'name'")
				continue
			}
		}
		if name != tenantName {
			continue
		}

		tenantInCfg = true

		xerr := validateTenant(tenant)

		if xerr != nil {
			return nullService(), xerr
		}

		providerKeysToCheck := []string{
			"provider",
			"Provider",
			"client",
			"Client",
		}

		ok = false

		for _, key := range providerKeysToCheck {
			if provider, found = tenant[key].(string); found {
				svcProvider = provider
				ok = true
				break
			}
		}

		if !ok {
			logrus.WithContext(ctx).Error("Missing field 'provider' or 'client' in tenant")
			continue
		}

		svc, found = allProviders[provider]
		if !found {
			logrus.WithContext(ctx).Errorf("failed to find client '%s' for tenant '%s'", svcProvider, name)
			continue
		}

		_, found = tenant["identity"].(map[string]interface{})
		if !found {
			logrus.WithContext(ctx).Debugf("No section 'identity' found in tenant '%s', continuing.", name)
		}
		_, found = tenant["compute"].(map[string]interface{})
		if !found {
			logrus.WithContext(ctx).Debugf("No section 'compute' found in tenant '%s', continuing.", name)
		}
		_, found = tenant["network"].(map[string]interface{})
		if !found {
			logrus.WithContext(ctx).Debugf("No section 'network' found in tenant '%s', continuing.", name)
		}

		_, tenantObjectStorageFound := tenant["objectstorage"]
		_, tenantMetadataFound := tenant["metadata"]

		// Initializes Provider
		providerInstance, xerr := svc.Build(tenant)
		if xerr != nil {
			return nullService(), fail.Wrap(xerr, "error initializing tenant '%s' on provider '%s'", tenantName, provider)
		}

		ristrettoCache, err := ristretto.NewCache(&ristretto.Config{
			NumCounters: 1024,
			MaxCost:     50000000,
			BufferItems: 128,
		})
		if err != nil {
			return nil, fail.ConvertError(err)
		}

		newS := &service{
			Provider:           providerInstance,
			tenantName:         tenantName,
			cacheManager:       NewWrappedCache(cache.New(store.NewRistretto(ristrettoCache, &store.Options{Expiration: 120 * time.Minute}))),
			mLoadHost:          &sync.Mutex{},
			mLoadCluster:       &sync.Mutex{},
			mLoadLabel:         &sync.Mutex{},
			mLoadNetwork:       &sync.Mutex{},
			mLoadShare:         &sync.Mutex{},
			mLoadVolume:        &sync.Mutex{},
			mLoadBucket:        &sync.Mutex{},
			mLoadSubnet:        &sync.Mutex{},
			mLoadSecurityGroup: &sync.Mutex{},
			mLoadFeature:       &sync.Mutex{},
		}

		if beta := os.Getenv("SAFESCALE_CACHE"); beta != "disabled" {
			logrus.WithContext(ctx).Infof("Created a cache in: %p", newS.cacheManager)
		}

		authOpts, xerr := providerInstance.GetAuthenticationOptions(ctx)
		if xerr != nil {
			return nullService(), xerr
		}

		// Initializes Object Storage
		var objectStorageLocation objectstorage.Location
		if tenantObjectStorageFound {
			objectStorageConfig, xerr := initObjectStorageLocationConfig(authOpts, tenant)
			if xerr != nil {
				return nullService(), xerr
			}

			objectStorageLocation, xerr = objectstorage.NewLocation(objectStorageConfig)
			if xerr != nil {
				return nullService(), fail.Wrap(xerr, "error connecting to Object Storage location")
			}
		} else {
			logrus.WithContext(ctx).Warnf("missing section 'objectstorage' in configuration file for tenant '%s'", tenantName)
		}

		// Initializes Metadata Object Storage (maybe different from the Object Storage)
		var (
			metadataBucket   abstract.ObjectStorageBucket
			metadataCryptKey *crypt.Key
		)
		if tenantMetadataFound || tenantObjectStorageFound {
			metadataLocationConfig, err := initMetadataLocationConfig(authOpts, tenant)
			if err != nil {
				return nullService(), err
			}

			metadataLocation, xerr := objectstorage.NewLocation(metadataLocationConfig)
			if xerr != nil {
				return nullService(), fail.Wrap(xerr, "error connecting to Object Storage location to store metadata")
			}

			if metadataLocationConfig.BucketName == "" {
				serviceCfg, xerr := providerInstance.GetConfigurationOptions(ctx)
				if xerr != nil {
					return nullService(), xerr
				}

				anon, there := serviceCfg.Get("MetadataBucketName")
				if !there {
					return nullService(), fail.SyntaxError("missing configuration option 'MetadataBucketName'")
				}

				var ok bool
				metadataLocationConfig.BucketName, ok = anon.(string)
				if !ok {
					return nullService(), fail.InvalidRequestError("invalid bucket name, it's not a string")
				}
			}
			found, err = metadataLocation.FindBucket(ctx, metadataLocationConfig.BucketName)
			if err != nil {
				return nullService(), fail.Wrap(err, "error accessing metadata location: %s", metadataLocationConfig.BucketName)
			}

			if found {
				metadataBucket, err = metadataLocation.InspectBucket(ctx, metadataLocationConfig.BucketName)
				if err != nil {
					return nullService(), err
				}
			} else {
				// create bucket
				metadataBucket, err = metadataLocation.CreateBucket(ctx, metadataLocationConfig.BucketName)
				if err != nil {
					return nullService(), err
				}

				// Creates metadata version file
				if metadataVersion != "" {
					content := bytes.NewBuffer([]byte(metadataVersion))
					_, xerr := metadataLocation.WriteObject(ctx, metadataLocationConfig.BucketName, "version", content, int64(content.Len()), nil)
					if xerr != nil {
						return nullService(), fail.Wrap(xerr, "failed to create version object in metadata Bucket")
					}
				}
			}
			if metadataConfig, ok := tenant["metadata"].(map[string]interface{}); ok {
				if key, ok := metadataConfig["CryptKey"].(string); ok {
					ek, err := crypt.NewEncryptionKey([]byte(key))
					if err != nil {
						return nullService(), fail.ConvertError(err)
					}
					metadataCryptKey = ek
				}
			}
			logrus.WithContext(ctx).Infof("Setting default Tenant to '%s'; storing metadata in bucket '%s'", tenantName, metadataBucket.GetName())
		} else {
			return nullService(), fail.SyntaxError("failed to build service: 'metadata' section (and 'objectstorage' as fallback) is missing in configuration file for tenant '%s'", tenantName)
		}

		// service is ready
		newS.Location = objectStorageLocation
		newS.metadataBucket = metadataBucket
		newS.metadataKey = metadataCryptKey

		// FIXME: OPP, Wrong, this is input validation, and should be into Build.
		if xerr := validateRegexps(newS, tenant); xerr != nil {
			return nullService(), xerr
		}

		// increase tenant counter
		ts := expvar.Get("tenant.setted")
		if ts != nil {
			tsi, ok := ts.(*expvar.Int)
			if ok {
				tsi.Add(1)
			}
		}

		return newS, nil
	}

	if !tenantInCfg {
		return nullService(), fail.NotFoundError("tenant '%s' not found in configuration", tenantName)
	}
	return nullService(), fail.NotFoundError("provider builder for '%s'", svcProvider)
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

	res, xerr := validateRegexpsOfKeyword("WhitelistTemplateRegexp", compute["WhitelistTemplateRegexp"])
	if xerr != nil {
		return xerr
	}
	svc.whitelistTemplateREs = res

	res, xerr = validateRegexpsOfKeyword("BlacklistTemplateRegexp", compute["BlacklistTemplateRegexp"])
	if xerr != nil {
		return xerr
	}
	svc.blacklistTemplateREs = res

	res, xerr = validateRegexpsOfKeyword("WhitelistImageRegexp", compute["WhitelistImageRegexp"])
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
	if str, ok := content.(string); ok {
		re, err := regexp.Compile(str)
		if err != nil {
			return nil, fail.SyntaxError("invalid value '%s' for keyword '%s': %s", str, keyword, err.Error())
		}
		out = append(out, re)
		return out, nil
	}

	if list, ok := content.([]interface{}); ok { // FIXME: This branch never ever happened, the input is always a string
		for _, v := range list {
			re, err := regexp.Compile(v.(string))
			if err != nil {
				return nil, fail.SyntaxError("invalid value '%s' for keyword '%s': %s", v, keyword, err.Error())
			}
			out = append(out, re)
		}
		return out, nil
	}

	return out, nil
}

// initObjectStorageLocationConfig initializes objectstorage.Config struct with map
func initObjectStorageLocationConfig(authOpts providers.Config, tenant map[string]interface{}) (
	objectstorage.Config, fail.Error,
) {
	var (
		config objectstorage.Config
		ok     bool
		found  bool
	)

	identity, _ := tenant["identity"].(map[string]interface{})      // nolint
	compute, _ := tenant["compute"].(map[string]interface{})        // nolint
	ostorage, _ := tenant["objectstorage"].(map[string]interface{}) // nolint
	client, _ := tenant["client"].(string)

	if config.Type, ok = ostorage["Type"].(string); !ok {
		return config, fail.SyntaxError("missing setting 'Type' in 'objectstorage' section")
	}

	domainKeysToCheck := []string{
		"Domain",
		"DomainName",
	}

	found = false

	for _, key := range domainKeysToCheck {
		if val, ok := ostorage[key].(string); ok {
			config.Domain = val
			found = true
			break
		} else if val, ok := compute[key].(string); ok {
			config.Domain = val
			found = true
			break
		} else if val, ok := identity[key].(string); ok {
			config.Domain = val
			found = true
			break
		}
	}
	if !found {
		config.Domain = authOpts.GetString("DomainName")
	}

	config.TenantDomain = config.Domain

	tenantKeysToCheck := []string{
		"Tenant",
		"ProjectName",
		"ProjectID",
	}

	found = false

	for _, key := range tenantKeysToCheck {
		if val, ok := ostorage[key].(string); ok {
			config.Tenant = val
			found = true
			break
		} else if val, ok := compute[key].(string); ok {
			config.Tenant = val
			found = true
			break
		}
	}

	if !found {
		config.Tenant = authOpts.GetString("ProjectName")
	}

	config.AuthURL, _ = ostorage["AuthURL"].(string)   // nolint
	config.Endpoint, _ = ostorage["Endpoint"].(string) // nolint
	if _, ok := ostorage["Direct"]; ok {
		config.Direct, _ = ostorage["Direct"].(bool) // nolint
	}

	if client != "gcp" {
		userKeysToCheck := []string{
			"AccessKey",
			"OpenstackID",
			"Username",
		}

		found = false

		for _, key := range userKeysToCheck {
			if val, ok := ostorage[key].(string); ok {
				config.User = val
				found = true
				break
			} else if val, ok := identity[key].(string); ok {
				config.User = val
				found = true
				break
			}
		}

		if !found {
			return config, fail.SyntaxError("missing setting 'AccessKey', 'OpenstackID' or 'Username' field in 'identity' section")
		}
	}

	if client == "ovh" || client == "openstack" || client == "cloudferro" {
		key := "ApplicationKey"

		if val, ok := ostorage[key].(string); ok {
			config.Key = val
		} else if val, ok := identity[key].(string); ok {
			config.Key = val
		} else if tenant["client"].(string) != "aws" {
			return config, fail.SyntaxError("missing setting 'ApplicationKey' in 'identity' section")
		}
	}

	secretKeyToCheck := []string{
		"SecretKey",
		"OpenstackPassword",
		"Password",
	}

	found = false

	for _, key := range secretKeyToCheck {
		if val, ok := ostorage[key].(string); ok {
			config.SecretKey = val
			found = true
			break
		} else if val, ok := identity[key].(string); ok {
			config.SecretKey = val
			found = true
			break
		}
	}

	if !found {
		return config, fail.SyntaxError("missing settings 'SecretKey' or 'OpenstackPassword' or 'Password' in 'identity' section")
	}

	if config.Region, ok = ostorage["Region"].(string); !ok {
		config.Region, _ = compute["Region"].(string) // nolint
		// TODO : Use validateRegionName function
		// if err := validateOVHObjectStorageRegionNaming("objectstorage", config.Region, config.AuthURL); err != nil {
		// 	return config, err
		// }
	}

	key := "AvailabilityZone"

	if val, ok := ostorage[key].(string); ok {
		config.AvailabilityZone = val
	} else if val, ok := compute[key].(string); ok {
		config.AvailabilityZone = val
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
			if k == "DNSList" {
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
func initMetadataLocationConfig(authOpts providers.Config, tenant map[string]interface{}) (
	objectstorage.Config, fail.Error,
) {
	var (
		config objectstorage.Config
		ok     bool
		found  bool
	)

	// FIXME: This code is ancient and doesn't provide nor hints nor protection against formatting

	identity, _ := tenant["identity"].(map[string]interface{})      // nolint
	compute, _ := tenant["compute"].(map[string]interface{})        // nolint
	ostorage, _ := tenant["objectstorage"].(map[string]interface{}) // nolint
	metadata, _ := tenant["metadata"].(map[string]interface{})      // nolint
	client, _ := tenant["client"].(string)

	if config.Type, ok = metadata["Type"].(string); !ok {
		if config.Type, ok = ostorage["Type"].(string); !ok {
			return config, fail.SyntaxError("missing setting 'Type' in 'metadata' section")
		}
	}

	var domainKeyToCheck = []string{
		"Domain",
		"DomainName",
	}

	found = false

	for _, key := range domainKeyToCheck {
		if val, ok := metadata[key].(string); ok {
			config.Domain = val
			found = true
			break
		} else if val, ok := ostorage[key].(string); ok {
			config.Domain = val
			found = true
			break
		} else if val, ok := compute[key].(string); ok {
			config.Domain = val
			found = true
			break
		} else if val, ok := compute[key].(string); ok {
			config.Domain = val
			found = true
			break
		}
	}

	if !found {
		config.Domain = authOpts.GetString("DomainName")
	}

	config.TenantDomain = config.Domain

	var tenantKeysToCheck = []string{
		"Tenant",
		"ProjectName",
		"ProjectID",
	}

	for _, key := range tenantKeysToCheck {
		if val, ok := metadata[key].(string); ok {
			config.Tenant = val
			break
		} else if val, ok := ostorage[key].(string); ok {
			config.Tenant = val
			break
		} else if val, ok := compute[key].(string); ok {
			config.Tenant = val
			break
		}
	}

	if config.AuthURL, ok = metadata["AuthURL"].(string); !ok {
		config.AuthURL, _ = ostorage["AuthURL"].(string) // nolint
	}

	if config.Endpoint, ok = metadata["Endpoint"].(string); !ok {
		config.Endpoint, _ = ostorage["Endpoint"].(string) // nolint
	}

	if client != "gcp" {
		var userKeysToCheck = []string{
			"AccessKey",
			"OpenstackID",
			"Username",
		}

		found = false

		for _, key := range userKeysToCheck {
			if val, ok := metadata[key].(string); ok {
				config.User = val
				found = true
				break
			} else if val, ok := ostorage[key].(string); ok {
				config.User = val
				found = true
				break
			} else if val, ok := identity[key].(string); ok {
				config.User = val
				found = true
				break
			}
		}
		if !found {
			return config, fail.SyntaxError("missing setting 'AccessKey', 'OpenstackID' or 'Username' field in 'identity' section")
		}
	}

	config.DNS, _ = compute["DNS"].(string) // nolint

	if client == "ovh" || client == "openstack" || client == "cloudferro" {
		key := "ApplicationKey"
		found = false

		if val, ok := metadata[key].(string); ok {
			config.Key = val
			found = true
		} else if val, ok := ostorage[key].(string); ok {
			config.Key = val
			found = true
		} else if val, ok := identity[key].(string); ok {
			config.Key = val
			found = true
		}
		if !found {
			return config, fail.SyntaxError("missing setting 'ApplicationKey' field in 'identity' section")
		}
	}

	var secretKeysToCheck = []string{
		"SecretKey",
		"AccessPassword",
		"OpenstackPassword",
		"Password",
	}

	found = false

	for _, key := range secretKeysToCheck {
		if val, ok := metadata[key].(string); ok {
			config.SecretKey = val
			found = true
			break
		} else if val, ok := ostorage[key].(string); ok {
			config.SecretKey = val
			found = true
			break
		} else if val, ok := identity[key].(string); ok {
			config.SecretKey = val
			found = true
			break
		}
	}
	if !found {
		return config, fail.SyntaxError("missing setting 'SecretKey' or 'AccessPassword' or 'OpenstackPasswork' or 'Password' field in 'identity' section")
	}

	//if config.Region, ok = metadata["Region"].(string); !ok {
	//	if config.Region, ok = ostorage["Region"].(string); !ok {
	//		config.Region, _ = compute["Region"].(string) // nolint
	//	}
	//	// FIXME: Wrong, this needs validation, but not ALL providers
	//	// if err := validateOVHObjectStorageRegionNaming("objectstorage", config.Region, config.AuthURL); err != nil {
	//	// 	return config, err
	//	// }
	//}

	key := "Region"
	found = false

	if val, ok := metadata[key].(string); ok {
		config.Region = val
		found = true
	} else if val, ok := ostorage[key].(string); ok {
		config.Region = val
		found = true
	} else if val, ok := compute[key].(string); ok {
		config.Region = val
		found = true
	}
	if !found {
		return config, fail.SyntaxError("missing setting 'Region' field in 'compute' section")
	}

	if client == "cloudferro" || client == "flexibleengine" {
		key = "AvailabilityZone"
		found = false

		if val, ok := metadata[key].(string); ok {
			config.AvailabilityZone = val
			found = true
		} else if val, ok := ostorage[key].(string); ok {
			config.AvailabilityZone = val
			found = true
		} else if val, ok := compute[key].(string); ok {
			config.AvailabilityZone = val
			found = true
		}
		if !found {
			return config, fail.SyntaxError("missing setting 'AvailabilityZone' field in 'compute' section")
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

	if config.BucketName, ok = metadata["MetadataBucketName"].(string); !ok {
		config.BucketName, _ = ostorage["MetadataBucketName"].(string) // nolint
	}

	if config.Suffix, ok = metadata["Suffix"].(string); !ok {
		config.Suffix, _ = ostorage["Suffix"].(string) // nolint
	}

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

func validateTenant(tenant map[string]interface{}) fail.Error {
	var (
		name     string
		client   string
		identity map[string]interface{}
		compute  map[string]interface{}
		//network  map[string]interface{}
		ostorage map[string]interface{}
		metadata map[string]interface{}
		val      string
		ok       bool
		found    bool
	)

	if val, ok = tenant["name"].(string); !ok {
		return fail.SyntaxError("Missing field 'name' for tenant")
	} else {
		name = val
	}

	providerKeysToCheck := []string{
		"provider",
		"Provider",
		"client",
		"Client",
	}

	found = false

	for _, key := range providerKeysToCheck {
		if val, ok = tenant[key].(string); ok {
			if !chekcClientName(val) {
				return fail.SyntaxError("Client value be 'aws, cloudferro, ebrc, flexibleengine, gcp, local, openstack, outscale, ovh'")
			}
			client = val
			found = true
			break
		}
	}

	if !found {
		return fail.SyntaxError("Missing field 'client' for tenant")
	}

	if identity, ok = tenant["identity"].(map[string]interface{}); !ok {
		return fail.SyntaxError("No section 'identity' found for tenant %s", name)
	}

	if compute, ok = tenant["compute"].(map[string]interface{}); !ok {
		return fail.SyntaxError("No section 'compute' found for tenant %s", name)
	}

	ostorage, _ = tenant["objectstorage"].(map[string]interface{})

	metadata, _ = tenant["metadata"].(map[string]interface{})

	if client != "gcp" {
		userKeysToCheck := []string{
			"AccessKey",
			"OpenstackID",
			"Username",
		}

		found = false

		for _, key := range userKeysToCheck {
			if _, ok := ostorage[key].(string); ok {
				found = true
				break
			} else if _, ok := identity[key].(string); ok {
				found = true
				break
			}
		}

		if !found {
			return fail.SyntaxError("missing setting 'AccessKey', 'OpenstackID' or 'Username' field in 'identity' section")
		}
	} else {
		if _, ok := identity["User"].(string); !ok {
			return fail.SyntaxError("missing setting 'User' field in 'identity' section")
		}
	}

	if client == "ovh" || client == "openstack" || client == "cloudferro" {
		key := "ApplicationKey"
		found = false

		if _, ok := ostorage[key].(string); ok {
			found = true
		} else if _, ok := identity[key].(string); ok {
			found = true
		}

		if !found {
			return fail.SyntaxError("missing setting 'ApplicationKey' field in 'identity' section")
		}
	}

	secretKeyToCheck := []string{
		"SecretKey",
		"AccessPassword",
		"OpenstackPassword",
		"Password",
	}

	found = false

	for _, key := range secretKeyToCheck {
		if _, ok := metadata[key].(string); ok {
			found = true
			break
		}
		if _, ok := ostorage[key].(string); ok {
			found = true
			break
		} else if _, ok := identity[key].(string); ok {
			found = true
			break
		}
	}

	if !found {
		return fail.SyntaxError("missing settings 'SecretKey' or 'AccessPassword' or 'OpenstackPassword' or 'Password' in 'identity' section")
	}

	if client == "cloudferro" || client == "flexibleengine" {
		key := "AvailabilityZone"
		found = false

		if _, ok := ostorage[key].(string); ok {
			found = true
		} else if _, ok := compute[key].(string); ok {
			found = true
		}

		if !found {
			return fail.SyntaxError("missing settings 'AvailabilityZone' in 'compute' section")
		}
	}

	if metadata != nil || ostorage != nil {
		var typeName string
		key := "Type"
		found = false

		if val, ok := metadata[key].(string); ok {
			typeName = val
			found = true
		} else if val, ok := ostorage[key].(string); ok {
			typeName = val
			found = true
		}

		if !found {
			return fail.SyntaxError("missing setting 'Type' in 'metadata' or 'objectstorage' section")
		} else {
			if !checkType(typeName) {
				return fail.SyntaxError("Type value must be 's3, swift, azure, gce'")
			}
		}
	}

	key := "Region"
	found = false

	if _, ok := metadata[key].(string); ok {
		found = true
	} else if _, ok := ostorage[key].(string); ok {
		found = true
	} else if _, ok := compute[key].(string); ok {
		found = true
	}
	if !found {
		return fail.SyntaxError("missing setting 'Region' field in 'compute' section")
	}

	return nil
}

func chekcClientName(client string) bool {
	clientList := []string{
		"aws",
		"cloudferro",
		"ebrc",
		"flexibleengine",
		"gcp",
		"local",
		"openstack",
		"outscale",
		"ovh",
	}

	for _, key := range clientList {
		if key == strings.ToLower(client) {
			return true
		}
	}

	return false
}

func checkType(typeName string) bool {
	typeList := []string{
		"s3",
		"swift",
		"azure",
		"gce",
		"google",
	}

	for _, key := range typeList {
		if key == strings.ToLower(typeName) {
			return true
		}
	}

	return false
}
