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

package outscale

import (
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/options"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// ConfigurationOptions ...
func (instance *stack) ConfigurationOptions() (iaasoptions.Configuration, fail.Error) {
	out := iaasoptions.Configuration{
		ProviderNetwork:           "",
		DNSServers:                instance.Options.Compute.DNSList,
		UseFloatingIP:             false,
		UseLayer3Networking:       false,
		UseNATService:             false,
		ProviderName:              "",
		BuildSubnets:              false,
		AutoHostNetworkInterfaces: true,
		VolumeSpeeds: map[string]volumespeed.Enum{
			"standard": volumespeed.Cold,
			"gp2":      volumespeed.Hdd,
			"io1":      volumespeed.Ssd,
		},
		DefaultImage:             instance.Options.Compute.DefaultImage,
		MetadataBucketName:       instance.Options.Metadata.Bucket,
		OperatorUsername:         instance.Options.Compute.OperatorUsername,
		DefaultSecurityGroupName: "",
		DefaultNetworkName:       "",
		DefaultNetworkCIDR:       "",
		WhitelistTemplateRegexp:  nil,
		BlacklistTemplateRegexp:  nil,
		WhitelistImageRegexp:     nil,
		BlacklistImageRegexp:     nil,
		MaxLifeTime:              0,
		Timings:                  instance.Options.Timings,
		Safe:                     instance.Options.Compute.Safe,
	}
	return out, nil
}

// AuthenticationOptions ...
func (instance *stack) AuthenticationOptions() (iaasoptions.Authentication, fail.Error) {
	return iaasoptions.Authentication{
		IdentityEndpoint: instance.Options.Compute.URL,
		Username:         "",
		UserID:           "",
		AccessKeyID:      instance.Options.Identity.AccessKey,
		Password:         "",
		APIKey:           "",
		SecretAccessKey:  instance.Options.Identity.SecretKey,
		DomainID:         "",
		DomainName:       "",
		TenantID:         "",
		TenantName:       "",
		ProjectName:      "",
		ProjectID:        "",
		AllowReauth:      false,
		TokenID:          "",
		Region:           instance.Options.Compute.Region,
		AvailabilityZone: instance.Options.Compute.Subregion,
		FloatingIPPool:   "",
		// AK:               "",
		// AS:               "",
		// CK:               "",
	}, nil
}
