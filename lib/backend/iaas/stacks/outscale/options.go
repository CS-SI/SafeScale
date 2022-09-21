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

package outscale

import (
	stackoptions "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/options"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// ConfigurationOptions ...
func (s stack) ConfigurationOptions() (stackoptions.Configuration, fail.Error) {
	out := stackoptions.Configuration{
		ProviderNetwork:           "",
		DNSServers:                s.Options.Compute.DNSList,
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
		DefaultImage:             s.Options.Compute.DefaultImage,
		MetadataBucketName:       s.Options.Metadata.Bucket,
		OperatorUsername:         s.Options.Compute.OperatorUsername,
		DefaultSecurityGroupName: "",
		DefaultNetworkName:       "",
		DefaultNetworkCIDR:       "",
		WhitelistTemplateRegexp:  nil,
		BlacklistTemplateRegexp:  nil,
		WhitelistImageRegexp:     nil,
		BlacklistImageRegexp:     nil,
		MaxLifeTime:              0,
		Timings:                  s.Options.Timings,
		Safe:                     s.Options.Compute.Safe,
	}
	return out, nil
}

// AuthenticationOptions ...
func (s stack) AuthenticationOptions() (stackoptions.Authentication, fail.Error) {
	return stackoptions.Authentication{
		IdentityEndpoint: s.Options.Compute.URL,
		Username:         "",
		UserID:           "",
		AccessKeyID:      s.Options.Identity.AccessKey,
		Password:         "",
		APIKey:           "",
		SecretAccessKey:  s.Options.Identity.SecretKey,
		DomainID:         "",
		DomainName:       "",
		TenantID:         "",
		TenantName:       "",
		ProjectName:      "",
		ProjectID:        "",
		AllowReauth:      false,
		TokenID:          "",
		Region:           s.Options.Compute.Region,
		AvailabilityZone: s.Options.Compute.Subregion,
		FloatingIPPool:   "",
		// AK:               "",
		// AS:               "",
		// CK:               "",
	}, nil
}
