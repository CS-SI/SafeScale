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

package options

import (
	"regexp"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

// ConfigurationOptions are the stack configuration options
type ConfigurationOptions struct {
	// Name of the provider (external) network
	ProviderNetwork string

	// DNSList list of DNS
	DNSList []string

	// UseFloatingIP indicates if floating IP are used (optional)
	UseFloatingIP bool

	// UseLayer3Networking indicates if layer 3 networking features (router) can be used
	// if UseFloatingIP is true UseLayer3Networking must be true
	UseLayer3Networking bool

	UseNATService bool

	ProviderName string
	BuildSubnets bool

	// AutoHostNetworkInterfaces indicates if network interfaces are configured automatically by the provider or needs a post configuration
	AutoHostNetworkInterfaces bool

	// VolumeSpeeds map volume types with volume speeds
	VolumeSpeeds map[string]volumespeed.Enum

	// DefaultImage names the image to use when not specified by the user
	DefaultImage string

	// MetadataBucket contains the name of the Object Storage bucket that will store metadata
	MetadataBucket string

	// OperatorUsername contain the name of the safescale created user
	OperatorUsername string

	// DefaultSecurityGroupName contains the name of the default security group
	DefaultSecurityGroupName string

	DefaultNetworkName string // contains the name of the Networking/VPC that is used by default (corresponds to keywords 'DefaultNetworkName' or 'NetworkName' in tenant section 'compute')
	DefaultNetworkCIDR string // contains the CIDR of the default Networking/VPC

	// Customizations map[string]string

	// WhitelistTemplateRegexp contains the regexp string to white list host templates
	WhitelistTemplateRegexp *regexp.Regexp
	// BlacklistTemplateRegexp contains the regexp string to black list host templates
	BlacklistTemplateRegexp *regexp.Regexp
	// WhitelistImageRegexp contains the regexp string to white list images
	WhitelistImageRegexp *regexp.Regexp
	// BlacklistImageRegexp contains the regexp string to black list images
	BlacklistImageRegexp *regexp.Regexp

	MaxLifeTime int

	Timings *temporal.MutableTimings
}
