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

package openstack

import (
	"encoding/json"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	secgroups "github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
)

// ProviderErrorToString creates an error string from openstack api error
func ProviderErrorToString(err error) string {
	switch e := err.(type) {
	case gophercloud.ErrDefault401:
		return fmt.Sprintf("code: 401, reason: %s", string(e.Body[:]))
	case *gophercloud.ErrDefault401:
		return fmt.Sprintf("code: 401, reason: %s", string(e.Body[:]))
	case gophercloud.ErrDefault404:
		return fmt.Sprintf("code: 404, reason: %s", string(e.Body[:]))
	case *gophercloud.ErrDefault404:
		return fmt.Sprintf("code: 404, reason: %s", string(e.Body[:]))
	case gophercloud.ErrDefault500:
		return fmt.Sprintf("code: 500, reason: %s", string(e.Body[:]))
	case *gophercloud.ErrDefault500:
		return fmt.Sprintf("code: 500, reason: %s", string(e.Body[:]))
	case gophercloud.ErrUnexpectedResponseCode:
		return fmt.Sprintf("code: %d, reason: %s", e.Actual, string(e.Body[:]))
	case *gophercloud.ErrUnexpectedResponseCode:
		return fmt.Sprintf("code: %d, reason: %s", e.Actual, string(e.Body[:]))
	default:
		// logrus.Debugf("Error code not yet handled specifically: ProviderErrorToString(%+v)\n", err)
		return e.Error()
	}
}

// ParseNeutronError parses neutron json error and returns fields
func ParseNeutronError(neutronError string) map[string]string {
	startIdx := strings.Index(neutronError, "{\"NeutronError\":")
	jsonError := strings.Trim(neutronError[startIdx:], " ")
	unjsoned := map[string]map[string]interface{}{}
	err := json.Unmarshal([]byte(jsonError), &unjsoned)
	if err != nil {
		log.Debugf(err.Error())
		return nil
	}
	if content, ok := unjsoned["NeutronError"]; ok {
		retval := map[string]string{
			"message": "",
			"type":    "",
			"code":    "",
			"detail":  "",
		}
		if field, ok := content["message"].(string); ok {
			retval["message"] = field
		}
		if field, ok := content["type"].(string); ok {
			retval["type"] = field
		}
		if field, ok := content["code"].(string); ok {
			retval["code"] = field
		}
		if field, ok := content["detail"].(string); ok {
			retval["detail"] = field
		}

		return retval
	}
	return nil
}

// Stack contains the needs to operate on stack OpenStack
type Stack struct {
	ComputeClient *gophercloud.ServiceClient
	NetworkClient *gophercloud.ServiceClient
	VolumeClient  *gophercloud.ServiceClient
	Driver        *gophercloud.ProviderClient

	authOpts stacks.AuthenticationOptions
	cfgOpts  stacks.ConfigurationOptions

	// DefaultSecurityGroupName is the name of the default security groups
	DefaultSecurityGroupName string
	// DefaultSecurityGroupDescription contains a description for the default security groups
	DefaultSecurityGroupDescription string
	// SecurityGroup is an instance of the default security group
	SecurityGroup     *secgroups.SecGroup
	ProviderNetworkID string

	// versions contains the last version supported for each service
	versions map[string]string

	// selectedAvailabilityZone contains the last selected availability zone chosen
	selectedAvailabilityZone string
}

// New authenticates and returns a Stack pointer
func New(
	auth stacks.AuthenticationOptions,
	authScope *gophercloud.AuthScope,
	cfg stacks.ConfigurationOptions,
	serviceVersions map[string]string,
) (*Stack, error) {

	gcOpts := gophercloud.AuthOptions{
		IdentityEndpoint: auth.IdentityEndpoint,
		Username:         auth.Username,
		UserID:           auth.UserID,
		Password:         auth.Password,
		DomainID:         auth.DomainID,
		DomainName:       auth.DomainName,
		TenantID:         auth.TenantID,
		TenantName:       auth.TenantName,
		AllowReauth:      auth.AllowReauth,
		TokenID:          auth.TokenID,
		Scope:            authScope,
	}

	s := Stack{
		authOpts: auth,
		cfgOpts:  cfg,
	}

	s.versions = map[string]string{
		"compute": "v2",
		"volume":  "v2",
		"network": "v2",
	}
	for k, v := range serviceVersions {
		s.versions[k] = v
	}

	var err error

	// Openstack client
	s.Driver, err = openstack.AuthenticatedClient(gcOpts)
	if err != nil {
		return nil, fmt.Errorf("%s", ProviderErrorToString(err))
	}

	// Compute API
	switch s.versions["compute"] {
	case "v2":
		s.ComputeClient, err = openstack.NewComputeV2(s.Driver, gophercloud.EndpointOpts{
			Region: auth.Region,
		})
	default:
		return nil, fmt.Errorf("unmanaged Openstack service 'compute' version '%s'", serviceVersions["compute"])

	}
	if err != nil {
		return nil, fmt.Errorf("%s", ProviderErrorToString(err))
	}

	// Network API
	switch s.versions["network"] {
	case "v2":
		s.NetworkClient, err = openstack.NewNetworkV2(s.Driver, gophercloud.EndpointOpts{
			Region: auth.Region,
		})
	default:
		return nil, fmt.Errorf("unmanaged Openstack service 'network' version '%s'", s.versions["network"])
	}
	if err != nil {
		return nil, fmt.Errorf("%s", ProviderErrorToString(err))
	}

	// Volume API
	switch s.versions["volume"] {
	case "v1":
		s.VolumeClient, err = openstack.NewBlockStorageV1(s.Driver, gophercloud.EndpointOpts{
			Region: auth.Region,
		})
	case "v2":
		s.VolumeClient, err = openstack.NewBlockStorageV2(s.Driver, gophercloud.EndpointOpts{
			Region: auth.Region,
		})
	default:
		return nil, fmt.Errorf("unmanaged service 'volumes' version '%s'", serviceVersions["volumes"])
	}
	if err != nil {
		return nil, fmt.Errorf("%s", ProviderErrorToString(err))
	}

	// Get provider network ID from network service
	if cfg.ProviderNetwork != "" {
		s.ProviderNetworkID, err = networks.IDFromName(s.NetworkClient, cfg.ProviderNetwork)
		if err != nil {
			return nil, fmt.Errorf("%s", ProviderErrorToString(err))
		}
	}

	return &s, nil
}
