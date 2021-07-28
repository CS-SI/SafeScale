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

package openstack

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	secgroups "github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// ProviderErrorToString creates an error string from openstack api error
func ProviderErrorToString(err error) string {
	if err == nil {
		return ""
	}
	switch e := err.(type) {
	case gophercloud.ErrDefault401:
		return fmt.Sprintf("code: 401, reason: %s", string(e.Body))
	case *gophercloud.ErrDefault401:
		return fmt.Sprintf("code: 401, reason: %s", string(e.Body))
	case gophercloud.ErrDefault404:
		return fmt.Sprintf("code: 404, reason: %s", string(e.Body))
	case *gophercloud.ErrDefault404:
		return fmt.Sprintf("code: 404, reason: %s", string(e.Body))
	case gophercloud.ErrDefault500:
		return fmt.Sprintf("code: 500, reason: %s", string(e.Body))
	case *gophercloud.ErrDefault500:
		return fmt.Sprintf("code: 500, reason: %s", string(e.Body))
	case gophercloud.ErrUnexpectedResponseCode:
		return fmt.Sprintf("code: %d, reason: %s", e.Actual, string(e.Body))
	case *gophercloud.ErrUnexpectedResponseCode:
		return fmt.Sprintf("code: %d, reason: %s", e.Actual, string(e.Body))
	default:
		logrus.Debugf(
			"Error code not yet handled specifically: ProviderErrorToString(%s, %+v)\n", reflect.TypeOf(err).String(),
			err,
		)
		return err.Error()
	}
}

// TranslateError translates gophercloud or openstack error to SafeScale error
func TranslateError(err error) error {
	switch e := err.(type) {
	case gophercloud.ErrDefault401:
		return fail.UnauthorizedError(string(e.Body))
	case *gophercloud.ErrDefault401:
		return fail.UnauthorizedError(string(e.Body))
	case gophercloud.ErrDefault403:
		return fail.ForbiddenError(string(e.Body))
	case *gophercloud.ErrDefault403:
		return fail.ForbiddenError(string(e.Body))
	case gophercloud.ErrDefault404:
		return fail.NotFoundError(string(e.Body))
	case *gophercloud.ErrDefault404:
		return fail.NotFoundError(string(e.Body))
	case gophercloud.ErrDefault429:
		return fail.OverloadError(string(e.Body))
	case *gophercloud.ErrDefault429:
		return fail.OverloadError(string(e.Body))
	case gophercloud.ErrDefault500:
		return fail.InvalidRequestError(string(e.Body))
	case *gophercloud.ErrDefault500:
		return fail.InvalidRequestError(string(e.Body))
	case gophercloud.ErrUnexpectedResponseCode:
		return fail.Errorf(
			fmt.Sprintf("unexpected response code: code: %d, reason: %s", e.Actual, string(e.Body)), err,
		)
	case *gophercloud.ErrUnexpectedResponseCode:
		return fail.Errorf(
			fmt.Sprintf("unexpected response code: code: %d, reason: %s", e.Actual, string(e.Body)), err,
		)
	default:
		logrus.Debugf("Unhandled error (%s) received from provider: %s", reflect.TypeOf(err).String(), err.Error())
		return fail.Errorf(fmt.Sprintf("unhandled error received from provider: %s", err.Error()), err)
	}
}

// ParseNeutronError parses neutron json error and returns fields
func ParseNeutronError(neutronError string) map[string]string {
	startIdx := strings.Index(neutronError, "{\"NeutronError\":")
	jsonError := strings.Trim(neutronError[startIdx:], " ")
	unjsoned := map[string]map[string]interface{}{}
	err := json.Unmarshal([]byte(jsonError), &unjsoned)
	if err != nil {
		logrus.Debugf(err.Error())
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
) (*Stack, fail.Error) {

	if auth.DomainName == "" && auth.DomainID == "" {
		auth.DomainName = "Default"
	}
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
		return nil, fail.Errorf(fmt.Sprintf("%s", ProviderErrorToString(err)), err)
	}

	// Compute API
	switch s.versions["compute"] {
	case "v2":
		s.ComputeClient, err = openstack.NewComputeV2(
			s.Driver, gophercloud.EndpointOpts{
				Region: auth.Region,
			},
		)
	default:
		return nil, fail.Errorf(
			fmt.Sprintf(
				"unmanaged Openstack service 'compute' version '%s'", serviceVersions["compute"],
			), nil,
		)
	}
	if err != nil {
		return nil, fail.Errorf(fmt.Sprintf("%s", ProviderErrorToString(err)), err)
	}

	// Network API
	switch s.versions["network"] {
	case "v2":
		s.NetworkClient, err = openstack.NewNetworkV2(
			s.Driver, gophercloud.EndpointOpts{
				Region: auth.Region,
			},
		)
	default:
		return nil, fail.Errorf(
			fmt.Sprintf(
				"unmanaged Openstack service 'network' version '%s'", s.versions["network"],
			), nil,
		)
	}
	if err != nil {
		return nil, fail.Errorf(fmt.Sprintf("%s", ProviderErrorToString(err)), err)
	}

	// Volume API
	switch s.versions["volume"] {
	case "v1":
		s.VolumeClient, err = openstack.NewBlockStorageV1(
			s.Driver, gophercloud.EndpointOpts{
				Region: auth.Region,
			},
		)
	case "v2":
		s.VolumeClient, err = openstack.NewBlockStorageV2(
			s.Driver, gophercloud.EndpointOpts{
				Region: auth.Region,
			},
		)
	default:
		return nil, fail.Errorf(
			fmt.Sprintf("unmanaged service 'volumes' version '%s'", serviceVersions["volumes"]), nil,
		)
	}
	if err != nil {
		return nil, fail.Errorf(fmt.Sprintf("%s", ProviderErrorToString(err)), err)
	}

	// Get provider network ID from network service
	if cfg.ProviderNetwork != "" {
		s.ProviderNetworkID, err = IDFromName(s.NetworkClient, cfg.ProviderNetwork)
		if err != nil {
			return nil, fail.Errorf(fmt.Sprintf("%s", ProviderErrorToString(err)), err)
		}
	}

	return &s, nil
}

func IDFromName(client *gophercloud.ServiceClient, name string) (string, error) {
	count := 0
	id := ""

	listOpts := networks.ListOpts{
		Name: name,
	}

	pages, err := networks.List(client, listOpts).AllPages()
	if err != nil {
		return "", err
	}

	all, err := networks.ExtractNetworks(pages)
	if err != nil {
		return "", err
	}

	for _, s := range all {
		if s.Name == name {
			count++
			id = s.ID
		}
	}

	switch count {
	case 0:
		return "", gophercloud.ErrResourceNotFound{Name: name, ResourceType: "network"}
	case 1:
		return id, nil
	default:
		return "", gophercloud.ErrMultipleResourcesFound{Name: name, Count: count, ResourceType: "network"}
	}
}
