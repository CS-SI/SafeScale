/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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
	"fmt"
	"reflect"

	log "github.com/sirupsen/logrus"

	gc "github.com/gophercloud/gophercloud"
	gcos "github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/secgroups"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
)

// Stack contains the needs to operate on stack OpenStack
type Stack struct {
	Compute *gc.ServiceClient
	Network *gc.ServiceClient
	Volume  *gc.ServiceClient

	AuthOpts *AuthenticationOptions
	CfgOpts  *ConfigurationOptions

	SecurityGroup     *secgroups.SecurityGroup
	ProviderNetworkID string

	Driver *gc.ProviderClient
}

// New authenticates and returns a Stack pointer
func New(auth AuthenticationOptions, cfg ConfigurationOptions) (*Stack, error) {
	gcOpts := gc.AuthOptions{
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
	}

	// Openstack client
	driver, err := gcos.AuthenticatedClient(gcOpts)
	if err != nil {
		return nil, fmt.Errorf("%s", ErrorToString(err))
	}

	// Compute API
	compute, err := gcos.NewComputeV2(driver, gc.EndpointOpts{
		Region: auth.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("%s", ErrorToString(err))
	}

	// Network API
	network, err := gcos.NewNetworkV2(driver, gc.EndpointOpts{
		Region: auth.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("%s", ErrorToString(err))
	}
	nID, err := networks.IDFromName(network, cfg.ProviderNetwork)
	if err != nil {
		return nil, fmt.Errorf("%s", ErrorToString(err))
	}

	// Volume API
	volume, err := gcos.NewBlockStorageV1(driver, gc.EndpointOpts{
		Region: auth.Region,
	})

	s := stack{
		AuthOpts:          &auth,
		CfgOpts:           &cfg,
		driver:            driver,
		Compute:           compute,
		Network:           network,
		Volume:            volume,
		ObjectStorage:     objectstorage,
		ProviderNetworkID: nID,
	}

	err = s.initDefaultSecurityGroup()
	if err != nil {
		return nil, err
	}

	// Creates metadata Object Storage bucket/container
	if s.CfgOpts.MetadataBucketName == "" {
		s.CfgOpts.MetadataBucketName = BuildMetadataBucketName(auth.DomainName)
	}
	// err = metadata.InitializeBucket(&clt)
	// if err != nil {
	// 	return nil, err
	// }
	return &s, nil
}

// ErrorToString creates an error string from openstack api error
func ErrorToString(err error) string {
	switch e := err.(type) {
	case gc.ErrDefault401:
		return fmt.Sprintf("code: 401, reason: %s", string(e.Body[:]))
	case *gc.ErrDefault401:
		return fmt.Sprintf("code: 401, reason: %s", string(e.Body[:]))
	case gc.ErrDefault404:
		return fmt.Sprintf("code: 404, reason: %s", string(e.Body[:]))
	case *gc.ErrDefault404:
		return fmt.Sprintf("code: 404, reason: %s", string(e.Body[:]))
	case gc.ErrDefault500:
		return fmt.Sprintf("code: 500, reason: %s", string(e.Body[:]))
	case *gc.ErrDefault500:
		return fmt.Sprintf("code: 500, reason: %s", string(e.Body[:]))
	case gc.ErrUnexpectedResponseCode:
		return fmt.Sprintf("code: %d, reason: %s", e.Actual, string(e.Body[:]))
	case *gc.ErrUnexpectedResponseCode:
		return fmt.Sprintf("code: %d, reason: %s", e.Actual, string(e.Body[:]))
	default:
		log.Printf("ProviderErrorToString(%s)\n", reflect.TypeOf(err))
		return e.Error()
	}
}
