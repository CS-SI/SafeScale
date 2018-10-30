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

package huaweicloud

import "github.com/CS-SI/SafeScale/providers/api"

// AuthenticationOptions fields are the union of those recognized by each identity implementation and
// provider.
type AuthenticationOptions struct {
	IdentityEndpoint string
	Username         string
	Password         string
	DomainName       string
	ProjectID        string

	AllowReauth bool

	// TokenID allows users to authenticate (possibly as another user) with an
	// authentication token ID.
	TokenID string

	//Openstack region (data center) where the infrstructure will be created
	Region string

	//FloatingIPPool name of the floating IP pool
	//Necessary only if UseFloatingIP is true
	//FloatingIPPool string

	// Name of the VPC (Virtual Private Cloud)
	VPCName string
	// CIDR if the VPC
	VPCCIDR string

	// Identifier for S3 object storage use
	S3AccessKeyID string
	// Password of the previous identifier
	S3AccessKeyPassword string
}

// GetAuthOpts returns the auth options
func (s *Stack) GetAuthOpts() (api.Config, error) {
	cfg := provider.ConfigMap{}

	cfg.Set("DomainName", client.Opts.DomainName)
	cfg.Set("Login", client.Opts.Username)
	cfg.Set("Password", client.Opts.Password)
	cfg.Set("AuthUrl", client.Opts.IdentityEndpoint)
	cfg.Set("Region", client.Opts.Region)
	cfg.Set("VPCName", client.Opts.VPCName)

	return cfg, nil
}

// GetCfgOpts return configuration parameters
func (s *Stack) GetCfgOpts() (api.Config, error) {
	return s.osclt.GetCfgOpts()
}
