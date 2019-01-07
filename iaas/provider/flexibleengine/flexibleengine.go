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

package flexibleengine

import (
	"fmt"

	"github.com/CS-SI/SafeScale/iaas/provider/api"
	"github.com/CS-SI/SafeScale/iaas/model/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/iaas/stack/huaweicloud"

	// official AWS API

	awscreds "github.com/aws/aws-sdk-go/aws/credentials"
)

const (
	defaultUser string = "cloud"

	authURL string = "https://iam.%s.prod-cloud-ocb.orange-business.com"
)

//VPL:BEGIN
// aws provider isn't finished yet, copying the necessary here meanwhile...

// AuthOpts AWS credentials
type awsAuthOpts struct {
	// AWS Access key ID
	AccessKeyID string

	// AWS Secret Access Key
	SecretAccessKey string
	// The region to send requests to. This parameter is required and must
	// be configured globally or on a per-client basis unless otherwise
	// noted. A full list of regions is found in the "Regions and Endpoints"
	// document.
	//
	// @see http://docs.aws.amazon.com/general/latest/gr/rande.html
	//   AWS Regions and Endpoints
	Region string
	//Config *Config
}

// Retrieve returns nil if it successfully retrieved the value.
// Error is returned if the value were not obtainable, or empty.
func (o awsAuthOpts) Retrieve() (awscreds.Value, error) {
	return awscreds.Value{
		AccessKeyID:     o.AccessKeyID,
		SecretAccessKey: o.SecretAccessKey,
		ProviderName:    "internal",
	}, nil
}

// IsExpired returns if the credentials are no longer valid, and need
// to be retrieved.
func (o awsAuthOpts) IsExpired() bool {
	return false
}

//VPL:END

// // AuthenticatedClient returns an authenticated client
// func AuthenticatedClient(opts AuthOptions, cfg openstack.CfgOptions) (*Client, error) {
// 	// gophercloud doesn't know how to determine Auth API version to use for FlexibleEngine.
// 	// So we help him to.
// 	if opts.IdentityEndpoint == "" {
// 		opts.IdentityEndpoint = fmt.Sprintf(authURL, opts.Region)
// 	}
// 	provider, err := gcos.NewClient(opts.IdentityEndpoint)
// 	if err != nil {
// 		return nil, err
// 	}
// 	authOptions := tokens.AuthOptions{
// 		IdentityEndpoint: opts.IdentityEndpoint,
// 		Username:         opts.Username,
// 		Password:         opts.Password,
// 		DomainName:       opts.DomainName,
// 		AllowReauth:      opts.AllowReauth,
// 		Scope: tokens.Scope{
// 			ProjectName: opts.Region,
// 			DomainName:  opts.DomainName,
// 		},
// 	}
// 	err = gcos.AuthenticateV3(provider, &authOptions, gc.EndpointOpts{})
// 	if err != nil {
// 		return nil, fmt.Errorf("%s", openstack.ProviderErrorToString(err))
// 	}

// 	// Identity API
// 	identity, err := gcos.NewIdentityV3(provider, gc.EndpointOpts{})
// 	if err != nil {
// 		return nil, fmt.Errorf("%s", openstack.ProviderErrorToString(err))
// 	}

// 	// Recover Project ID of region
// 	listOpts := projects.ListOpts{
// 		Enabled: gc.Enabled,
// 		Name:    opts.Region,
// 	}
// 	allPages, err := projects.List(identity, listOpts).AllPages()
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to query project ID corresponding to region '%s': %s", opts.Region, openstack.ProviderErrorToString(err))
// 	}
// 	allProjects, err := projects.ExtractProjects(allPages)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to load project ID corresponding to region '%s': %s", opts.Region, openstack.ProviderErrorToString(err))
// 	}
// 	if len(allProjects) > 0 {
// 		opts.ProjectID = allProjects[0].ID
// 	} else {
// 		return nil, fmt.Errorf("failed to found project ID corresponding to region '%s': %s", opts.Region, openstack.ProviderErrorToString(err))
// 	}

// 	// Compute API
// 	compute, err := gcos.NewComputeV2(provider, gc.EndpointOpts{})
// 	if err != nil {
// 		return nil, fmt.Errorf("%s", openstack.ProviderErrorToString(err))
// 	}

// 	// Network API
// 	network, err := gcos.NewNetworkV2(provider, gc.EndpointOpts{
// 		Type:   "network",
// 		Region: opts.Region,
// 	})
// 	if err != nil {
// 		return nil, fmt.Errorf("%s", openstack.ProviderErrorToString(err))
// 	}

// 	// Storage API
// 	blockStorage, err := gcos.NewBlockStorageV2(provider, gc.EndpointOpts{
// 		Type:   "volumev2",
// 		Region: opts.Region,
// 	})
// 	if err != nil {
// 		return nil, fmt.Errorf("%s", openstack.ProviderErrorToString(err))
// 	}

// 	// Need to get Endpoint URL for ObjectStorage, that will be used with AWS S3 protocol
// 	objectStorage, err := gcos.NewObjectStorageV1(provider, gc.EndpointOpts{
// 		Type:   "object",
// 		Region: opts.Region,
// 	})
// 	if err != nil {
// 		return nil, fmt.Errorf("%s", openstack.ProviderErrorToString(err))
// 	}
// 	// Fix URL of ObjectStorage for FlexibleEngine...
// 	u, _ := url.Parse(objectStorage.Endpoint)
// 	endpoint := u.Scheme + "://" + u.Hostname() + "/"
// 	// FlexibleEngine uses a protocol compatible with S3, so we need to get aws.Session instance
// 	authOpts := awsAuthOpts{
// 		AccessKeyID:     opts.S3AccessKeyID,
// 		SecretAccessKey: opts.S3AccessKeyPassword,
// 		Region:          opts.Region,
// 	}
// 	awsSession, err := awssession.NewSession(&aws.Config{
// 		Region:      aws.String(opts.Region),
// 		Credentials: awscreds.NewCredentials(authOpts),
// 		Endpoint:    &endpoint,
// 	})
// 	if err != nil {
// 		return nil, err
// 	}
// 	openstackClient := openstack.Client{
// 		Opts: &openstack.AuthOptions{
// 			IdentityEndpoint: opts.IdentityEndpoint,
// 			Username:         opts.Username,
// 			Password:         opts.Password,
// 			DomainName:       opts.DomainName,
// 			AllowReauth:      opts.AllowReauth,
// 			Region:           opts.Region,
// 		},
// 		Cfg: &openstack.CfgOptions{
// 			DNSList:             cfg.DNSList,
// 			UseFloatingIP:       true,
// 			UseLayer3Networking: cfg.UseLayer3Networking,
// 			VolumeSpeeds:        cfg.VolumeSpeeds,
// 			S3Protocol:          "s3",
// 			MetadataBucketName:  api.BuildMetadataBucketName(opts.DomainName),
// 		},
// 		Provider: provider,
// 		Compute:  compute,
// 		Network:  network,
// 		Volume:   blockStorage,
// 		//Container:   objectStorage,
// 	}

// 	clt := Client{
// 		Opts:      &opts,
// 		osclt:     &openstackClient,
// 		Identity:  identity,
// 		S3Session: awsSession,
// 	}

// 	// Initializes the VPC
// 	err = clt.initVPC()
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Initializes the default security group
// 	err = clt.initDefaultSecurityGroup()
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Creates metadata Object Storage container
// 	err = metadata.InitializeBucket(&clt)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return &clt, nil
// }

// FlexibleEngine allows to use FlexibleEngine provider
type FlexibleEngine struct {
	AuthOpts AuthenticationOptions
	CfgOpts  ConfigurationOptions
	stack    *huaweicloud.Stack
}

// Build initializes a new FlexibleEngine instance from parameters
func (p *FlexibleEngine) Build(params map[string]interface{}) (api.Provider, error) {
	Username, _ := params["Username"].(string)
	Password, _ := params["Password"].(string)
	DomainName, _ := params["DomainName"].(string)
	ProjectID, _ := params["ProjectID"].(string)
	VPCName, _ := params["VPCName"].(string)
	VPCCIDR, _ := params["VPCCIDR"].(string)
	Region, _ := params["Region"].(string)
	S3AccessKeyID, _ := params["S3AccessKeyID"].(string)
	S3AccessKeyPassword, _ := params["S3AccessKeyPassword"].(string)
	if IdentityEndpoint == "" {
		IdentityEndpoint = fmt.Sprintf(authUrl, Region)
	}

	newP := FlexibleEngine{
		AuthOpts: AuthenticationOptions{
			IdentityEndpoint:    IdentityEndpoint,
			Username:            Username,
			Password:            Password,
			DomainName:          DomainName,
			ProjectID:           ProjectID,
			Region:              Region,
			AllowReauth:         true,
			VPCName:             VPCName,
			VPCCIDR:             VPCCIDR,
			S3AccessKeyID:       S3AccessKeyID,
			S3AccessKeyPassword: S3AccessKeyPassword,
		},
		CfgOptions: ConfigurationOptions{
			DNSList:             []string{"100.125.0.41", "100.126.0.41"},
			UseFloatingIP:       true,
			UseLayer3Networking: false,
			VolumeSpeeds: map[string]VolumeSpeed.Enum{
				"SATA": VolumeSpeed.COLD,
				"SSD":  VolumeSpeed.SSD,
			},
		},
	}
	newP.stack, err := huaweicloud.New(p.AuthOpts, p.CfgOpts)
	if err != nil {
		return nil, err
	}

	return &newP, nil
}

// init registers the flexibleengine provider
func init() {
	provider.Register("flexibleengine", &FlexibleEngine{})
}
