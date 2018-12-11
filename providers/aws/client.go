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

package aws

import (
	"fmt"
	"text/template"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/pricing"

	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/VolumeSpeed"
)

// //Config AWS configurations
// type Config struct {
// 	ImageOwners    []string
// 	DefaultNetwork string
// }

// AuthOpts AWS credentials
type AuthOpts struct {
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
func (o AuthOpts) Retrieve() (credentials.Value, error) {
	return credentials.Value{
		AccessKeyID:     o.AccessKeyID,
		SecretAccessKey: o.SecretAccessKey,
		ProviderName:    "internal",
	}, nil
}

// IsExpired returns if the credentials are no longer valid, and need
// to be retrieved.
func (o AuthOpts) IsExpired() bool {
	return false
}

// AuthenticatedClient returns an authenticated client
func AuthenticatedClient(opts AuthOpts) (*Client, error) {
	s, err := session.NewSession(&aws.Config{
		Region:      aws.String(opts.Region),
		Credentials: credentials.NewCredentials(opts),
	})
	if err != nil {
		return nil, err
	}
	sPricing, err := session.NewSession(&aws.Config{
		Region:      aws.String("us-east-1"),
		Credentials: credentials.NewCredentials(opts),
	})
	if err != nil {
		return nil, err
	}
	c := Client{
		Session:  s,
		EC2:      ec2.New(s),
		Pricing:  pricing.New(sPricing),
		AuthOpts: opts,
	}

	return &c, nil
}

func wrapError(msg string, err error) error {
	if err == nil {
		return nil
	}
	if aerr, ok := err.(awserr.Error); ok {
		return fmt.Errorf("%s: cause by %s", msg, aerr.Message())
	}
	return err
}

// Build build a new Client from configuration parameter
func (c *Client) Build(params map[string]interface{}) (api.ClientAPI, error) {
	tenantName, _ := params["name"].(string)
	_ = tenantName

	identity, _ := params["identity"].(map[string]interface{})
	compute, _ := params["compute"].(map[string]interface{})
	network, _ := params["network"].(map[string]interface{})
	_ = network

	accessKeyID, _ := identity["AccessKeyID"].(string)
	secretAccessKey, _ := identity["SecretAccessKey"].(string)
	identityEndpoint, _ := identity["EndPoint"].(string)
	_ = identityEndpoint

	region, _ := compute["Region"].(string)
	defaultImage, _ := compute["DefaultImage"]
	_ = defaultImage

	return AuthenticatedClient(
		AuthOpts{
			AccessKeyID:     accessKeyID,
			SecretAccessKey: secretAccessKey,
			Region:          region,
		},
	)

}

// CfgOptions configuration options
type CfgOptions struct {
	// Name of the provider (external) network
	ProviderNetwork string
	// DNSList list of DNS
	DNSList []string
	// UseFloatingIP indicates if floating IP are used (optional)
	UseFloatingIP bool
	// UseLayer3Networking indicates if layer 3 networking features (router) can be used
	// if UseFloatingIP is true UseLayer3Networking must be true
	UseLayer3Networking bool
	// AutoHostNetworkInterfaces indicates if network interfaces are configured automatically by the provider or needs a post configuration
	AutoHostNetworkInterfaces bool
	// VolumeSpeeds map volume types with volume speeds
	VolumeSpeeds map[string]VolumeSpeed.Enum
	// // ObjectStorageType type of Object Storage (ex: swift or s3)
	// ObjectStorageType string
	// MetadataBucket contains the name of the bucket storing metadata
	MetadataBucket string
	DefaultImage   string
}

// Client a AWS provider client
type Client struct {
	Session     *session.Session
	EC2         *ec2.EC2
	Pricing     *pricing.Pricing
	AuthOpts    AuthOpts
	UserDataTpl *template.Template
	//ImageOwners []string

	Cfg *CfgOptions
}

func (c *Client) createSecurityGroup(vpcID string, name string) (string, error) {
	out, err := c.EC2.CreateSecurityGroup(&ec2.CreateSecurityGroupInput{
		GroupName: aws.String(name),
		VpcId:     aws.String(vpcID),
	})
	if err != nil {
		return "", err
	}
	_, err = c.EC2.AuthorizeSecurityGroupEgress(&ec2.AuthorizeSecurityGroupEgressInput{
		IpPermissions: []*ec2.IpPermission{
			&ec2.IpPermission{
				IpProtocol: aws.String("-1"),
			},
		},
	})
	if err != nil {
		return "", err
	}

	_, err = c.EC2.AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
		IpPermissions: []*ec2.IpPermission{
			&ec2.IpPermission{
				IpProtocol: aws.String("-1"),
			},
		},
	})
	if err != nil {
		return "", err
	}
	return *out.GroupId, nil
}

// GetAuthOpts ...
func (c *Client) GetAuthOpts() (model.Config, error) {
	cfg := model.ConfigMap{}
	return cfg, nil
}

// GetCfgOpts return configuration parameters
func (c *Client) GetCfgOpts() (model.Config, error) {
	cfg := model.ConfigMap{}

	cfg.Set("DNSList", c.Cfg.DNSList)
	// cfg.Set("S3Protocol", c.Cfg.S3Protocol)
	cfg.Set("AutoHostNetworkInterfaces", c.Cfg.AutoHostNetworkInterfaces)
	cfg.Set("UseLayer3Networking", c.Cfg.UseLayer3Networking)

	return cfg, nil
}
