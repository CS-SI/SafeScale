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

	gc "github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/secgroups"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/metadata"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/VolumeSpeed"
	"net/http"
)

// AuthOptions fields are the union of those recognized by each identity implementation and
// provider.
type AuthOptions struct {
	// IdentityEndpoint specifies the HTTP endpoint that is required to work with
	// the Identity API of the appropriate version. While it's ultimately needed by
	// all of the identity services, it will often be populated by a provider-level
	// function.
	IdentityEndpoint string

	// Username is required if using Identity V2 API. Consult with your provider's
	// control panel to discover your account's username. In Identity V3, either
	// UserID or a combination of Username and DomainID or DomainName are needed.
	Username, UserID string

	// Exactly one of Password or APIKey is required for the Identity V2 and V3
	// APIs. Consult with your provider's control panel to discover your account's
	// preferred method of authentication.
	Password, APIKey string

	// At most one of DomainID and DomainName must be provided if using Username
	// with Identity V3. Otherwise, either are optional.
	DomainID, DomainName string

	// The TenantID and TenantName fields are optional for the Identity V2 API.
	// Some providers allow you to specify a TenantName instead of the TenantId.
	// Some require both. Your provider's authentication policies will determine
	// how these fields influence authentication.
	TenantID, TenantName string

	// AllowReauth should be set to true if you grant permission for Gophercloud to
	// cache your credentials in memory, and to allow Gophercloud to attempt to
	// re-authenticate automatically if/when your token expires.  If you set it to
	// false, it will not cache these settings, but re-authentication will not be
	// possible. This setting defaults to false.
	//
	// NOTE: The reauth function will try to re-authenticate endlessly if left unchecked.
	// The way to limit the number of attempts is to provide a custom HTTP client to the provider client
	// and provide a transport that implements the RoundTripper interface and stores the number of failed retries.
	// For an example of this, see here: https://github.com/gophercloud/rack/blob/1.0.0/auth/clients.go#L311
	AllowReauth bool

	// TokenID allows users to authenticate (possibly as another user) with an
	// authentication token ID.
	TokenID string

	//Openstack region (data center) where the infrstructure will be created
	Region string

	//FloatingIPPool name of the floating IP pool
	//Necessary only if UseFloatingIP is true
	FloatingIPPool string
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

// ProviderErrorToString creates an error string from openstack api error
func ProviderErrorToString(err error) string {
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
		// logrus.Debugf("Error code not yet handled specifically: ProviderErrorToString(%+v)\n", err)
		return e.Error()
	}
}

func verifyServiceEndpoint(service string) (bool, error) {
	var serviceGone error = nil

	resp, err := http.Get(service)
	if (err == nil) && (resp.StatusCode != 200) && (resp.StatusCode != 401) && (resp.StatusCode != 403) {
		serviceGone = fmt.Errorf("%d Http Error: [%s]", resp.StatusCode, service)
		return false, serviceGone
	}

	return true, nil
}

func VerifyEndpoints(service *Client) (bool, error) {
	if service == nil {
		panic("Nil service !!")
	}

	ok := true

	pok, err := verifyServiceEndpoint(service.Compute.Endpoint)
	if err != nil {
		return false, err
	}
	ok = ok && pok

	pok, err = verifyServiceEndpoint(service.Network.Endpoint)
	if err != nil {
		return false, err
	}
	ok = ok && pok

	pok, err = verifyServiceEndpoint(service.Volume.Endpoint)
	if err != nil {
		return false, err
	}
	ok = ok && pok

	pok, err = verifyServiceEndpoint(service.Container.Endpoint)
	if err != nil {
		return false, err
	}
	ok = ok && pok

	return ok, nil
}

// AuthenticatedClient returns an authenticated client
func AuthenticatedClient(opts AuthOptions, cfg CfgOptions) (*Client, error) {
	gcOpts := gc.AuthOptions{
		IdentityEndpoint: opts.IdentityEndpoint,
		Username:         opts.Username,
		UserID:           opts.UserID,
		Password:         opts.Password,
		DomainID:         opts.DomainID,
		DomainName:       opts.DomainName,
		TenantID:         opts.TenantID,
		TenantName:       opts.TenantName,
		AllowReauth:      opts.AllowReauth,
		TokenID:          opts.TokenID,
	}
	if cfg.MetadataBucket == "" {
		cfg.MetadataBucket = metadata.BuildMetadataBucketName(opts.Username)
	}

	// Openstack client
	pClient, err := openstack.AuthenticatedClient(gcOpts)
	if err != nil {
		return nil, fmt.Errorf("%s", ProviderErrorToString(err))
	}

	// Compute API
	compute, err := openstack.NewComputeV2(pClient, gc.EndpointOpts{
		Region: opts.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("%s", ProviderErrorToString(err))
	}

	// Network API
	network, err := openstack.NewNetworkV2(pClient, gc.EndpointOpts{
		Region: opts.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("%s", ProviderErrorToString(err))
	}

	// Get Identity from network service
	nID, err := networks.IDFromName(network, cfg.ProviderNetwork)
	if err != nil {
		return nil, fmt.Errorf("%s", ProviderErrorToString(err))
	}
	// volume API
	volume, err := openstack.NewBlockStorageV1(pClient, gc.EndpointOpts{
		Region: opts.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("%s", ProviderErrorToString(err))
	}

	clt := Client{
		Opts:              &opts,
		Cfg:               &cfg,
		Provider:          pClient,
		Compute:           compute,
		Network:           network,
		Volume:            volume,
		ProviderNetworkID: nID,
	}

	err = clt.initDefaultSecurityGroup()
	if err != nil {
		return nil, err
	}

	return &clt, nil
}

const defaultRouter string = "d46886b1-cb8e-4e98-9b18-b60bf847dd09"
const defaultSecurityGroup string = "30ad3142-a5ec-44b5-9560-618bde3de1ef"

// Client is the implementation of the openstack driver regarding to the api.ClientAPI
type Client struct {
	Opts     *AuthOptions
	Cfg      *CfgOptions
	Provider *gc.ProviderClient
	Compute  *gc.ServiceClient
	Network  *gc.ServiceClient
	Volume   *gc.ServiceClient
	// Container *gc.ServiceClient

	SecurityGroup     *secgroups.SecurityGroup
	ProviderNetworkID string
}

// getDefaultSecurityGroup returns the default security group
func (client *Client) getDefaultSecurityGroup() (*secgroups.SecurityGroup, error) {
	var sgList []secgroups.SecurityGroup

	err := secgroups.List(client.Compute).EachPage(func(page pagination.Page) (bool, error) {
		list, err := secgroups.ExtractSecurityGroups(page)
		if err != nil {
			return false, err
		}
		for _, e := range list {
			if e.Name == defaultSecurityGroup {
				sgList = append(sgList, e)
			}
		}
		return true, nil
	})
	if len(sgList) == 0 {
		return nil, err
	}
	if len(sgList) > 1 {
		return nil, fmt.Errorf("Configuration error: More than one default security groups exists")
	}

	return &sgList[0], nil
}

// createTCPRules creates TCP rules to configure the default security group
func (client *Client) createTCPRules(groupID string) error {
	// Open TCP Ports
	ruleOpts := secgroups.CreateRuleOpts{
		ParentGroupID: groupID,
		FromPort:      1,
		ToPort:        65535,
		IPProtocol:    "TCP",
		CIDR:          "0.0.0.0/0",
	}

	_, err := secgroups.CreateRule(client.Compute, ruleOpts).Extract()
	if err != nil {
		return err
	}
	ruleOpts = secgroups.CreateRuleOpts{
		ParentGroupID: groupID,
		FromPort:      1,
		ToPort:        65535,
		IPProtocol:    "TCP",
		CIDR:          "::/0",
	}
	_, err = secgroups.CreateRule(client.Compute, ruleOpts).Extract()
	return err
}

// createTCPRules creates UDP rules to configure the default security group
func (client *Client) createUDPRules(groupID string) error {
	// Open UDP Ports
	ruleOpts := secgroups.CreateRuleOpts{
		ParentGroupID: groupID,
		FromPort:      1,
		ToPort:        65535,
		IPProtocol:    "UDP",
		CIDR:          "0.0.0.0/0",
	}

	_, err := secgroups.CreateRule(client.Compute, ruleOpts).Extract()
	if err != nil {
		return err
	}
	ruleOpts = secgroups.CreateRuleOpts{
		ParentGroupID: groupID,
		FromPort:      1,
		ToPort:        65535,
		IPProtocol:    "UDP",
		CIDR:          "::/0",
	}
	_, err = secgroups.CreateRule(client.Compute, ruleOpts).Extract()
	return err
}

// createICMPRules creates UDP rules to configure the default security group
func (client *Client) createICMPRules(groupID string) error {
	// Open TCP Ports
	ruleOpts := secgroups.CreateRuleOpts{
		ParentGroupID: groupID,
		FromPort:      -1,
		ToPort:        -1,
		IPProtocol:    "ICMP",
		CIDR:          "0.0.0.0/0",
	}

	_, err := secgroups.CreateRule(client.Compute, ruleOpts).Extract()
	if err != nil {
		return err
	}
	ruleOpts = secgroups.CreateRuleOpts{
		ParentGroupID: groupID,
		FromPort:      -1,
		ToPort:        -1,
		IPProtocol:    "ICMP",
		CIDR:          "::/0",
	}
	_, err = secgroups.CreateRule(client.Compute, ruleOpts).Extract()
	return err
}

// initDefaultSecurityGroup create an open Security Group
// The default security group opens all TCP, UDP, ICMP ports
// Security is managed individually on each host using a linux firewall
func (client *Client) initDefaultSecurityGroup() error {
	sg, err := client.getDefaultSecurityGroup()
	if err != nil {
		return err
	}
	if sg != nil {
		client.SecurityGroup = sg
		return nil
	}
	opts := secgroups.CreateOpts{
		Name:        defaultSecurityGroup,
		Description: "Default security group",
	}

	group, err := secgroups.Create(client.Compute, opts).Extract()
	if err != nil {
		return err
	}
	err = client.createTCPRules(group.ID)
	if err != nil {
		secgroups.Delete(client.Compute, group.ID)
		return err
	}

	err = client.createUDPRules(group.ID)
	if err != nil {
		secgroups.Delete(client.Compute, group.ID)
		return err
	}
	err = client.createICMPRules(group.ID)
	if err != nil {
		secgroups.Delete(client.Compute, group.ID)
		return err
	}
	client.SecurityGroup = group
	return nil
}

// Build build a new Client from configuration parameter
func (client *Client) Build(params map[string]interface{}) (api.ClientAPI, error) {
	tenantName, _ := params["name"].(string)

	identity, _ := params["identity"].(map[string]interface{})
	compute, _ := params["compute"].(map[string]interface{})
	// network, _ := params["network"].(map[string]interface{})

	identityEndpoint, _ := identity["Endpoint"].(string)
	username, _ := identity["Username"].(string)
	password, _ := identity["Password"].(string)

	region, _ := compute["Region"].(string)
	floatingIPPool, _ := compute["FloatingIPPool"].(string)
	defaultImage, _ := compute["DefaultImage"]

	return AuthenticatedClient(
		AuthOptions{
			IdentityEndpoint: identityEndpoint,
			Username:         username,
			Password:         password,
			TenantName:       tenantName,
			Region:           region,
			FloatingIPPool:   floatingIPPool,
		},
		CfgOptions{
			ProviderNetwork:           "public",
			UseFloatingIP:             true,
			UseLayer3Networking:       true,
			AutoHostNetworkInterfaces: true,
			VolumeSpeeds: map[string]VolumeSpeed.Enum{
				"standard":   VolumeSpeed.COLD,
				"performant": VolumeSpeed.HDD,
			},
			DNSList:      []string{"185.23.94.244", "185.23.94.244"},
			DefaultImage: defaultImage.(string),
		},
	)
}

// GetAuthOpts returns the auth options
func (client *Client) GetAuthOpts() (model.Config, error) {
	cfg := model.ConfigMap{}

	cfg.Set("TenantName", client.Opts.TenantName)
	cfg.Set("Login", client.Opts.Username)
	cfg.Set("Password", client.Opts.Password)
	cfg.Set("AuthUrl", client.Opts.IdentityEndpoint)
	cfg.Set("Region", client.Opts.Region)
	return cfg, nil
}

// GetCfgOpts return configuration parameters
func (client *Client) GetCfgOpts() (model.Config, error) {
	cfg := model.ConfigMap{}

	cfg.Set("DNSList", client.Cfg.DNSList)
	// cfg.Set("ObjectStorageType", client.Cfg.ObjectStorageType)
	cfg.Set("AutoHostNetworkInterfaces", client.Cfg.AutoHostNetworkInterfaces)
	cfg.Set("UseLayer3Networking", client.Cfg.UseLayer3Networking)
	cfg.Set("ProviderNetwork", client.Cfg.ProviderNetwork)
	cfg.Set("MetadataBucket", client.Cfg.MetadataBucket)

	return cfg, nil
}
