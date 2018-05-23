package openstack

import (
	"fmt"
	"log"
	"text/template"

	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"

	"github.com/GeertJohan/go.rice"
	"github.com/SafeScale/providers/api"
	"github.com/SafeScale/providers/api/VolumeSpeed"

	gc "github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/secgroups"
	"github.com/gophercloud/gophercloud/pagination"
)

//go:generate rice embed-go

/*AuthOptions fields are the union of those recognized by each identity implementation and
provider.
*/
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
	// possible.  This setting defaults to false.
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

//CfgOptions configuration options
type CfgOptions struct {
	//Name of the provider (external) network
	ProviderNetwork string

	//DNSList list of DNS
	DNSList []string

	//UseFloatingIP indicates if floating IP are used (optional)
	UseFloatingIP bool

	//UseLayer3Networking indicates if layer 3 networking features (router) can be used
	//if UseFloatingIP is true UseLayer3Networking must be true
	UseLayer3Networking bool

	//AutoVMNetworkInterfaces indicates if network interfaces are configured automatically by the provider or needs a post configuration
	AutoVMNetworkInterfaces bool

	//VolumeSpeeds map volume types with volume speeds
	VolumeSpeeds map[string]VolumeSpeed.Enum

	//S3Protocol protocol used to mount object storage (ex: swiftks or s3)
	S3Protocol string
}

//errorString creates an error string from openstack api error
func errorString(err error) string {
	switch e := err.(type) {
	default:
		return e.Error()
	case *gc.ErrUnexpectedResponseCode:
		return fmt.Sprintf("code : %d reason ; %s", e.Actual, string(e.Body[:]))
	}
}

//AuthenticatedClient returns an authenticated client
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

	//Openstack client
	pClient, err := openstack.AuthenticatedClient(gcOpts)
	if err != nil {
		return nil, fmt.Errorf("%s", errorString(err))
	}

	//Compute API
	compute, err := openstack.NewComputeV2(pClient, gc.EndpointOpts{
		Region: opts.Region,
	})

	if err != nil {
		return nil, fmt.Errorf("%s", errorString(err))
	}

	//Network API
	network, err := openstack.NewNetworkV2(pClient, gc.EndpointOpts{
		Region: opts.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("%s", errorString(err))
	}
	nID, err := networks.IDFromName(network, cfg.ProviderNetwork)
	if err != nil {
		return nil, fmt.Errorf("%s", errorString(err))
	}
	//Storage API
	blocstorage, err := openstack.NewBlockStorageV1(pClient, gc.EndpointOpts{
		Region: opts.Region,
	})

	objectstorage, err := openstack.NewObjectStorageV1(pClient, gc.EndpointOpts{
		Region: opts.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("%s", errorString(err))
	}
	box, err := rice.FindBox("scripts")
	if err != nil {
		return nil, err
	}
	userDataStr, err := box.String("userdata.sh")
	if err != nil {
		return nil, err
	}
	tpl, err := template.New("user_data").Parse(userDataStr)
	if err != nil {
		return nil, err
	}

	if len(cfg.S3Protocol) == 0 {
		log.Print("No S3 protocol defined. Fallthrough default 'swiftks'")
		cfg.S3Protocol = "swiftks"
	}

	clt := Client{
		Opts:              &opts,
		Cfg:               &cfg,
		Provider:          pClient,
		Compute:           compute,
		Network:           network,
		Volume:            blocstorage,
		Container:         objectstorage,
		ScriptBox:         box,
		UserDataTpl:       tpl,
		ProviderNetworkID: nID,
	}

	err = clt.initDefaultSecurityGroup()
	if err != nil {
		return nil, err
	}
	clt.CreateContainer(api.NetworkContainerName)
	clt.CreateContainer(api.VMContainerName)
	clt.CreateContainer(api.NasContainerName)
	return &clt, nil
}

const defaultRouter string = "d46886b1-cb8e-4e98-9b18-b60bf847dd09"
const defaultSecurityGroup string = "30ad3142-a5ec-44b5-9560-618bde3de1ef"

//Client is the implementation of the openstack driver regarding to the api.ClientAPI
type Client struct {
	Opts        *AuthOptions
	Cfg         *CfgOptions
	Provider    *gc.ProviderClient
	Compute     *gc.ServiceClient
	Network     *gc.ServiceClient
	Volume      *gc.ServiceClient
	Container   *gc.ServiceClient
	ScriptBox   *rice.Box
	UserDataTpl *template.Template

	SecurityGroup     *secgroups.SecurityGroup
	ProviderNetworkID string
}

//getDefaultSecurityGroup returns the default security group
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

//createTCPRules creates TCP rules to configure the default security group
func (client *Client) createTCPRules(groupID string) error {
	//Open TCP Ports
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

//createTCPRules creates UDP rules to configure the default security group
func (client *Client) createUDPRules(groupID string) error {
	//Open UDP Ports
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

//createICMPRules creates UDP rules to configure the default security group
func (client *Client) createICMPRules(groupID string) error {
	//Open TCP Ports
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

//initDefaultSecurityGroup create an open Security Group
//The default security group opens all TCP, UDP, ICMP ports
//Security is managed individually on each VM using a linux firewall
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

//Build build a new Client from configuration parameter
func (client *Client) Build(params map[string]interface{}) (api.ClientAPI, error) {
	IdentityEndpoint, _ := params["IdentityEndpoint"].(string)
	Username, _ := params["Username"].(string)
	Password, _ := params["Password"].(string)
	TenantName, _ := params["TenantName"].(string)
	Region, _ := params["Region"].(string)
	FloatingIPPool, _ := params["FloatingIPPool"].(string)
	return AuthenticatedClient(
		AuthOptions{
			IdentityEndpoint: IdentityEndpoint,
			Username:         Username,
			Password:         Password,
			TenantName:       TenantName,
			Region:           Region,
			FloatingIPPool:   FloatingIPPool,
		},
		CfgOptions{
			ProviderNetwork:         "public",
			UseFloatingIP:           true,
			UseLayer3Networking:     true,
			AutoVMNetworkInterfaces: true,
			VolumeSpeeds: map[string]VolumeSpeed.Enum{
				"standard":   VolumeSpeed.COLD,
				"performant": VolumeSpeed.HDD,
			},
			DNSList:    []string{"185.23.94.244", "185.23.94.244"},
			S3Protocol: "swiftks",
		},
	)
}

//GetAuthOpts returns the auth options
func (client *Client) GetAuthOpts() (api.Config, error) {
	cfg := api.ConfigMap{}

	cfg.Set("TenantName", client.Opts.TenantName)
	cfg.Set("Login", client.Opts.Username)
	cfg.Set("Password", client.Opts.Password)
	cfg.Set("AuthUrl", client.Opts.IdentityEndpoint)
	cfg.Set("Region", client.Opts.Region)

	return cfg, nil
}

//GetCfgOpts return configuration parameters
func (client *Client) GetCfgOpts() (api.Config, error) {
	cfg := api.ConfigMap{}

	cfg.Set("DNSList", client.Cfg.DNSList)
	cfg.Set("S3Protocol", client.Cfg.S3Protocol)

	return cfg, nil
}
