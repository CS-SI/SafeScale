package flexibleengine

import (
	"fmt"

	rice "github.com/GeertJohan/go.rice"
	"github.com/SafeScale/providers/api"
	"github.com/SafeScale/providers/api/VolumeSpeed"
	"github.com/SafeScale/providers/openstack"

	gc "github.com/gophercloud/gophercloud"
	gcos "github.com/gophercloud/gophercloud/openstack"
	tokens3 "github.com/gophercloud/gophercloud/openstack/identity/v3/tokens"
	secgroups "github.com/gophercloud/gophercloud/openstack/network/v2/extensions/security/groups"
	secrules "github.com/gophercloud/gophercloud/openstack/network/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/pagination"
)

//go:generate rice embed-go

/*AuthOptions fields are the union of those recognized by each identity implementation and
provider.
*/
type AuthOptions struct {
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
}

//CfgOptions configuration options
type CfgOptions struct {
	//VPL: No choice with FlexibleEngine
	//Name of the provider (external) network
	//ProviderNetwork string

	//DNSList list of DNS
	DNSList []string

	// VPL: Floating IP are mandatory in FlexibleEngine
	//UseFloatingIP indicates if floating IP are used (optional)
	UseFloatingIP bool

	//UseLayer3Networking indicates if layer 3 networking features (router) can be used
	//if UseFloatingIP is true UseLayer3Networking must be true
	UseLayer3Networking bool

	//AutoVMNetworkInterfaces indicates if network interfaces are configured automatically by the provider or needs a post configuration
	AutoVMNetworkInterfaces bool

	//VolumeSpeeds map volume types with volume speeds
	VolumeSpeeds map[string]VolumeSpeed.Enum
}

//errorString creates an error string from flexibleengine api error
func errorString(err error) string {
	switch e := err.(type) {
	default:
		return e.Error()
	case *gc.ErrUnexpectedResponseCode:
		return fmt.Sprintf("code : %d reason ; %s", e.Actual, string(e.Body[:]))
	}
}

//NetworkGWContainer container where Gateway configuratiion are stored
const NetworkGWContainer string = "__network_gws__"

const defaultUser = "cloud"

//const authURL = "https://iam.%s.prod-cloud-ocb.orange-business.com/v3/auth/tokens"
const authURL = "https://iam.%s.prod-cloud-ocb.orange-business.com"

//AuthenticatedClient returns an authenticated client
func AuthenticatedClient(opts AuthOptions, cfg CfgOptions) (*Client, error) {
	// gophercloud doesn't know how to determine Auth API version to use for FlexibleEngine.
	// So we help him to.
	provider, err := gcos.NewClient(fmt.Sprintf(authURL, opts.Region))
	authOptions := tokens3.AuthOptions{
		IdentityEndpoint: fmt.Sprintf(authURL, opts.Region),
		Username:         opts.Username,
		Password:         opts.Password,
		DomainName:       opts.DomainName,
		AllowReauth:      opts.AllowReauth,
		//TokenID string `json:"-"`
		Scope: tokens3.Scope{
			ProjectID: opts.ProjectID,
		},
	}
	err = gcos.AuthenticateV3(provider, &authOptions, gc.EndpointOpts{})
	if err != nil {
		return nil, fmt.Errorf("%s", errorString(err))
	}

	//Compute API
	compute, err := gcos.NewComputeV2(provider, gc.EndpointOpts{})
	if err != nil {
		return nil, fmt.Errorf("%s", errorString(err))
	}

	//Network API
	network, err := gcos.NewNetworkV2(provider, gc.EndpointOpts{
		Type:   "network",
		Region: opts.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("%s", errorString(err))
	}

	//Storage API
	blockStorage, err := gcos.NewBlockStorageV2(provider, gc.EndpointOpts{
		Type:   "volumev2",
		Region: opts.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("%s", errorString(err))
	}

	objectStorage, err := gcos.NewObjectStorageV1(provider, gc.EndpointOpts{
		Type:   "object",
		Region: opts.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("%s", errorString(err))
	}

	box, err := rice.FindBox("../openstack/scripts")
	if err != nil {
		return nil, err
	}
	/*
		userDataStr, err := box.String("userdata.sh")
		if err != nil {
			return nil, err
		}

		tpl, err := template.New("user_data").Parse(userDataStr)
		if err != nil {
			return nil, err
		}
	*/

	openstackClient := openstack.Client{
		Opts: &openstack.AuthOptions{
			IdentityEndpoint: opts.IdentityEndpoint,
			Username:         opts.Username,
			Password:         opts.Password,
			DomainName:       opts.DomainName,
			AllowReauth:      opts.AllowReauth,
			Region:           opts.Region,
		},
		Cfg: &openstack.CfgOptions{
			UseFloatingIP:       true,
			UseLayer3Networking: true,
			VolumeSpeeds:        cfg.VolumeSpeeds,
		},
		Provider:  provider,
		Compute:   compute,
		Network:   network,
		Volume:    blockStorage,
		Container: objectStorage,
		ScriptBox: box,
		//UserDataTpl:       tpl,
	}
	clt := Client{
		Opts:   &opts,
		Cfg:    &cfg,
		Client: &openstackClient,
	}

	// Initializes the VPC
	err = clt.initVPC()
	if err != nil {
		return nil, err
	}

	// Initializes the default security group
	err = clt.initDefaultSecurityGroup()
	if err != nil {
		return nil, err
	}

	clt.CreateContainer("__network_gws__")
	clt.CreateContainer("__vms__")
	return &clt, nil
}

/* VPL: Not used ?
const defaultRouter string = "d46886b1-cb8e-4e98-9b18-b60bf847dd09"
*/

//Client is the implementation of the flexibleengine driver regarding to the api.ClientAPI
type Client struct {
	Opts *AuthOptions
	Cfg  *CfgOptions
	*openstack.Client

	// Contains the name of the default security group for the VPC
	defaultSecurityGroup string
}

//Build build a new Client from configuration parameter
func (client *Client) Build(params map[string]interface{}) (api.ClientAPI, error) {
	Username, _ := params["Username"].(string)
	Password, _ := params["Password"].(string)
	DomainName, _ := params["DomainName"].(string)
	ProjectID, _ := params["ProjectID"].(string)
	VPCName, _ := params["VPCName"].(string)
	VPCCIDR, _ := params["VPCCIDR"].(string)
	Region, _ := params["Region"].(string)
	return AuthenticatedClient(AuthOptions{
		Username:    Username,
		Password:    Password,
		DomainName:  DomainName,
		ProjectID:   ProjectID,
		Region:      Region,
		AllowReauth: true,
		VPCName:     VPCName,
		VPCCIDR:     VPCCIDR,
	}, CfgOptions{
		UseFloatingIP:       true,
		UseLayer3Networking: true,
		VolumeSpeeds: map[string]VolumeSpeed.Enum{
			"classic":    VolumeSpeed.COLD,
			"high-speed": VolumeSpeed.HDD,
			"ssd":        VolumeSpeed.SSD,
		},
	})
}

/*
 * VPL: Duplicated code from providers/openstack/client.go
 *      Because of the concept of VPC in FlexibleEngine, we need to create
 *      default Security Group bound to a VPC, to prevent side effect if
 *      a default Security Group is changed
 */

/*
 * Pourquoi un ID plutôt qu'un nom ?
const defaultSecurityGroup string = "30ad3142-a5ec-44b5-9560-618bde3de1ef"
*/

//getDefaultSecurityGroup returns the default security group for the client, in the form
// sg-<VPCName>, if it exists.
func (client *Client) getDefaultSecurityGroup() (*secgroups.SecurityGroup, error) {
	var sgList []secgroups.SecurityGroup
	err := secgroups.List(client.Network).EachPage(func(page pagination.Page) (bool, error) {
		list, err := secgroups.ExtractSecurityGroups(page)
		if err != nil {
			return false, err
		}
		for _, e := range list {
			if e.Name == client.defaultSecurityGroup {
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
	// Inbound == ingress == coming from Outside
	ruleOpts := secrules.CreateOpts{
		Direction:    "ingress",
		PortRangeMin: 1,
		PortRangeMax: 65535,
		EtherType:    secrules.EtherType4,
		SecGroupID:   groupID,
		Protocol:     "tcp",
	}
	_, err := secgroups.CreateRule(client.Network, ruleOpts).Extract()
	if err != nil {
		return err
	}
	ruleOpts = secgroups.CreateRuleOpts{
		Direction:    "ingress",
		PortRangeMin: 1,
		PortRangeMax: 65535,
		EtherType:    secrules.EtherType6,
		SecGroupID:   groupID,
		Protocol:     "tcp",
	}
	_, err = secgroups.CreateRule(client.Compute, ruleOpts).Extract()
	if err != nil {
		return err
	}

	// Outbound = egress == going to Outside
	ruleOpts := secrules.CreateOpts{
		Direction:    "egress",
		PortRangeMin: 1,
		PortRangeMax: 65535,
		EtherType:    secrules.EtherType4,
		SecGroupID:   groupID,
		Protocol:     "tcp",
	}
	_, err := secgroups.CreateRule(client.Network, ruleOpts).Extract()
	if err != nil {
		return err
	}
	ruleOpts = secgroups.CreateRuleOpts{
		Direction:    "egress",
		PortRangeMin: 1,
		PortRangeMax: 65535,
		EtherType:    secrules.EtherType6,
		SecGroupID:   groupID,
		Protocol:     "tcp",
	}
	_, err = secgroups.CreateRule(client.Compute, ruleOpts).Extract()
	return err
}

//createTCPRules creates UDP rules to configure the default security group
func (client *Client) createUDPRules(groupID string) error {
	// Inbound == ingress == coming from Outside
	ruleOpts := secrules.CreateOpts{
		Direction:    "ingress",
		PortRangeMin: 1,
		PortRangeMax: 65535,
		EtherType:    secrules.EtherType4,
		SecGroupID:   groupID,
		Protocol:     "udp",
	}
	_, err := secgroups.CreateRule(client.Network, ruleOpts).Extract()
	if err != nil {
		return err
	}
	ruleOpts = secgroups.CreateRuleOpts{
		Direction:    "ingress",
		PortRangeMin: 1,
		PortRangeMax: 65535,
		EtherType:    secrules.EtherType6,
		SecGroupID:   groupID,
		Protocol:     "udp",
	}
	_, err = secgroups.CreateRule(client.Network, ruleOpts).Extract()
	if err != nil {
		return err
	}

	// Outbound = egress == going to Outside
	ruleOpts := secrules.CreateOpts{
		Direction:    "egress",
		PortRangeMin: 1,
		PortRangeMax: 65535,
		EtherType:    secrules.EtherType4,
		SecGroupID:   groupID,
		Protocol:     "udp",
	}
	_, err := secgroups.CreateRule(client.Network, ruleOpts).Extract()
	if err != nil {
		return err
	}
	ruleOpts = secgroups.CreateRuleOpts{
		Direction:    "egress",
		PortRangeMin: 1,
		PortRangeMax: 65535,
		EtherType:    secrules.EtherType6,
		SecGroupID:   groupID,
		Protocol:     "udp",
	}
	_, err = secgroups.CreateRule(client.Network, ruleOpts).Extract()
	return err
}

//createICMPRules creates UDP rules to configure the default security group
func (client *Client) createICMPRules(groupID string) error {
	// Inbound == ingress == coming from Outside
	ruleOpts := secrules.CreateOpts{
		Direction:    "ingress",
		PortRangeMin: 1,
		PortRangeMax: 65535,
		EtherType:    secrules.EtherType4,
		SecGroupID:   groupID,
		Protocol:     "icmp",
	}
	_, err := secgroups.CreateRule(client.Network, ruleOpts).Extract()
	if err != nil {
		return err
	}
	ruleOpts = secgroups.CreateRuleOpts{
		Direction:    "ingress",
		PortRangeMin: 1,
		PortRangeMax: 65535,
		EtherType:    secrules.EtherType6,
		SecGroupID:   groupID,
		Protocol:     "icmp",
	}
	_, err = secgroups.CreateRule(client.Network, ruleOpts).Extract()
	if err != nil {
		return err
	}

	// Outbound = egress == going to Outside
	ruleOpts := secrules.CreateOpts{
		Direction:    "egress",
		PortRangeMin: 1,
		PortRangeMax: 65535,
		EtherType:    secrules.EtherType4,
		SecGroupID:   groupID,
		Protocol:     "icmp",
	}
	_, err := secgroups.CreateRule(client.Network, ruleOpts).Extract()
	if err != nil {
		return err
	}
	ruleOpts = secgroups.CreateRuleOpts{
		Direction:    "egress",
		PortRangeMin: 1,
		PortRangeMax: 65535,
		EtherType:    secrules.EtherType6,
		SecGroupID:   groupID,
		Protocol:     "icmp",
	}
	_, err = secgroups.CreateRule(client.Network, ruleOpts).Extract()
	return err
}

//initDefaultSecurityGroup create an open Security Group
//The default security group opens all TCP, UDP, ICMP ports
//Security is managed individually on each VM using a linux firewall
func (client *Client) initDefaultSecurityGroup() error {
	client.defaultSecurityGroup = "sg-" + client.Opts.VPCName

	sg, err := client.getDefaultSecurityGroup()
	if err != nil {
		return err
	}
	if sg != nil {
		client.Client.SecurityGroup = sg
		return nil
	}
	opts := secgroups.CreateOpts{
		Name:        client.defaultSecurityGroup,
		Description: "Default security group",
	}

	group, err := secgroups.Create(client.Network, opts).Extract()
	if err != nil {
		return err
	}
	err = client.createTCPRules(group.ID)
	if err != nil {
		secgroups.Delete(client.Network, group.ID)
		return err
	}
	err = client.createUDPRules(group.ID)
	if err != nil {
		secgroups.Delete(client.Network, group.ID)
		return err
	}
	err = client.createICMPRules(group.ID)
	if err != nil {
		secgroups.Delete(client.Network, group.ID)
		return err
	}
	//client.SecurityGroup = group
	return nil
}

//initVPC initializes the VPC if it doesn't exist
func (client *Client) initVPC() error {
	// Tries to get VPC information
	vpc, err := client.FindVPC(client.Opts.VPCName)
	if err != nil {
		return err
	}
	if vpc != nil {
		return nil
	}

	vpc, err = client.CreateVPC(VPCRequest{
		Name: client.Opts.VPCName,
		CIDR: client.Opts.VPCCIDR,
	})
	if err != nil {
		return fmt.Errorf("Failed to initialize VPC '%s'!", client.Opts.VPCName)
	}

	//client.vpc = vpc
	return nil
}
