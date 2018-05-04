package flexibleengine

import (
	"fmt"
	"net/url"
	"text/template"

	rice "github.com/GeertJohan/go.rice"
	"github.com/SafeScale/providers"
	"github.com/SafeScale/providers/api"
	"github.com/SafeScale/providers/api/VolumeSpeed"
	"github.com/SafeScale/providers/openstack"

	// OpenStack API from GopherCloud
	gc "github.com/gophercloud/gophercloud"
	gcos "github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/projects"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/tokens"
	secgroups "github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/groups"
	secrules "github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/rules"
	"github.com/gophercloud/gophercloud/pagination"

	// official AWS API
	"github.com/aws/aws-sdk-go/aws"
	awscreds "github.com/aws/aws-sdk-go/aws/credentials"
	awssession "github.com/aws/aws-sdk-go/aws/session"
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

	// Identifier for S3 object storage use
	S3AccessKeyID string
	// Password of the previous identifier
	S3AccessKeyPassword string
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

//NetworkGWContainerName contains the name of the Object Storage Bucket in to put Gateway definitions (not needed in FlexibleEngine ?)
//const NetworkGWContainerName string = "0.%s.network-gws"
//VMContainerName contains the name of the Object Storage Bucket in to put VMs definitions
//const VMContainerName string = "0.%s.vms"
//NetworkGWContainerName contains the name of the Object Storage Bucket in to put Gateway definitions (not needed in FlexibleEngine ?)
const NetworkGWContainerName string = "0.network-gws"

//VMContainerName contains the name of the Object Storage Bucket in to put VMs definitions
const VMContainerName string = "0.vms"

const defaultUser = "cloud"

const authURL = "https://iam.%s.prod-cloud-ocb.orange-business.com"

//VPL:BEGIN
// aws provider isn't finished yet, copying the necessary here meanwhile...

//AuthOpts AWS credentials
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

//AuthenticatedClient returns an authenticated client
func AuthenticatedClient(opts AuthOptions, cfg CfgOptions) (*Client, error) {
	// gophercloud doesn't know how to determine Auth API version to use for FlexibleEngine.
	// So we help him to.
	provider, err := gcos.NewClient(fmt.Sprintf(authURL, opts.Region))
	authOptions := tokens.AuthOptions{
		IdentityEndpoint: fmt.Sprintf(authURL, opts.Region),
		Username:         opts.Username,
		Password:         opts.Password,
		DomainName:       opts.DomainName,
		AllowReauth:      opts.AllowReauth,
		Scope: tokens.Scope{
			ProjectName: opts.Region,
			DomainName:  opts.DomainName,
		},
	}
	err = gcos.AuthenticateV3(provider, &authOptions, gc.EndpointOpts{})
	if err != nil {
		return nil, fmt.Errorf("%s", errorString(err))
	}

	//Identity API
	identity, err := gcos.NewIdentityV3(provider, gc.EndpointOpts{})
	if err != nil {
		return nil, fmt.Errorf("%s", errorString(err))
	}

	// Recover Project ID of region
	listOpts := projects.ListOpts{
		Enabled: gc.Enabled,
		Name:    opts.Region,
	}
	allPages, err := projects.List(identity, listOpts).AllPages()
	if err != nil {
		return nil, fmt.Errorf("failed to query project ID corresponding to region '%s': %s", opts.Region, errorString(err))
	}
	allProjects, err := projects.ExtractProjects(allPages)
	if err != nil {
		return nil, fmt.Errorf("failed to load project ID corresponding to region '%s': %s", opts.Region, errorString(err))
	}
	if len(allProjects) > 0 {
		opts.ProjectID = allProjects[0].ID
	} else {
		return nil, fmt.Errorf("failed to found project ID corresponding to region '%s': %s", opts.Region, errorString(err))
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

	// Need to get Endpoint URL for ObjectStorage, thzt will be used with AWS S3 protocol
	objectStorage, err := gcos.NewObjectStorageV1(provider, gc.EndpointOpts{
		Type:   "object",
		Region: opts.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("%s", errorString(err))
	}
	// Fix URL of ObjectStorage for FlexibleEngine...
	u, _ := url.Parse(objectStorage.Endpoint)
	endpoint := u.Scheme + "://" + u.Hostname() + "/"
	// FlexibleEngine uses a protocol compatible with S3, so we need to get aws.Session instance
	authOpts := awsAuthOpts{
		AccessKeyID:     opts.S3AccessKeyID,
		SecretAccessKey: opts.S3AccessKeyPassword,
		Region:          opts.Region,
	}
	awsSession, err := awssession.NewSession(&aws.Config{
		Region:      aws.String(opts.Region),
		Credentials: awscreds.NewCredentials(authOpts),
		Endpoint:    &endpoint,
	})
	if err != nil {
		return nil, err
	}

	box, err := rice.FindBox("../openstack/scripts")
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
		Provider: provider,
		Compute:  compute,
		Network:  network,
		Volume:   blockStorage,
		//Container:   objectStorage,
		ScriptBox:   box,
		UserDataTpl: tpl,
	}
	clt := Client{
		Opts:      &opts,
		Cfg:       &cfg,
		Client:    &openstackClient,
		Identity:  identity,
		S3Session: awsSession,
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

	err = clt.CreateContainer(NetworkGWContainerName)
	if err != nil {
		fmt.Printf("Failed to create Object Container %s: %s\n", NetworkGWContainerName, errorString(err))
	}
	err = clt.CreateContainer(VMContainerName)
	if err != nil {
		fmt.Printf("Failed to create Object Container %s: %s\n", VMContainerName, err)
	}
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
	Identity *gc.ServiceClient

	// "AWS Session" for object storage use (compatible S3)
	S3Session *awssession.Session

	// Instance of the VPC
	vpc *VPC
	// Contains the name of the default security group for the VPC
	defaultSecurityGroup string
	// Instance of the default security group
	SecurityGroup *secgroups.SecGroup
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
	S3AccessKeyID, _ := params["S3AccessKeyID"].(string)
	S3AccessKeyPassword, _ := params["S3AccessKeyPassword"].(string)
	return AuthenticatedClient(AuthOptions{
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
	}, CfgOptions{
		UseFloatingIP:       true,
		UseLayer3Networking: false,
		VolumeSpeeds: map[string]VolumeSpeed.Enum{
			"SATA": VolumeSpeed.COLD,
			"SAS":  VolumeSpeed.HDD,
			"SSD":  VolumeSpeed.SSD,
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
func (client *Client) getDefaultSecurityGroup() (*secgroups.SecGroup, error) {
	var sgList []secgroups.SecGroup
	opts := secgroups.ListOpts{
		Name: client.defaultSecurityGroup,
	}
	err := secgroups.List(client.Network, opts).EachPage(func(page pagination.Page) (bool, error) {
		list, err := secgroups.ExtractGroups(page)
		if err != nil {
			return false, err
		}
		for _, g := range list {
			if g.Name == client.defaultSecurityGroup {
				sgList = append(sgList, g)
			}
		}
		return true, nil
	})
	if err != nil {
		return nil, fmt.Errorf("Error listing routers: %s", errorString(err))
	}
	if len(sgList) == 0 {
		return nil, nil
	}
	if len(sgList) > 1 {
		return nil, fmt.Errorf("Configuration error: multiple Security Groups named '%s' exist", client.defaultSecurityGroup)
	}

	return &sgList[0], nil
}

//createTCPRules creates TCP rules to configure the default security group
func (client *Client) createTCPRules(groupID string) error {
	// Inbound == ingress == coming from Outside
	ruleOpts := secrules.CreateOpts{
		Direction:      secrules.DirIngress,
		PortRangeMin:   1,
		PortRangeMax:   65535,
		EtherType:      secrules.EtherType4,
		SecGroupID:     groupID,
		Protocol:       secrules.ProtocolTCP,
		RemoteIPPrefix: "0.0.0.0/0",
	}
	_, err := secrules.Create(client.Network, ruleOpts).Extract()
	if err != nil {
		return err
	}
	ruleOpts = secrules.CreateOpts{
		Direction:      secrules.DirIngress,
		PortRangeMin:   1,
		PortRangeMax:   65535,
		EtherType:      secrules.EtherType6,
		SecGroupID:     groupID,
		Protocol:       secrules.ProtocolTCP,
		RemoteIPPrefix: "::/0",
	}
	_, err = secrules.Create(client.Network, ruleOpts).Extract()
	if err != nil {
		return err
	}

	// Outbound = egress == going to Outside
	ruleOpts = secrules.CreateOpts{
		Direction:      secrules.DirEgress,
		PortRangeMin:   1,
		PortRangeMax:   65535,
		EtherType:      secrules.EtherType4,
		SecGroupID:     groupID,
		Protocol:       secrules.ProtocolTCP,
		RemoteIPPrefix: "0.0.0.0/0",
	}
	_, err = secrules.Create(client.Network, ruleOpts).Extract()
	if err != nil {
		return err
	}
	ruleOpts = secrules.CreateOpts{
		Direction:      secrules.DirEgress,
		PortRangeMin:   1,
		PortRangeMax:   65535,
		EtherType:      secrules.EtherType6,
		SecGroupID:     groupID,
		Protocol:       secrules.ProtocolTCP,
		RemoteIPPrefix: "::/0",
	}
	_, err = secrules.Create(client.Network, ruleOpts).Extract()
	return err
}

//createTCPRules creates UDP rules to configure the default security group
func (client *Client) createUDPRules(groupID string) error {
	// Inbound == ingress == coming from Outside
	ruleOpts := secrules.CreateOpts{
		Direction:      secrules.DirIngress,
		PortRangeMin:   1,
		PortRangeMax:   65535,
		EtherType:      secrules.EtherType4,
		SecGroupID:     groupID,
		Protocol:       secrules.ProtocolUDP,
		RemoteIPPrefix: "0.0.0.0/0",
	}
	_, err := secrules.Create(client.Network, ruleOpts).Extract()
	if err != nil {
		return err
	}
	ruleOpts = secrules.CreateOpts{
		Direction:      secrules.DirIngress,
		PortRangeMin:   1,
		PortRangeMax:   65535,
		EtherType:      secrules.EtherType6,
		SecGroupID:     groupID,
		Protocol:       secrules.ProtocolUDP,
		RemoteIPPrefix: "::/0",
	}
	_, err = secrules.Create(client.Network, ruleOpts).Extract()
	if err != nil {
		return err
	}

	// Outbound = egress == going to Outside
	ruleOpts = secrules.CreateOpts{
		Direction:      secrules.DirEgress,
		PortRangeMin:   1,
		PortRangeMax:   65535,
		EtherType:      secrules.EtherType4,
		SecGroupID:     groupID,
		Protocol:       secrules.ProtocolUDP,
		RemoteIPPrefix: "0.0.0.0/0",
	}
	_, err = secrules.Create(client.Network, ruleOpts).Extract()
	if err != nil {
		return err
	}
	ruleOpts = secrules.CreateOpts{
		Direction:      secrules.DirEgress,
		PortRangeMin:   1,
		PortRangeMax:   65535,
		EtherType:      secrules.EtherType6,
		SecGroupID:     groupID,
		Protocol:       secrules.ProtocolUDP,
		RemoteIPPrefix: "::/0",
	}
	_, err = secrules.Create(client.Network, ruleOpts).Extract()
	return err
}

//createICMPRules creates UDP rules to configure the default security group
func (client *Client) createICMPRules(groupID string) error {
	// Inbound == ingress == coming from Outside
	ruleOpts := secrules.CreateOpts{
		Direction:      secrules.DirIngress,
		EtherType:      secrules.EtherType4,
		SecGroupID:     groupID,
		Protocol:       secrules.ProtocolICMP,
		RemoteIPPrefix: "0.0.0.0/0",
	}
	_, err := secrules.Create(client.Network, ruleOpts).Extract()
	if err != nil {
		return err
	}
	ruleOpts = secrules.CreateOpts{
		Direction: secrules.DirIngress,
		//		PortRangeMin:   0,
		//		PortRangeMax:   18,
		EtherType:      secrules.EtherType6,
		SecGroupID:     groupID,
		Protocol:       secrules.ProtocolICMP,
		RemoteIPPrefix: "::/0",
	}
	_, err = secrules.Create(client.Network, ruleOpts).Extract()
	if err != nil {
		return err
	}

	// Outbound = egress == going to Outside
	ruleOpts = secrules.CreateOpts{
		Direction: secrules.DirEgress,
		//		PortRangeMin:   0,
		//		PortRangeMax:   18,
		EtherType:      secrules.EtherType4,
		SecGroupID:     groupID,
		Protocol:       secrules.ProtocolICMP,
		RemoteIPPrefix: "0.0.0.0/0",
	}
	_, err = secrules.Create(client.Network, ruleOpts).Extract()
	if err != nil {
		return err
	}
	ruleOpts = secrules.CreateOpts{
		Direction: secrules.DirEgress,
		//		PortRangeMin:   0,
		//		PortRangeMax:   18,
		EtherType:      secrules.EtherType6,
		SecGroupID:     groupID,
		Protocol:       secrules.ProtocolICMP,
		RemoteIPPrefix: "::/0",
	}
	_, err = secrules.Create(client.Network, ruleOpts).Extract()
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
		client.SecurityGroup = sg
		return nil
	}
	opts := secgroups.CreateOpts{
		Name:        client.defaultSecurityGroup,
		Description: "Default security group for VPC " + client.Opts.VPCName,
	}
	group, err := secgroups.Create(client.Network, opts).Extract()
	if err != nil {
		return fmt.Errorf("Failed to create Security Group '%s': %s", client.defaultSecurityGroup, errorString(err))
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
	client.SecurityGroup = group
	return nil
}

//initVPC initializes the VPC if it doesn't exist
func (client *Client) initVPC() error {
	// Tries to get VPC information
	vpcID, err := client.findVPCID()
	if err != nil {
		return err
	}
	if vpcID != nil {
		client.vpc, err = client.GetVPC(*vpcID)
		return err
	}

	vpc, err := client.CreateVPC(VPCRequest{
		Name: client.Opts.VPCName,
		CIDR: client.Opts.VPCCIDR,
	})
	if err != nil {
		return fmt.Errorf("Failed to initialize VPC '%s': %s", client.Opts.VPCName, errorString(err))
	}
	client.vpc = vpc
	return nil
}

//findVPC returns the ID about the VPC
func (client *Client) findVPCID() (*string, error) {
	var router *openstack.Router
	found := false
	routers, err := client.Client.ListRouter()
	if err != nil {
		return nil, fmt.Errorf("Error listing routers: %s", errorString(err))
	}
	for _, r := range routers {
		if r.Name == client.Opts.VPCName {
			found = true
			router = &r
			break
		}
	}
	if found {
		return &router.ID, nil
	}
	return nil, nil
}

func init() {
	providers.Register("flexibleengine", &Client{})
}
