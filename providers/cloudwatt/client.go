package cloudwatt

import (
	"fmt"

	"github.com/SafeScale/providers/api"
	"github.com/SafeScale/providers/api/VolumeSpeed"
	"github.com/SafeScale/providers/openstack"
)

//ProviderNetwork name of ovh external network
const ProviderNetwork string = "Ext-Net"

/*AuthOptions fields are the union of those recognized by each identity implementation and
provider.
*/
type AuthOptions struct {
	Username   string
	Password   string
	TenantName string
	Region     string
}

// func parseOpenRC(openrc string) (*openstack.AuthOptions, error) {
// 	tokens := strings.Split(openrc, "export")
// }

//AuthenticatedClient returns an authenticated client
func AuthenticatedClient(opts AuthOptions) (*Client, error) {
	IdentityEndpoint := fmt.Sprintf("https://identity.%s.cloudwatt.com/v2.0", opts.Region)
	os, err := openstack.AuthenticatedClient(openstack.AuthOptions{
		IdentityEndpoint: IdentityEndpoint,
		//UserID:           opts.OpenstackID,
		Username:       opts.Username,
		Password:       opts.Password,
		TenantName:     opts.TenantName,
		Region:         opts.Region,
		FloatingIPPool: "public",
	},
		openstack.CfgOptions{
			ProviderNetwork:         "public",
			UseFloatingIP:           true,
			UseLayer3Networking:     true,
			AutoVMNetworkInterfaces: true,
			VolumeSpeeds: map[string]VolumeSpeed.Enum{
				"standard":   VolumeSpeed.COLD,
				"performant": VolumeSpeed.HDD,
			},
			DNSList: []string{"185.23.94.244", "185.23.94.245"},
		},
	)

	if err != nil {
		return nil, err
	}
	return &Client{
		Client: os,
		opts:   opts,
	}, nil

}

//Client is the implementation of the ovh driver regarding to the api.ClientAPI
//This client used ovh api and opensatck ovh api to maximize code reuse
type Client struct {
	*openstack.Client
	opts AuthOptions
}

//Build build a new Client from configuration parameter
func (c *Client) Build(params map[string]interface{}) (api.ClientAPI, error) {
	Username, _ := params["Username"].(string)
	Password, _ := params["Password"].(string)
	TenantName, _ := params["TenantName"].(string)
	Region, _ := params["Region"].(string)
	return AuthenticatedClient(AuthOptions{
		Username:   Username,
		Password:   Password,
		TenantName: TenantName,
		Region:     Region,
	})
}
