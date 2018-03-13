package broker

import (
	"fmt"

	"github.com/SafeScale/providers"
	"github.com/SafeScale/providers/api"
	"github.com/SafeScale/providers/api/IPVersion"
)

// broker network create net1 --cidr="192.145.0.0/16" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" (par défault "192.168.0.0/24", on crée une gateway sur chaque réseau: gw_net1)
// broker network list
// broker network delete net1
// broker network inspect net1

//NetworkAPI defines API to manage networks
type NetworkAPI interface {
	Create(net string, cidr string, ipVersion IPVersion.Enum, cpu int, ram float32, disk int, os string) (*api.Network, error)
	List() ([]api.Network, error)
	Get(ref string) (*api.Network, error)
	Delete(ref string) error
}

//NetworkService an instance of NetworkAPI
type NetworkService struct {
	provider  *providers.Service
	ipVersion IPVersion.Enum
}

//NewNetworkService Creates new Network service
func NewNetworkService(api api.ClientAPI) NetworkAPI {
	return &NetworkService{
		provider: providers.FromClient(api),
	}
}

//Create creates a network
func (srv *NetworkService) Create(net string, cidr string, ipVersion IPVersion.Enum, cpu int, ram float32, disk int, os string) (*api.Network, error) {
	_, err := srv.Get(net)
	if err != nil {
		return nil, fmt.Errorf("Network %s already exists", net)
	}
	tpls, err := srv.provider.SelectTemplatesBySize(api.SizingRequirements{
		MinCores:    cpu,
		MinRAMSize:  ram,
		MinDiskSize: disk,
	})
	img, err := srv.provider.SearchImage(os)
	if err != nil {
		return nil, err
	}
	gwRequest := api.VMRequest{
		ImageID:    img.ID,
		Name:       net,
		TemplateID: tpls[0].ID,
	}
	network, err := srv.provider.CreateNetwork(api.NetworkRequest{
		Name:      net,
		IPVersion: srv.ipVersion,
		CIDR:      cidr,
		GWRequest: gwRequest,
	})
	if err != nil {
		return nil, err
	}
	return network, nil
}

//List returns the network list
func (srv *NetworkService) List() ([]api.Network, error) {
	return srv.provider.ListNetworks()
}

//Get returns the network identified by ref, ref can be the name or the id
func (srv *NetworkService) Get(ref string) (*api.Network, error) {
	nets, err := srv.provider.ListNetworks()
	if err != nil {
		return nil, err
	}
	for _, n := range nets {
		if n.ID == ref || n.Name == ref {
			return &n, nil
		}
	}
	return nil, fmt.Errorf("Network %s does not exists", ref)
}

//Delete deletes network referenced by ref
func (srv *NetworkService) Delete(ref string) error {
	n, err := srv.Get(ref)
	if err != nil {
		return fmt.Errorf("Network %s does not exists", ref)
	}
	return srv.provider.DeleteNetwork(n.ID)
}
