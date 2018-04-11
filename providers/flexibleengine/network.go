package flexibleengine

import (
	"fmt"

	gc "github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/pagination"
)

//RouterRequest represents a router request
type VPCRequest struct {
	Name string `json:"name"`
	//CIDR is the CIDR of the VPC, in which networks/subnets will be created
	CIDR string `json:"cidr"`
}

//VPC represents a Virtual Private Cloud
type VPC struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	//CIDR is the CIDR of the VPC, in which networks/subnets will be created
	CIDR   string `json:"cidr"`
	Status string `json:"status",omitempty`
}

type commonResult struct {
	gc.Result
}

// Extract is a function that accepts a result and extracts a VPC.
func (r commonResult) Extract() (*VPC, error) {
	var s struct {
		VPC *VPC `json:"vpc"`
	}
	err := r.ExtractInto(&s)
	return s.VPC, err
}

type createResult struct {
	commonResult
}
type getResult struct {
	commonResult
}
type deleteResult struct {
	gc.ErrResult
}

//CreateVPC creates a network named name
func (client *Client) CreateVPC(req VPCRequest) (*VPC, error) {
	b, err := gc.BuildRequestBody(req, "vpc")
	if err != nil {
		return nil, fmt.Errorf("Error creating VPC %s: %s", req.Name, errorString(err))
	}

	resp := createResult{}
	url := client.Network.Endpoint + "v1/" + client.Opts.ProjectID + "/vpcs"
	opts := gc.RequestOpts{
		JSONBody:     b,
		JSONResponse: &resp.Body,
		OkCodes:      []int{200, 201},
	}
	_, err = client.Provider.Request("POST", url, &opts)
	if err != nil {
		return nil, fmt.Errorf("Error creating VPC %s: %s", req.Name, errorString(err))
	}
	vpc, err := resp.Extract()
	if err != nil {
		return nil, fmt.Errorf("Error creating VPC %s: %s", req.Name, errorString(err))
	}
	return vpc, nil
}

//GetVPC returns the information about the VPC
func (client *Client) GetVPC(id string) (*VPC, error) {
	r := getResult{}
	url := client.Network.Endpoint + "v1/" + client.Opts.ProjectID + "/vpcs/" + id
	opts := gc.RequestOpts{
		JSONResponse: &r.Body,
		OkCodes:      []int{200, 201},
	}
	_, err := client.Provider.Request("POST", url, &opts)
	r.Err = err
	if err != nil {
		return nil, fmt.Errorf("Error getting VPC %s: %s", id, errorString(err))
	}
	vpc, err := r.Extract()
	if err != nil {
		return nil, fmt.Errorf("Error getting VPC %s: %s", id, errorString(err))
	}
	return vpc, nil
}

//FindVPC returns the information about the VPC by its name
func (client *Client) FindVPC(name string) (*VPC, error) {
	vpc := routers.Router{}
	found := false
	err := routers.List(client.Network, routers.ListOpts{}).EachPage(func(page pagination.Page) (bool, error) {
		list, err := routers.ExtractRouters(page)
		if err != nil {
			return false, err
		}
		for _, r := range list {
			if r.Name == client.Opts.VPCName {
				vpc = r
				found = true
				return false, nil
			}
		}
		return true, nil
	})
	if err != nil {
		return nil, fmt.Errorf("Error listing routers: %s", errorString(err))
	}
	if found {
		return client.GetVPC(vpc.ID)
	}
	return nil, nil
}

//DeleteVPC deletes a Virtual Private Cloud
func (client *Client) DeleteVPC(vpc string) error {
	return fmt.Errorf("flexibleengine.DeleteVPC() not implemented!")
}
