package openstack

import (
	"fmt"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/floatingips"
)

type bandwidthCreateOpts struct {
	Name       string `json:"name"`
	Size       int    `json:"size"`
	ShareType  string `json:"share_type"`
	ChargeMode string `json:"charge_mode,omitempty"`
}

type commonResult struct {
	gophercloud.Result
}

// Extract will extract a FloatingIP resource from a result.
func (r commonResult) Extract() (*FloatingIP, error) {
	var s struct {
		FloatingIP *FloatingIP `json:"publicip"`
	}
	err := r.ExtractInto(&s)
	return s.FloatingIP, err
}

// CreateResult represents the result of a create operation. Call its Extract
// method to interpret it as a FloatingIP.
type createResult struct {
	commonResult
}

func (opts bandwidthCreateOpts) toBandwidthCreateMap() (map[string]interface{}, error) {
	return gophercloud.BuildRequestBody(opts, "bandwidth")
}

type ipCreateOpts struct {
	Type      string `json:"type"`
	IPAddress string `json:"ip_address,omitempty"`
}

func (opts ipCreateOpts) toFloatingIPCreateMap() (map[string]interface{}, error) {
	return gophercloud.BuildRequestBody(opts, "publicip")
}

// FloatingIP represents a FlexibleEngine Floating IP
type FloatingIP struct {
	ID              string `json:"id"`
	Status          string `json:"status"`
	Type            string `json:"type"`
	PublicIPAddress string `json:"public_ip_address"`
	TenantID        string `json:"tenant_id"`
	CreateTime      string `json:"create_time"`
	BandwidthSize   int    `json:"bandwidth_size"`
}

// CreateFloatingIP creates a floating IP
func (s *Stack) CreateFloatingIP() (*FloatingIP, error) {
	ipOpts := ipCreateOpts{
		Type: "5_bgp",
	}
	bi, err := ipOpts.toFloatingIPCreateMap()
	if err != nil {
		return nil, scerr.Errorf(
			fmt.Sprintf(
				"failed to build request to create FloatingIP: %s", ProviderErrorToString(err),
			), err,
		)
	}
	bandwidthOpts := bandwidthCreateOpts{
		Name:      "bandwidth-" + "thing",
		Size:      1000,
		ShareType: "PER",
	}
	bb, err := bandwidthOpts.toBandwidthCreateMap()
	if err != nil {
		return nil, scerr.Errorf(
			fmt.Sprintf(
				"failed to build request to create FloatingIP: %s", ProviderErrorToString(err),
			), err,
		)
	}
	// Merger bi in bb
	for k, v := range bi {
		bb[k] = v
	}

	r := createResult{}
	url := s.NetworkClient.Endpoint + "v1/" + s.authOpts.ProjectID + "/publicips"
	opts := gophercloud.RequestOpts{
		JSONBody:     bb,
		JSONResponse: &r.Body,
		OkCodes:      []int{200, 201},
	}
	_, err = s.Driver.Request("POST", url, &opts)
	if err != nil {
		return nil, scerr.Errorf(
			fmt.Sprintf(
				"failed to request Floating IP creation: %s", ProviderErrorToString(err),
			), err,
		)
	}
	fip, err := r.Extract()
	if err != nil {
		return nil, scerr.Errorf(fmt.Sprintf("failed to create Floating IP: %s", err), err)
	}
	return fip, nil
}

// getFloatingIP returns the floating IP associated with the host identified by hostID
// By convention only one floating IP is allocated to an host
func (s *Stack) getFloatingIP(hostID string) (*floatingips.FloatingIP, error) {
	var fips []floatingips.FloatingIP

	pager := floatingips.List(s.ComputeClient)
	retryErr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			err := pager.EachPage(
				func(page pagination.Page) (bool, error) {
					list, err := floatingips.ExtractFloatingIPs(page)
					if err != nil {
						return false, err
					}

					for _, fip := range list {
						if fip.InstanceID == hostID {
							fips = append(fips, fip)
						}
					}
					return true, nil
				},
			)
			return err
		},
		temporal.GetDefaultDelay()*2,
	)
	if len(fips) == 0 {
		if retryErr != nil {
			return nil, scerr.NotFoundError(
				fmt.Sprintf(
					"no floating IP found for host '%s': %s", hostID, ProviderErrorToString(retryErr),
				),
			)
		}
		return nil, scerr.NotFoundError(fmt.Sprintf("no floating IP found for host '%s'", hostID))
	}
	if len(fips) > 1 {
		return nil, scerr.InconsistentError(
			fmt.Sprintf(
				"Configuration error, more than one Floating IP associated to host '%s'", hostID,
			),
		)
	}
	return &fips[0], nil
}
