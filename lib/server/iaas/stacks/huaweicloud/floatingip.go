/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

package huaweicloud

import (
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// ListOpts to define parameter of list
type ListOpts struct {
	Marker string `json:"marker,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

type bandwidthCreateOpts struct {
	Name       string `json:"name"`
	Size       int    `json:"size"`
	ShareType  string `json:"share_type"`
	ChargeMode string `json:"charge_mode,omitempty"`
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

type floatingIPPage struct {
	pagination.LinkedPageBase
}

// NextPageURL is invoked when a paginated collection of floating IPs has
// reached the end of a page and the pager seeks to traverse over a new one.
// In order to do this, it needs to construct the next page's URL.
func (r floatingIPPage) NextPageURL() (string, error) {
	var s struct {
		Links []gophercloud.Link `json:"floatingips_links"`
	}
	err := r.ExtractInto(&s)
	if err != nil {
		return "", err
	}
	return gophercloud.ExtractNextURL(s.Links)
}

// IsEmpty checks whether a FloatingIPPage struct is empty.
func (r floatingIPPage) IsEmpty() (bool, error) {
	is, err := extractFloatingIPs(r)
	return len(is) == 0, err
}

// extractFloatingIPs accepts a Page struct, specifically a FloatingIPPage
// struct, and extracts the elements into a slice of FloatingIP structs. In
// other words, a generic collection is mapped into a relevant slice.
func extractFloatingIPs(r pagination.Page) ([]FloatingIP, error) {
	var s struct {
		FloatingIPs []FloatingIP `json:"floatingips"`
	}
	err := (r.(floatingIPPage)).ExtractInto(&s)
	return s.FloatingIPs, err
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

// Result represents the result of a get operation. Call its Extract
// method to interpret it as a FloatingIP.
type getResult struct {
	commonResult
}

type deleteResult struct {
	gophercloud.ErrResult
}

// ListFloatingIPs lists all the floating IP currently requested for the VPC
func (s stack) ListFloatingIPs() pagination.Pager {
	if s.IsNull() {
		return pagination.Pager{}
	}

	url := s.Stack.NetworkClient.Endpoint + "v1/" + s.authOpts.ProjectID + "/publicips"
	return pagination.NewPager(s.Stack.NetworkClient, url, func(r pagination.PageResult) pagination.Page {
		return floatingIPPage{pagination.LinkedPageBase{PageResult: r}}
	})
}

// GetFloatingIP returns FloatingIP instance corresponding to ID 'id'
func (s stack) GetFloatingIP(id string) (*FloatingIP, fail.Error) {
	if s.IsNull() {
		return &FloatingIP{}, fail.InvalidInstanceError()
	}

	r := getResult{}
	url := s.Stack.NetworkClient.Endpoint + "v1/" + s.authOpts.ProjectID + "/publicips/" + id
	opts := gophercloud.RequestOpts{
		JSONResponse: &r.Body,
		OkCodes:      []int{200, 201},
	}
	commRetryErr := stacks.RetryableRemoteCall(
		func() error {
			_, err := s.Stack.Driver.Request("GET", url, &opts)
			r.Err = err
			return normalizeError(err)
		},
		normalizeError,
	)
	if commRetryErr != nil {
		return nil, commRetryErr
	}

	fip, err := r.Extract()
	if err != nil {
		return nil, normalizeError(err)
	}
	return fip, nil
}

// FindFloatingIPByIP returns FloatingIP instance associated with 'ipAddress'
func (s stack) FindFloatingIPByIP(ipAddress string) (*FloatingIP, error) {
	if s.IsNull() {
		return &FloatingIP{}, fail.InvalidInstanceError()
	}

	found := false
	fip := FloatingIP{}
	commRetryErr := stacks.RetryableRemoteCall(
		func() error {
			innerErr := s.ListFloatingIPs().EachPage(func(page pagination.Page) (bool, error) {
				list, err := extractFloatingIPs(page)
				if err != nil {
					return false, err
				}
				for _, i := range list {
					if i.PublicIPAddress == ipAddress {
						found = true
						fip = i
						return false, nil
					}
				}
				return true, nil
			})
			return normalizeError(innerErr)
		},
		normalizeError,
	)
	if commRetryErr != nil {
		return nil, commRetryErr
	}
	if found {
		return &fip, nil
	}
	return nil, abstract.ResourceNotFoundError("Floating IP", ipAddress)
}

// CreateFloatingIP creates a floating IP
func (s stack) CreateFloatingIP() (*FloatingIP, fail.Error) {
	if s.IsNull() {
		return &FloatingIP{}, fail.InvalidInstanceError()
	}

	ipOpts := ipCreateOpts{
		Type: "5_bgp",
	}
	bi, err := ipOpts.toFloatingIPCreateMap()
	if err != nil {
		return nil, normalizeError(err)
	}
	bandwidthOpts := bandwidthCreateOpts{
		Name:      "bandwidth-" + s.vpc.Name,
		Size:      1000,
		ShareType: "PER",
	}
	bb, err := bandwidthOpts.toBandwidthCreateMap()
	if err != nil {
		return nil, normalizeError(err)
	}
	// Merger bi in bb
	for k, v := range bi {
		bb[k] = v
	}

	r := createResult{}
	url := s.Stack.NetworkClient.Endpoint + "v1/" + s.authOpts.ProjectID + "/publicips"
	opts := gophercloud.RequestOpts{
		JSONBody:     bb,
		JSONResponse: &r.Body,
		OkCodes:      []int{200, 201},
	}
	commRetryErr := stacks.RetryableRemoteCall(
		func() error {
			_, innerErr := s.Stack.Driver.Request("POST", url, &opts)
			return normalizeError(innerErr)
		},
		normalizeError,
	)
	if commRetryErr != nil {
		return nil, commRetryErr
	}
	fip, err := r.Extract()
	if err != nil {
		return nil, normalizeError(err)
	}
	return fip, nil
}

// DeleteFloatingIP deletes a floating IP
func (s stack) DeleteFloatingIP(id string) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}

	r := deleteResult{}
	url := s.Stack.NetworkClient.Endpoint + "v1/" + s.authOpts.ProjectID + "/publicips/" + id
	opts := gophercloud.RequestOpts{
		JSONResponse: &r.Body,
		OkCodes:      []int{200, 201},
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, r.Err = s.Stack.Driver.Request("DELETE", url, &opts)
			err := r.ExtractErr()
			return normalizeError(err)
		},
		normalizeError,
	)
}

// AssociateFloatingIP associates a floating ip to an host
func (s stack) AssociateFloatingIP(host *abstract.HostCore, id string) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}

	fip, xerr := s.GetFloatingIP(id)
	if xerr != nil {
		return xerr
	}

	b := map[string]interface{}{
		"addFloatingIp": map[string]string{
			"address": fip.PublicIPAddress,
		},
	}

	return stacks.RetryableRemoteCall(
		func() error {
			r := servers.ActionResult{}
			_, r.Err = s.Stack.ComputeClient.Post(s.Stack.ComputeClient.ServiceURL("servers", host.ID, "action"), b, nil, nil)
			return normalizeError(r.ExtractErr())
		},
		normalizeError,
	)
}

// DissociateFloatingIP from host
func (s stack) DissociateFloatingIP(host *abstract.HostCore, id string) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}

	fip, xerr := s.GetFloatingIP(id)
	if xerr != nil {
		return xerr
	}

	b := map[string]interface{}{
		"removeFloatingIp": map[string]string{
			"address": fip.PublicIPAddress,
		},
	}

	return stacks.RetryableRemoteCall(
		func() error {
			r := servers.ActionResult{}
			_, r.Err = s.Stack.ComputeClient.Post(s.Stack.ComputeClient.ServiceURL("servers", host.ID, "action"), b, nil, nil)
			return normalizeError(r.ExtractErr())
		},
		normalizeError,
	)
}
