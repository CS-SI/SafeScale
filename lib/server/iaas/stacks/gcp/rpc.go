/*
 * Copyright 2018, CS Systemes d'Information, http://csgroup.eu
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

package gcp

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"google.golang.org/api/compute/v1"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// opContext ...
type opContext struct {
	Operation    *compute.Operation
	ProjectID    string
	Service      *compute.Service
	DesiredState string
}

// result ...
type result struct {
	State string
	Error error
	Done  bool
}

// refreshResult ...
func refreshResult(oco opContext) (res result, xerr fail.Error) {
	var err error
	res = result{}
	if oco.Operation != nil {
		if oco.Operation.Zone != "" { // nolint
			zoneURL, ierr := url.Parse(oco.Operation.Zone)
			if ierr != nil {
				return res, fail.ToError(ierr)
			}
			zone := getResourceNameFromSelfLink(*zoneURL)
			oco.Operation, err = oco.Service.ZoneOperations.Get(oco.ProjectID, zone, oco.Operation.Name).Do()
		} else if oco.Operation.Region != "" {
			regionURL, ierr := url.Parse(oco.Operation.Region)
			if ierr != nil {
				return res, fail.ToError(ierr)
			}
			region := getResourceNameFromSelfLink(*regionURL)
			oco.Operation, err = oco.Service.RegionOperations.Get(oco.ProjectID, region, oco.Operation.Name).Do()
		} else {
			oco.Operation, err = oco.Service.GlobalOperations.Get(oco.ProjectID, oco.Operation.Name).Do()
		}

		if oco.Operation == nil {
			if err == nil {
				return res, fail.NewError("no operation")
			}
			return res, fail.ToError(err)
		}

		res.State = oco.Operation.Status
		res.Error = err
		res.Done = res.State == oco.DesiredState

		return res, fail.ToError(err)
	}

	return res, fail.NewError("no operation")
}

func getResourceNameFromSelfLink(link SelfLink) string {
	stringRepr := link.String()
	parts := strings.Split(stringRepr, "/")
	return parts[len(parts)-1]
}

func getRegionFromSelfLink(link SelfLink) (string, fail.Error) {
	stringRepr := link.String()
	if strings.Contains(stringRepr, "regions") {
		parts := strings.Split(stringRepr, "/")
		regionPos := indexOf("regions", parts)
		if regionPos != -1 {
			if (regionPos + 1) < len(parts) {
				return parts[regionPos+1], nil
			}
		}
		return "", fail.NewError("not a region link")
	}
	return "", fail.InvalidRequestError("not a region link")
}

func indexOf(element string, data []string) int {
	for k, v := range data {
		if element == v {
			return k
		}
	}
	return -1 // not found.
}

func (s stack) rpcWaitUntilOperationIsSuccessfulOrTimeout(opp *compute.Operation, poll time.Duration, duration time.Duration) (xerr fail.Error) {
	oco := opContext{
		Operation:    opp,
		ProjectID:    s.GcpConfig.ProjectID,
		Service:      s.ComputeService,
		DesiredState: "DONE",
	}
	retryErr := retry.WhileUnsuccessful(func() error {
		r, anerr := refreshResult(oco)
		if anerr != nil {
			return anerr
		}
		if !r.Done {
			return fmt.Errorf("not finished yet")
		}
		return nil
	}, poll, duration)

	return fail.ToError(retryErr)
}

func (s stack) rpcGetSubnetByID(id string) (*compute.Subnetwork, fail.Error) {
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	var resp *compute.Subnetwork
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.ComputeService.Subnetworks.Get(s.GcpConfig.ProjectID, s.GcpConfig.Region, id).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}
	return resp, nil
}

func (s stack) rpcGetSubnetByName(subnetName string) (*compute.Subnetwork, fail.Error) {
	return s.rpcGetSubnetByNameAndRegion(subnetName, s.GcpConfig.Region)
}

func (s stack) rpcGetSubnetByNameAndRegion(subnetName, region string) (*compute.Subnetwork, fail.Error) {
	if subnetName == "" {
		return &compute.Subnetwork{}, fail.InvalidParameterError("subnetName", "cannot be empty string")
	}
	if region == "" {
		region = s.GcpConfig.Region
	}

	filter := `selfLink eq "` + s.selfLinkPrefix + `/regions/` + region + `/subnetworks/` + subnetName + `"`
	resp, xerr := s.rpcListSubnets(filter)
	if xerr != nil {
		return nil, xerr
	}
	if len(resp) == 0 {
		return &compute.Subnetwork{}, fail.NotFoundError("failed to find a Subnet named '%s' in region '%s'", subnetName, region)
	}
	if len(resp) > 1 {
		return nil, fail.InconsistentError("found more than one Subnet named '%s' in region '%s'", subnetName, region)
	}
	return resp[0], nil
}

func (s stack) rpcDeleteSubnetByName(name string) fail.Error {
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}

	var op *compute.Operation
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			op, err = s.ComputeService.Subnetworks.Delete(s.GcpConfig.ProjectID, s.GcpConfig.Region, name).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return xerr
	}

	return s.rpcWaitUntilOperationIsSuccessfulOrTimeout(op, temporal.GetMinDelay(), temporal.GetHostCleanupTimeout())
}

func (s stack) rpcCreateSubnet(subnetName, networkName, cidr string) (*compute.Subnetwork, fail.Error) {
	if subnetName = strings.TrimSpace(subnetName); subnetName == "" {
		return &compute.Subnetwork{}, fail.InvalidParameterError("subnetName", "cannot be empty string")
	}
	if networkName = strings.TrimSpace(networkName); networkName == "" {
		return &compute.Subnetwork{}, fail.InvalidParameterError("networkName", "cannot be empty string")
	}
	if cidr = strings.TrimSpace(cidr); cidr == "" {
		return &compute.Subnetwork{}, fail.InvalidParameterError("cidr", "cannot be empty string")
	}

	request := compute.Subnetwork{
		IpCidrRange: cidr,
		Name:        subnetName,
		Network:     s.selfLinkPrefix + "/global/networks/" + networkName,
		Region:      s.GcpConfig.Region,
	}
	var opp *compute.Operation
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			opp, err = s.ComputeService.Subnetworks.Insert(s.GcpConfig.ProjectID, s.GcpConfig.Region, &request).Context(context.Background()).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return &compute.Subnetwork{}, xerr
	}

	if err := s.rpcWaitUntilOperationIsSuccessfulOrTimeout(opp, temporal.GetMinDelay(), 2*temporal.GetContextTimeout()); err != nil {
		return &compute.Subnetwork{}, normalizeError(err)
	}

	return s.rpcGetSubnetByName(subnetName)
}

func (s stack) rpcListSubnets(filter string) ([]*compute.Subnetwork, fail.Error) {
	var (
		out  []*compute.Subnetwork
		resp *compute.SubnetworkList
	)
	for token := ""; ; {
		xerr := stacks.RetryableRemoteCall(
			func() (err error) {
				resp, err = s.ComputeService.Subnetworks.List(s.GcpConfig.ProjectID, s.GcpConfig.Region).Filter(filter).PageToken(token).Do()
				return err
			},
			normalizeError,
		)
		if xerr != nil {
			return nil, xerr
		}

		out = append(out, resp.Items...)
		if token = resp.NextPageToken; token == "" {
			break
		}
	}
	return out, nil
}

func (s stack) rpcGetFirewallRuleByName(name string) (*compute.Firewall, fail.Error) {
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	var resp *compute.Firewall
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.ComputeService.Firewalls.Get(s.GcpConfig.ProjectID, name).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}
	return resp, nil
}

func (s stack) rpcGetFirewallRuleByID(id string) (*compute.Firewall, fail.Error) {
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	filter := `id eq "` + id + `"`
	var resp *compute.FirewallList
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.ComputeService.Firewalls.List(s.GcpConfig.ProjectID).Filter(filter).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	if len(resp.Items) == 0 {
		return &compute.Firewall{}, fail.NotFoundError("failed to find a firewall rule with ID %s", id)
	}
	if len(resp.Items) > 1 {
		return &compute.Firewall{}, fail.InconsistentError("found more than one firewall rule with ID %s", id)
	}
	return resp.Items[0], nil
}

func (s stack) rpcCreateFirewallRule(ruleName, networkName, description, direction string, sourcesUseGroups bool, sources []string, targetsUseGroups bool, targets []string, allowed []*compute.FirewallAllowed, denied []*compute.FirewallDenied) (*compute.Firewall, fail.Error) {
	if ruleName == "" {
		return nil, fail.InvalidParameterError("ruleName", "cannot be empty string")
	}
	if networkName == "" {
		return nil, fail.InvalidParameterError("networkName", "cannot be empty string")
	}
	if direction == "" {
		return nil, fail.InvalidParameterError("direction", "cannot be empty string")
	}

	request := compute.Firewall{
		Direction:   direction,
		Disabled:    false,
		Name:        ruleName,
		Description: description,
		Network:     s.selfLinkPrefix + `/global/networks/` + networkName,
		Priority:    10000,
	}
	if len(allowed) > 0 {
		request.Allowed = allowed
	}
	if len(denied) > 0 {
		request.Denied = denied
	}
	if len(sources) > 0 {
		if sourcesUseGroups {
			request.SourceTags = sources
		} else {
			request.SourceRanges = sources
		}
	}
	if len(targets) > 0 {
		if targetsUseGroups {
			request.TargetTags = targets
		} else {
			request.DestinationRanges = targets
		}
	}

	var opp *compute.Operation
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			opp, err = s.ComputeService.Firewalls.Insert(s.GcpConfig.ProjectID, &request).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	if xerr = s.rpcWaitUntilOperationIsSuccessfulOrTimeout(opp, temporal.GetMinDelay(), temporal.GetHostTimeout()); xerr != nil {
		return nil, xerr
	}

	return s.rpcGetFirewallRuleByName(ruleName)
}

func (s stack) rpcListFirewallRules(networkRef string, ids []string) ([]*compute.Firewall, fail.Error) {
	if networkRef == "" && len(ids) == 0 {
		return []*compute.Firewall{}, fail.InvalidParameterError("networkRef", "cannot be empty string if 'ids' is an empty slice")
	}

	var filter string
	if len(ids) > 0 {
		for k, v := range ids {
			if k == 1 {
				filter = `(` + filter + `)`
			}
			if k > 0 {
				filter += ` OR `
			}
			filter += `(id eq "` + v + `")`
		}
	} else {
		filter = `network eq "` + s.selfLinkPrefix + `/global/networks/` + networkRef + `"`
	}

	var (
		resp *compute.FirewallList
		out  []*compute.Firewall
	)
	for token := ""; ; {
		xerr := stacks.RetryableRemoteCall(
			func() (err error) {
				resp, err = s.ComputeService.Firewalls.List(s.GcpConfig.ProjectID).Filter(filter).PageToken(token).Do()
				return err
			},
			normalizeError,
		)
		if xerr != nil {
			return []*compute.Firewall{}, xerr
		}
		if len(resp.Items) > 0 {
			out = append(out, resp.Items...)
		}
		if token = resp.NextPageToken; token == "" {
			break
		}
	}
	return out, nil
}

func (s stack) rpcDeleteFirewallRuleByID(id string) fail.Error {
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	var opp *compute.Operation
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			opp, err = s.ComputeService.Firewalls.Delete(s.GcpConfig.ProjectID, id).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return xerr
	}

	return s.rpcWaitUntilOperationIsSuccessfulOrTimeout(opp, temporal.GetMinDelay(), temporal.GetHostTimeout())
}

func (s stack) rpcEnableFirewallRuleByName(name string) fail.Error {
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}

	request := compute.Firewall{
		Disabled: false,
	}
	var opp *compute.Operation
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			opp, err = s.ComputeService.Firewalls.Patch(s.GcpConfig.ProjectID, name, &request).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return xerr
	}

	return s.rpcWaitUntilOperationIsSuccessfulOrTimeout(opp, temporal.GetMinDelay(), 2*temporal.GetContextTimeout())
}

func (s stack) rpcDisableFirewallRuleByName(name string) fail.Error {
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}

	request := compute.Firewall{
		Disabled: true,
	}
	var opp *compute.Operation
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			opp, err = s.ComputeService.Firewalls.Patch(s.GcpConfig.ProjectID, name, &request).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return xerr
	}

	return s.rpcWaitUntilOperationIsSuccessfulOrTimeout(opp, temporal.GetMinDelay(), 2*temporal.GetContextTimeout())
}

func (s stack) rpcGetNetworkByID(id string) (*compute.Network, fail.Error) {
	if id = strings.TrimSpace(id); id == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	var resp *compute.Network
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.ComputeService.Networks.Get(s.GcpConfig.ProjectID, id).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return &compute.Network{}, xerr
	}
	return resp, nil
}

func (s stack) rpcGetNetworkByName(name string) (*compute.Network, fail.Error) {
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	var resp *compute.Network
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.ComputeService.Networks.Get(s.GcpConfig.ProjectID, name).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return &compute.Network{}, xerr
	}
	return resp, nil
}

func (s stack) rpcCreateNetwork(name string) (*compute.Network, fail.Error) {
	request := compute.Network{
		Name:                  name,
		AutoCreateSubnetworks: false,
		ForceSendFields:       []string{"AutoCreateSubnetworks"},
	}
	var opp *compute.Operation
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			opp, err = s.ComputeService.Networks.Insert(s.GcpConfig.ProjectID, &request).Context(context.Background()).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	if xerr = s.rpcWaitUntilOperationIsSuccessfulOrTimeout(opp, temporal.GetMinDelay(), 2*temporal.GetContextTimeout()); xerr != nil {
		return nil, xerr
	}

	var out *compute.Network
	xerr = stacks.RetryableRemoteCall(
		func() (err error) {
			out, err = s.ComputeService.Networks.Get(s.GcpConfig.ProjectID, name).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}
	return out, nil
}

func (s stack) rpcGetRouteByName(name string) (*compute.Route, fail.Error) {
	if name = strings.TrimSpace(name); name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	var resp *compute.Route
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.ComputeService.Routes.Get(s.GcpConfig.ProjectID, name).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}
	return resp, nil
}

func (s stack) rpcCreateRoute(networkName, subnetName string) (*compute.Route, fail.Error) {
	if networkName == "" {
		return nil, fail.InvalidParameterError("networkName", "cannot be empty string")
	}
	if subnetName == "" {
		return nil, fail.InvalidParameterError("subnetName", "cannot be empty string")
	}

	routeName := fmt.Sprintf(natRouteNameFormat, networkName, subnetName)

	request := compute.Route{
		DestRange:       "0.0.0.0/0",
		Name:            routeName,
		Network:         fmt.Sprintf("%s/global/networks/%s", s.selfLinkPrefix, networkName),
		NextHopInstance: fmt.Sprintf("%s/zones/%s/instances/gw-%s", s.selfLinkPrefix, s.GcpConfig.Zone, subnetName),
		Priority:        800,
		Tags:            []string{fmt.Sprintf("no-ip-%s", subnetName)},
	}
	var opp *compute.Operation
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			opp, err = s.ComputeService.Routes.Insert(s.GcpConfig.ProjectID, &request).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	if xerr = s.rpcWaitUntilOperationIsSuccessfulOrTimeout(opp, temporal.GetMinDelay(), 2*temporal.GetContextTimeout()); xerr != nil {
		return nil, xerr
	}

	return s.rpcGetRouteByName(routeName)
}

func (s stack) rpcDeleteRoute(name string) fail.Error {
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}

	var opp *compute.Operation
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			opp, err = s.ComputeService.Routes.Delete(s.GcpConfig.ProjectID, name).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return xerr
	}

	return s.rpcWaitUntilOperationIsSuccessfulOrTimeout(opp, temporal.GetMinDelay(), temporal.GetHostCleanupTimeout())
}

var imageFamilies = []string{"centos-cloud", "debian-cloud", "rhel-cloud", "ubuntu-os-cloud", "suse-cloud", "rhel-sap-cloud", "suse-sap-cloud"}

func (s stack) rpcListImages() ([]*compute.Image, fail.Error) {
	var (
		out  []*compute.Image
		resp *compute.ImageList
	)
	filter := `deprecated.replacement ne .*images.*`
	for _, f := range imageFamilies {
		for token := ""; ; {
			xerr := stacks.RetryableRemoteCall(
				func() (err error) {
					resp, err = s.ComputeService.Images.List(f).Filter(filter).PageToken(token).Do()
					return err
				},
				normalizeError,
			)
			if xerr != nil {
				return []*compute.Image{}, xerr
			}
			out = append(out, resp.Items...)
			if token = resp.NextPageToken; token == "" {
				break
			}
		}
	}
	return out, nil
}

func (s stack) rpcGetImageByID(id string) (*compute.Image, fail.Error) {
	if id == "" {
		return &compute.Image{}, fail.InvalidParameterError("id", "cannot be empty string")
	}

	var (
		out  []*compute.Image
		resp *compute.ImageList
	)
	filter := `id eq "` + id + `"`
	for _, f := range imageFamilies {
		for token := ""; ; {
			xerr := stacks.RetryableRemoteCall(
				func() (err error) {
					resp, err = s.ComputeService.Images.List(f).Filter(filter).PageToken(token).Do()
					return err
				},
				normalizeError,
			)
			if xerr != nil {
				return &compute.Image{}, xerr
			}
			out = append(out, resp.Items...)
			if token = resp.NextPageToken; token == "" {
				break
			}
		}
	}
	if len(out) == 0 {
		return &compute.Image{}, fail.NotFoundError("failed to find Image with ID %s", id)
	}
	if len(out) > 1 {
		return &compute.Image{}, fail.InconsistentError("found more than one Image with ID %s", id)
	}
	return out[0], nil
}

func (s stack) rpcListMachineTypes() ([]*compute.MachineType, fail.Error) {
	var (
		out  []*compute.MachineType
		resp *compute.MachineTypeList
	)
	for token := ""; ; {
		xerr := stacks.RetryableRemoteCall(
			func() (err error) {
				resp, err = s.ComputeService.MachineTypes.List(s.GcpConfig.ProjectID, s.GcpConfig.Zone).PageToken(token).Do()
				return err
			},
			normalizeError,
		)
		if xerr != nil {
			return []*compute.MachineType{}, xerr
		}
		out = append(out, resp.Items...)
		if token = resp.NextPageToken; token == "" {
			break
		}
	}
	return out, nil
}

func (s stack) rpcGetMachineType(id string) (*compute.MachineType, fail.Error) {
	if id == "" {
		return &compute.MachineType{}, fail.InvalidParameterError("id", "cannot be empty string")
	}

	var resp *compute.MachineType
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.ComputeService.MachineTypes.Get(s.GcpConfig.ProjectID, s.GcpConfig.Zone, id).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return &compute.MachineType{}, xerr
	}
	return resp, nil
}

func (s stack) rpcListInstances() ([]*compute.Instance, fail.Error) {
	var (
		out  []*compute.Instance
		resp *compute.InstanceList
	)
	for token := ""; ; {
		xerr := stacks.RetryableRemoteCall(
			func() (err error) {
				resp, err = s.ComputeService.Instances.List(s.GcpConfig.ProjectID, s.GcpConfig.Zone).PageToken(token).Do()
				return err
			},
			normalizeError,
		)
		if xerr != nil {
			return []*compute.Instance{}, xerr
		}
		if len(resp.Items) > 0 {
			out = append(out, resp.Items...)
		}
		if token = resp.NextPageToken; token == "" {
			break
		}
	}
	return out, nil
}

func (s stack) rpcCreateInstance(name, networkName, subnetName, templateName, imageURL string, diskSize int64, userdata string, hasPublicIP bool, sgs []string) (*compute.Instance, fail.Error) {
	tags := sgs
	// Add nat route name as tag to host that has a public IP
	if hasPublicIP {
		tags = append(tags, fmt.Sprintf(natRouteNameFormat, networkName, subnetName))
	}

	request := compute.Instance{
		Name:         name,
		Description:  name,
		MachineType:  s.selfLinkPrefix + "/zones/" + s.GcpConfig.Zone + "/machineTypes/" + templateName,
		CanIpForward: hasPublicIP,
		Tags: &compute.Tags{
			Items: tags,
		},
		Disks: []*compute.AttachedDisk{
			{
				AutoDelete: true,
				Boot:       true,
				Type:       "PERSISTENT",
				InitializeParams: &compute.AttachedDiskInitializeParams{
					DiskName:    fmt.Sprintf("%s-disk", name),
					SourceImage: imageURL,
					DiskSizeGb:  diskSize,
				},
			},
		},
		NetworkInterfaces: []*compute.NetworkInterface{
			{
				AccessConfigs: publicAccess(hasPublicIP),
				Network:       s.selfLinkPrefix + "/global/networks/" + networkName,
				Subnetwork:    s.selfLinkPrefix + "/regions/" + s.GcpConfig.Region + "/subnetworks/" + subnetName,
			},
		},
		ServiceAccounts: []*compute.ServiceAccount{
			{
				Email: "default",
				Scopes: []string{
					compute.DevstorageFullControlScope,
					compute.ComputeScope,
				},
			},
		},
		Metadata: &compute.Metadata{
			Items: []*compute.MetadataItems{
				{
					Key:   "startup-script",
					Value: &userdata,
				},
			},
		},
	}

	var op *compute.Operation
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			op, err = s.ComputeService.Instances.Insert(s.GcpConfig.ProjectID, s.GcpConfig.Zone, &request).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return &compute.Instance{}, xerr
	}

	etag := op.Header.Get("Etag")
	if xerr = s.rpcWaitUntilOperationIsSuccessfulOrTimeout(op, temporal.GetMinDelay(), temporal.GetHostTimeout()); xerr != nil {
		return &compute.Instance{}, xerr
	}

	var resp *compute.Instance
	xerr = stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.ComputeService.Instances.Get(s.GcpConfig.ProjectID, s.GcpConfig.Zone, name).IfNoneMatch(etag).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return &compute.Instance{}, xerr
	}
	return resp, nil
}

func publicAccess(isPublic bool) []*compute.AccessConfig {
	if isPublic {
		return []*compute.AccessConfig{
			{
				Type: "ONE_TO_ONE_NAT",
				Name: "External NAT",
			},
		}
	}

	return []*compute.AccessConfig{}
}

func (s stack) rpcGetInstance(ref string) (*compute.Instance, fail.Error) {
	if ref == "" {
		return &compute.Instance{}, fail.InvalidParameterError("ref", "cannot be empty string")
	}

	var resp *compute.Instance
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.ComputeService.Instances.Get(s.GcpConfig.ProjectID, s.GcpConfig.Zone, ref).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return &compute.Instance{}, xerr
	}
	return resp, nil
}

func (s stack) rpcDeleteInstance(ref string) fail.Error {
	var op *compute.Operation
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			op, err = s.ComputeService.Instances.Delete(s.GcpConfig.ProjectID, s.GcpConfig.Zone, ref).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return xerr
	}

	return s.rpcWaitUntilOperationIsSuccessfulOrTimeout(op, temporal.GetMinDelay(), temporal.GetHostCleanupTimeout())
}

func (s stack) rpcStopInstance(ref string) fail.Error {
	if ref == "" {
		return fail.InvalidParameterError("ref", "cannot be empty string")
	}

	var op *compute.Operation
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			op, err = s.ComputeService.Instances.Stop(s.GcpConfig.ProjectID, s.GcpConfig.Zone, ref).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return xerr
	}

	return s.rpcWaitUntilOperationIsSuccessfulOrTimeout(op, temporal.GetMinDelay(), temporal.GetHostTimeout())
}

func (s stack) rpcStartInstance(ref string) fail.Error {
	if ref == "" {
		return fail.InvalidParameterError("ref", "cannot be empty string")
	}

	var op *compute.Operation
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			op, err = s.ComputeService.Instances.Start(s.GcpConfig.ProjectID, s.GcpConfig.Zone, ref).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return xerr
	}

	return s.rpcWaitUntilOperationIsSuccessfulOrTimeout(op, temporal.GetMinDelay(), temporal.GetHostTimeout())
}

func (s stack) rpcListZones() ([]*compute.Zone, fail.Error) {
	var (
		resp            *compute.ZoneList
		out, emptySlice []*compute.Zone
	)
	for token := ""; ; {
		xerr := stacks.RetryableRemoteCall(
			func() (err error) {
				resp, err = s.ComputeService.Zones.List(s.GcpConfig.ProjectID).PageToken(token).Do()
				return err
			},
			normalizeError,
		)
		if xerr != nil {
			return emptySlice, xerr
		}
		out = append(out, resp.Items...)
		if token = resp.NextPageToken; token == "" {
			break
		}
	}
	return out, nil
}

func (s stack) rpcListRegions() ([]*compute.Region, fail.Error) {
	var (
		out  []*compute.Region
		resp *compute.RegionList
	)
	for token := ""; ; {
		xerr := stacks.RetryableRemoteCall(
			func() (err error) {
				resp, err = s.ComputeService.Regions.List(s.GcpConfig.ProjectID).PageToken(token).Do()
				return err
			},
			normalizeError,
		)
		if xerr != nil {
			return []*compute.Region{}, xerr
		}
		out = append(out, resp.Items...)
		if token = resp.NextPageToken; token == "" {
			break
		}
	}
	return out, nil
}

func (s stack) rpcAddTagsToInstance(hostID string, tags []string) fail.Error {
	if hostID == "" {
		return fail.InvalidParameterError("hostID", "cannot be empty string")
	}
	if len(tags) == 0 {
		return fail.InvalidParameterError("tags", "cannot be empty slice")
	}

	var resp *compute.Instance
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.ComputeService.Instances.Get(s.GcpConfig.ProjectID, s.GcpConfig.Zone, hostID).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return xerr
	}

	newTags := resp.Tags
	for _, v := range tags {
		// If tag is already present, do nothing
		for _, w := range newTags.Items {
			if v == w {
				break
			}
		}
		newTags.Items = append(newTags.Items, v)
	}
	if len(newTags.Items) == len(resp.Tags.Items) {
		return nil
	}

	var opp *compute.Operation
	xerr = stacks.RetryableRemoteCall(
		func() (err error) {
			opp, err = s.ComputeService.Instances.SetTags(s.GcpConfig.ProjectID, s.GcpConfig.Zone, hostID, newTags).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return xerr
	}

	return s.rpcWaitUntilOperationIsSuccessfulOrTimeout(opp, temporal.GetMinDelay(), 2*temporal.GetContextTimeout())
}

func (s stack) rpcRemoveTagsFromInstance(hostID string, tags []string) fail.Error {
	if hostID == "" {
		return fail.InvalidParameterError("hostID", "cannot be empty string")
	}
	if len(tags) == 0 {
		return fail.InvalidParameterError("tags", "cannot be empty slice")
	}

	var resp *compute.Instance
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.ComputeService.Instances.Get(s.GcpConfig.ProjectID, s.GcpConfig.Zone, hostID).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return xerr
	}

	newTags := resp.Tags
	newTags.Items = make([]string, len(resp.Tags.Items))
	for _, v := range resp.Tags.Items {
		// If tag is present, remove it by not copying it
		for _, w := range tags {
			if v != w {
				newTags.Items = append(newTags.Items, v)
			}
		}
	}
	if len(newTags.Items) == len(resp.Tags.Items) {
		return nil
	}

	var opp *compute.Operation
	xerr = stacks.RetryableRemoteCall(
		func() (err error) {
			opp, err = s.ComputeService.Instances.SetTags(s.GcpConfig.ProjectID, s.GcpConfig.Zone, hostID, newTags).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return xerr
	}

	return s.rpcWaitUntilOperationIsSuccessfulOrTimeout(opp, temporal.GetMinDelay(), 2*temporal.GetContextTimeout())
}

func (s stack) rpcListNetworks() (_ []*compute.Network, xerr fail.Error) {
	var (
		out  []*compute.Network
		resp *compute.NetworkList
	)
	for token := ""; ; {
		xerr = stacks.RetryableRemoteCall(
			func() (err error) {
				resp, err = s.ComputeService.Networks.List(s.GcpConfig.ProjectID).PageToken(token).Do()
				return err
			},
			normalizeError,
		)
		if xerr != nil {
			return []*compute.Network{}, xerr
		}

		out = append(out, resp.Items...)
		token = resp.NextPageToken
		if token == "" {
			break
		}
	}
	return out, nil
}

func (s stack) rpcDeleteNetworkByID(id string) (xerr fail.Error) {
	if id = strings.TrimSpace(id); id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	var resp *compute.Operation
	xerr = stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.ComputeService.Networks.Delete(s.GcpConfig.ProjectID, id).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return xerr
	}
	if resp == nil {
		return fail.NotFoundError("failed to find Network with ID %s", id)
	}

	return s.rpcWaitUntilOperationIsSuccessfulOrTimeout(resp, temporal.GetMinDelay(), 2*temporal.GetContextTimeout())
}

func (s stack) rpcCreateDisk(name, kind string, size int64) (*compute.Disk, fail.Error) {
	request := compute.Disk{
		Name:   name,
		Region: s.GcpConfig.Region,
		SizeGb: size,
		Type:   kind,
		Zone:   s.GcpConfig.Zone,
	}
	var op *compute.Operation
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			op, err = s.ComputeService.Disks.Insert(s.GcpConfig.ProjectID, s.GcpConfig.Zone, &request).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return &compute.Disk{}, xerr
	}

	if xerr = s.rpcWaitUntilOperationIsSuccessfulOrTimeout(op, temporal.GetMinDelay(), temporal.GetHostTimeout()); xerr != nil {
		return &compute.Disk{}, xerr
	}

	return s.rpcGetDisk(name)
}

func (s stack) rpcGetDisk(ref string) (*compute.Disk, fail.Error) {
	if ref == "" {
		return &compute.Disk{}, fail.InvalidParameterError("ref", "cannot be empty string")
	}

	var resp *compute.Disk
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.ComputeService.Disks.Get(s.GcpConfig.ProjectID, s.GcpConfig.Zone, ref).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return &compute.Disk{}, xerr
	}
	if resp == nil {
		return &compute.Disk{}, fail.NotFoundError("failed to find Volume named '%s'", ref)
	}
	return resp, nil
}

func (s stack) rpcDeleteDisk(ref string) fail.Error {
	if ref == "" {
		return fail.InvalidParameterError("ref", "cannot be empty string")
	}
	var op *compute.Operation
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			op, err = s.ComputeService.Disks.Delete(s.GcpConfig.ProjectID, s.GcpConfig.Zone, ref).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return xerr
	}

	return s.rpcWaitUntilOperationIsSuccessfulOrTimeout(op, temporal.GetMinDelay(), temporal.GetHostTimeout())
}

func (s stack) rpcCreateDiskAttachment(diskRef, hostRef string) (string, fail.Error) {
	if diskRef == "" {
		return "", fail.InvalidParameterError("diskRef", "cannot be empty string")
	}
	if hostRef == "" {
		return "", fail.InvalidParameterError("hostRef", "cannot be empty string")
	}

	instance, xerr := s.rpcGetInstance(hostRef)
	if xerr != nil {
		return "", xerr
	}

	disk, xerr := s.rpcGetDisk(diskRef)
	if xerr != nil {
		return "", xerr
	}

	request := compute.AttachedDisk{
		DeviceName: disk.Name,
		Source:     disk.SelfLink,
	}
	var op *compute.Operation
	xerr = stacks.RetryableRemoteCall(
		func() (err error) {
			op, err = s.ComputeService.Instances.AttachDisk(s.GcpConfig.ProjectID, s.GcpConfig.Zone, instance.Name, &request).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return "", xerr
	}

	if xerr = s.rpcWaitUntilOperationIsSuccessfulOrTimeout(op, temporal.GetMinDelay(), temporal.GetHostTimeout()); xerr != nil {
		return "", xerr
	}

	return generateDiskAttachmentID(instance.Name, disk.Name), nil
}

func (s stack) rpcDeleteDiskAttachment(vaID string) fail.Error {
	if vaID == "" {
		return fail.InvalidParameterError("vaID", "cannot be empty string")
	}
	serverName, diskName := extractFromAttachmentID(vaID)
	if serverName == "" || diskName == "" {
		return fail.SyntaxError("the content of 'vaID' does not represent an ID for a Volume attachment")
	}
	var op *compute.Operation
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			op, err = s.ComputeService.Instances.DetachDisk(s.GcpConfig.ProjectID, s.GcpConfig.Zone, serverName, diskName).Do()
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return xerr
	}

	return s.rpcWaitUntilOperationIsSuccessfulOrTimeout(op, temporal.GetMinDelay(), temporal.GetHostTimeout())
}
