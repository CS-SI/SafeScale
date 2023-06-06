/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/sirupsen/logrus"

	"google.golang.org/api/compute/v1"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
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
func refreshResult(oco opContext) (res result, ferr fail.Error) {
	var err error
	res = result{}
	if oco.Operation != nil {
		if oco.Operation.Zone != "" { // nolint
			zoneURL, ierr := url.Parse(oco.Operation.Zone)
			if ierr != nil {
				return res, fail.ConvertError(ierr)
			}

			zone := getResourceNameFromSelfLink(*zoneURL)
			oco.Operation, err = oco.Service.ZoneOperations.Get(oco.ProjectID, zone, oco.Operation.Name).Do()
			if err != nil {
				return res, fail.ConvertError(err)
			}
		} else if oco.Operation.Region != "" {
			regionURL, ierr := url.Parse(oco.Operation.Region)
			if ierr != nil {
				return res, fail.ConvertError(ierr)
			}

			region := getResourceNameFromSelfLink(*regionURL)
			oco.Operation, err = oco.Service.RegionOperations.Get(oco.ProjectID, region, oco.Operation.Name).Do()
			if err != nil {
				return res, fail.ConvertError(err)
			}
		} else {
			oco.Operation, err = oco.Service.GlobalOperations.Get(oco.ProjectID, oco.Operation.Name).Do()
			if err != nil {
				return res, fail.ConvertError(err)
			}
		}

		if oco.Operation == nil {
			return res, fail.NewError("no operation")
		}

		res.State = oco.Operation.Status
		if oco.Operation.Error != nil {
			res.Error = normalizeOperationError(oco.Operation.Error)
		}
		res.Done = res.State == oco.DesiredState

		return res, fail.ConvertError(res.Error)
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

func (s stack) rpcWaitUntilOperationIsSuccessfulOrTimeout(opp *compute.Operation, poll time.Duration, duration time.Duration) (ferr fail.Error) {
	if opp == nil {
		return fail.InvalidParameterCannotBeNilError("opp")
	}
	oco := opContext{
		Operation:    opp,
		ProjectID:    s.GcpConfig.ProjectID,
		Service:      s.ComputeService,
		DesiredState: "DONE",
	}
	retryErr := retry.WhileUnsuccessful(
		func() error {
			r, anerr := refreshResult(oco)
			if anerr != nil {
				return anerr
			}

			if !r.Done {
				return fmt.Errorf("not finished yet")
			}
			return nil
		},
		poll,
		duration,
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrStopRetry: // here it should never happen
			return fail.Wrap(fail.Cause(retryErr), "stopping retries")
		case *retry.ErrTimeout:
			return fail.Wrap(fail.Cause(retryErr), "timeout")
		default:
			return retryErr
		}
	}

	return nil
}

func (s stack) rpcGetSubnetByID(ctx context.Context, id string) (*compute.Subnetwork, fail.Error) {
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	var resp *compute.Subnetwork
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.ComputeService.Subnetworks.Get(s.GcpConfig.ProjectID, s.GcpConfig.Region, id).Do()
			if err != nil {
				return err
			}
			if resp != nil {
				if resp.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", resp.HTTPStatusCode)
					return fail.NewError("received http error code %d", resp.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return nil, fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return nil, fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return nil, xerr
		}
	}
	return resp, nil
}

func (s stack) rpcGetSubnetByName(ctx context.Context, subnetName string) (*compute.Subnetwork, fail.Error) {
	return s.rpcGetSubnetByNameAndRegion(ctx, subnetName, s.GcpConfig.Region)
}

func (s stack) rpcGetSubnetByNameAndRegion(ctx context.Context, subnetName string, region string) (*compute.Subnetwork, fail.Error) {
	if subnetName == "" {
		return &compute.Subnetwork{}, fail.InvalidParameterError("subnetName", "cannot be empty string")
	}
	if region == "" {
		region = s.GcpConfig.Region
	}

	filter := `selfLink eq "` + s.selfLinkPrefix + `/regions/` + region + `/subnetworks/` + subnetName + `"`
	resp, xerr := s.rpcListSubnets(ctx, filter)
	if xerr != nil {
		return nil, xerr
	}
	if len(resp) == 0 {
		return &compute.Subnetwork{}, fail.NotFoundError(
			"failed to find a Subnet named '%s' in region '%s'", subnetName, region,
		)
	}
	if len(resp) > 1 {
		return nil, fail.InconsistentError("found more than one Subnet named '%s' in region '%s'", subnetName, region)
	}
	return resp[0], nil
}

func (s stack) rpcDeleteSubnetByName(ctx context.Context, name string) fail.Error {
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}

	timings, xerr := s.Timings()
	if xerr != nil {
		return xerr
	}

	var op *compute.Operation
	xerr = stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			op, err = s.ComputeService.Subnetworks.Delete(s.GcpConfig.ProjectID, s.GcpConfig.Region, name).Do()
			if err != nil {
				return err
			}
			if op != nil {
				if op.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", op.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return xerr
		}
	}

	return s.rpcWaitUntilOperationIsSuccessfulOrTimeout(op, timings.SmallDelay(), timings.HostCleanupTimeout())
}

func (s stack) rpcCreateSubnet(ctx context.Context, subnetName string, networkName, cidr string) (*compute.Subnetwork, fail.Error) {
	if subnetName = strings.TrimSpace(subnetName); subnetName == "" {
		return &compute.Subnetwork{}, fail.InvalidParameterError("subnetName", "cannot be empty string")
	}
	if networkName = strings.TrimSpace(networkName); networkName == "" {
		return &compute.Subnetwork{}, fail.InvalidParameterError("networkName", "cannot be empty string")
	}
	if cidr = strings.TrimSpace(cidr); cidr == "" {
		return &compute.Subnetwork{}, fail.InvalidParameterError("cidr", "cannot be empty string")
	}

	timings, xerr := s.Timings()
	if xerr != nil {
		return &compute.Subnetwork{}, xerr
	}

	request := compute.Subnetwork{
		IpCidrRange: cidr,
		Name:        subnetName,
		Network:     s.selfLinkPrefix + "/global/networks/" + networkName,
		Region:      s.GcpConfig.Region,
	}
	var opp *compute.Operation
	xerr = stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			opp, err = s.ComputeService.Subnetworks.Insert(
				s.GcpConfig.ProjectID, s.GcpConfig.Region, &request,
			).Context(context.Background()).Do()
			if err != nil {
				return err
			}
			if opp != nil {
				if opp.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", opp.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return &compute.Subnetwork{}, fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return &compute.Subnetwork{}, fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return &compute.Subnetwork{}, xerr
		}
	}

	if err := s.rpcWaitUntilOperationIsSuccessfulOrTimeout(opp, timings.SmallDelay(), 2*timings.ContextTimeout()); err != nil {
		return &compute.Subnetwork{}, normalizeError(err)
	}

	return s.rpcGetSubnetByName(ctx, subnetName)
}

func (s stack) rpcListSubnets(ctx context.Context, filter string) ([]*compute.Subnetwork, fail.Error) {
	var (
		out  []*compute.Subnetwork
		resp *compute.SubnetworkList
	)
	for token := ""; ; {
		xerr := stacks.RetryableRemoteCall(ctx,
			func() (err error) {
				resp, err = s.ComputeService.Subnetworks.List(
					s.GcpConfig.ProjectID, s.GcpConfig.Region,
				).Filter(filter).PageToken(token).Do()
				if err != nil {
					return err
				}
				if resp != nil {
					if resp.HTTPStatusCode != 200 {
						logrus.WithContext(ctx).Tracef("received http error code %d", resp.HTTPStatusCode)
						return fail.NewError("received http error code %d", resp.HTTPStatusCode)
					}
				}
				return err
			},
			normalizeError,
		)
		if xerr != nil {
			switch xerr.(type) {
			case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
				return nil, fail.Wrap(fail.Cause(xerr), "stopping retries")
			case *retry.ErrTimeout: // On timeout, we keep the last error as cause
				return nil, fail.Wrap(fail.Cause(xerr), "timeout")
			default:
				return nil, xerr
			}
		}

		out = append(out, resp.Items...)
		if token = resp.NextPageToken; token == "" {
			break
		}
	}
	return out, nil
}

func (s stack) rpcGetFirewallRuleByName(ctx context.Context, name string) (*compute.Firewall, fail.Error) {
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	var resp *compute.Firewall
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.ComputeService.Firewalls.Get(s.GcpConfig.ProjectID, name).Do()
			if err != nil {
				return err
			}
			if resp != nil {
				if resp.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", resp.HTTPStatusCode)
					return fail.NewError("received http error code %d", resp.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return nil, fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return nil, fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return nil, xerr
		}
	}
	return resp, nil
}

func (s stack) rpcGetFirewallRuleByID(ctx context.Context, id string) (*compute.Firewall, fail.Error) {
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	filter := `id eq "` + id + `"`
	var resp *compute.FirewallList
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.ComputeService.Firewalls.List(s.GcpConfig.ProjectID).Filter(filter).Do()
			if err != nil {
				return err
			}
			if resp != nil {
				if resp.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", resp.HTTPStatusCode)
					return fail.NewError("received http error code %d", resp.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return nil, fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return nil, fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return nil, xerr
		}
	}

	if len(resp.Items) == 0 {
		return &compute.Firewall{}, fail.NotFoundError("failed to find a firewall rule with ID %s", id)
	}
	if len(resp.Items) > 1 {
		return &compute.Firewall{}, fail.InconsistentError("found more than one firewall rule with ID %s", id)
	}
	return resp.Items[0], nil
}

func (s stack) rpcCreateFirewallRule(ctx context.Context, ruleName string, networkName, description, direction string, sourcesUseGroups bool, sources []string, targetsUseGroups bool, targets []string, allowed []*compute.FirewallAllowed, denied []*compute.FirewallDenied) (*compute.Firewall, fail.Error) {
	if ruleName == "" {
		return nil, fail.InvalidParameterError("ruleName", "cannot be empty string")
	}
	if networkName == "" {
		return nil, fail.InvalidParameterError("networkName", "cannot be empty string")
	}
	if direction == "" {
		return nil, fail.InvalidParameterError("direction", "cannot be empty string")
	}

	timings, xerr := s.Timings()
	if xerr != nil {
		return nil, xerr
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
	xerr = stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			opp, err = s.ComputeService.Firewalls.Insert(s.GcpConfig.ProjectID, &request).Do()
			if err != nil {
				return err
			}
			if opp != nil {
				if opp.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", opp.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return nil, fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return nil, fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return nil, xerr
		}
	}

	xerr = s.rpcWaitUntilOperationIsSuccessfulOrTimeout(opp, timings.SmallDelay(), timings.HostOperationTimeout())
	if xerr != nil {
		return nil, xerr
	}

	return s.rpcGetFirewallRuleByName(ctx, ruleName)
}

func (s stack) rpcListFirewallRules(ctx context.Context, networkRef string, ids []string) ([]*compute.Firewall, fail.Error) {
	if networkRef == "" && len(ids) == 0 {
		return []*compute.Firewall{}, fail.InvalidParameterError(
			"networkRef", "cannot be empty string if 'ids' is an empty slice",
		)
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
		xerr := stacks.RetryableRemoteCall(ctx,
			func() (err error) {
				resp, err = s.ComputeService.Firewalls.List(s.GcpConfig.ProjectID).Filter(filter).PageToken(token).Do()
				if err != nil {
					return err
				}
				if resp != nil {
					if resp.HTTPStatusCode != 200 {
						logrus.WithContext(ctx).Tracef("received http error code %d", resp.HTTPStatusCode)
						return fail.NewError("received http error code %d", resp.HTTPStatusCode)
					}
				}
				return err
			},
			normalizeError,
		)
		if xerr != nil {
			switch xerr.(type) {
			case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
				return []*compute.Firewall{}, fail.Wrap(fail.Cause(xerr), "stopping retries")
			case *retry.ErrTimeout: // On timeout, we keep the last error as cause
				return []*compute.Firewall{}, fail.Wrap(fail.Cause(xerr), "timeout")
			default:
				return []*compute.Firewall{}, xerr
			}
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

func (s stack) rpcDeleteFirewallRuleByID(ctx context.Context, id string) fail.Error {
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	timings, xerr := s.Timings()
	if xerr != nil {
		return xerr
	}

	var opp *compute.Operation
	xerr = stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			opp, err = s.ComputeService.Firewalls.Delete(s.GcpConfig.ProjectID, id).Do()
			if err != nil {
				return err
			}
			if opp != nil {
				if opp.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", opp.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return xerr
		}
	}

	return s.rpcWaitUntilOperationIsSuccessfulOrTimeout(opp, timings.SmallDelay(), timings.HostOperationTimeout())
}

func (s stack) rpcEnableFirewallRuleByName(ctx context.Context, name string) fail.Error {
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}

	timings, xerr := s.Timings()
	if xerr != nil {
		return xerr
	}

	request := compute.Firewall{
		Disabled: false,
	}
	var opp *compute.Operation
	xerr = stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			opp, err = s.ComputeService.Firewalls.Patch(s.GcpConfig.ProjectID, name, &request).Do()
			if err != nil {
				return err
			}
			if opp != nil {
				if opp.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", opp.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return xerr
		}
	}

	return s.rpcWaitUntilOperationIsSuccessfulOrTimeout(opp, timings.SmallDelay(), 2*timings.ContextTimeout())
}

func (s stack) rpcDisableFirewallRuleByName(ctx context.Context, name string) fail.Error {
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}

	timings, xerr := s.Timings()
	if xerr != nil {
		return xerr
	}

	request := compute.Firewall{
		Disabled: true,
	}
	var opp *compute.Operation
	xerr = stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			opp, err = s.ComputeService.Firewalls.Patch(s.GcpConfig.ProjectID, name, &request).Do()
			if err != nil {
				return err
			}
			if opp != nil {
				if opp.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", opp.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return xerr
		}
	}

	return s.rpcWaitUntilOperationIsSuccessfulOrTimeout(opp, timings.SmallDelay(), 2*timings.ContextTimeout())
}

func (s stack) rpcGetNetworkByID(ctx context.Context, id string) (*compute.Network, fail.Error) {
	if id = strings.TrimSpace(id); id == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	var resp *compute.Network
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.ComputeService.Networks.Get(s.GcpConfig.ProjectID, id).Do()
			if err != nil {
				return err
			}
			if resp != nil {
				if resp.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", resp.HTTPStatusCode)
					return fail.NewError("received http error code %d", resp.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return &compute.Network{}, xerr
	}
	return resp, nil
}

func (s stack) rpcGetNetworkByName(ctx context.Context, name string) (*compute.Network, fail.Error) {
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	var resp *compute.Network
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			ans, err := s.ComputeService.Networks.Get(s.GcpConfig.ProjectID, name).Do()
			if err != nil {
				return err
			}
			if ans != nil {
				resp = ans
				if resp.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", resp.HTTPStatusCode)
					return fail.NewError("received http error code %d", resp.HTTPStatusCode)
				}
			}
			return nil
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return &compute.Network{}, fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return &compute.Network{}, fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return &compute.Network{}, xerr
		}
	}
	return resp, nil
}

func (s stack) rpcCreateNetwork(ctx context.Context, name string) (*compute.Network, fail.Error) {
	timings, xerr := s.Timings()
	if xerr != nil {
		return nil, xerr
	}

	request := compute.Network{
		Name:                  name,
		AutoCreateSubnetworks: false,
		ForceSendFields:       []string{"AutoCreateSubnetworks"},
	}
	var opp *compute.Operation
	xerr = stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			opp, err = s.ComputeService.Networks.Insert(
				s.GcpConfig.ProjectID, &request,
			).Context(context.Background()).Do()
			if err != nil {
				return err
			}
			if opp != nil {
				if opp.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", opp.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return nil, fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return nil, fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return nil, xerr
		}
	}

	if xerr = s.rpcWaitUntilOperationIsSuccessfulOrTimeout(opp, timings.SmallDelay(), 2*timings.ContextTimeout()); xerr != nil {
		return nil, xerr
	}

	var out *compute.Network
	xerr = stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			out, err = s.ComputeService.Networks.Get(s.GcpConfig.ProjectID, name).Do()
			if err != nil {
				return err
			}
			if out != nil {
				if out.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", out.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return nil, fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return nil, fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return nil, xerr
		}
	}
	return out, nil
}

func (s stack) rpcGetRouteByName(ctx context.Context, name string) (*compute.Route, fail.Error) {
	if name = strings.TrimSpace(name); name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	var resp *compute.Route
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.ComputeService.Routes.Get(s.GcpConfig.ProjectID, name).Do()
			if err != nil {
				return err
			}
			if resp != nil {
				if resp.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", resp.HTTPStatusCode)
					return fail.NewError("received http error code %d", resp.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return nil, fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return nil, fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return nil, xerr
		}
	}
	return resp, nil
}

func (s stack) rpcCreateRoute(ctx context.Context, networkName, subnetID, subnetName string) (*compute.Route, fail.Error) {
	if networkName == "" {
		return nil, fail.InvalidParameterError("networkName", "cannot be empty string")
	}
	if subnetID == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("subnetID")
	}
	if subnetName == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("subnetName")
	}

	timings, xerr := s.Timings()
	if xerr != nil {
		return nil, xerr
	}

	routeName := fmt.Sprintf(NATRouteNameFormat, subnetID)

	request := compute.Route{
		DestRange:       "0.0.0.0/0",
		Name:            routeName,
		Network:         fmt.Sprintf("%s/global/networks/%s", s.selfLinkPrefix, networkName),
		NextHopInstance: fmt.Sprintf("%s/zones/%s/instances/gw-%s", s.selfLinkPrefix, s.GcpConfig.Zone, subnetName),
		Priority:        800,
		Tags:            []string{fmt.Sprintf(NATRouteTagFormat, subnetID)},
	}
	var opp *compute.Operation
	xerr = stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			opp, err = s.ComputeService.Routes.Insert(s.GcpConfig.ProjectID, &request).Do()
			if err != nil {
				return err
			}
			if opp != nil {
				if opp.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", opp.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return nil, fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return nil, fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return nil, xerr
		}
	}

	xerr = s.rpcWaitUntilOperationIsSuccessfulOrTimeout(opp, timings.SmallDelay(), 2*timings.ContextTimeout())
	if xerr != nil {
		return nil, xerr
	}

	return s.rpcGetRouteByName(ctx, routeName)
}

func (s stack) rpcDeleteRoute(ctx context.Context, name string) fail.Error {
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}

	timings, xerr := s.Timings()
	if xerr != nil {
		return xerr
	}

	var opp *compute.Operation
	xerr = stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			opp, err = s.ComputeService.Routes.Delete(s.GcpConfig.ProjectID, name).Do()
			if err != nil {
				return err
			}
			if opp != nil {
				if opp.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", opp.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return xerr
		}
	}

	return s.rpcWaitUntilOperationIsSuccessfulOrTimeout(opp, timings.SmallDelay(), timings.HostCleanupTimeout())
}

var imageFamilies = []string{
	"centos-cloud", "debian-cloud", "rhel-cloud", "ubuntu-os-cloud", "suse-cloud", "rhel-sap-cloud", "suse-sap-cloud",
}

func (s stack) rpcListImages(ctx context.Context) ([]*compute.Image, fail.Error) {
	var (
		out  []*compute.Image
		resp *compute.ImageList
	)
	filter := `deprecated.replacement ne .*images.*`
	for _, f := range imageFamilies {
		for token := ""; ; {
			xerr := stacks.RetryableRemoteCall(ctx,
				func() (err error) {
					resp, err = s.ComputeService.Images.List(f).Filter(filter).PageToken(token).Do()
					if err != nil {
						return err
					}
					if resp != nil {
						if resp.HTTPStatusCode != 200 {
							logrus.WithContext(ctx).Tracef("received http error code %d", resp.HTTPStatusCode)
							return fail.NewError("received http error code %d", resp.HTTPStatusCode)
						}
					}
					return err
				},
				normalizeError,
			)
			if xerr != nil {
				switch xerr.(type) {
				case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
					return []*compute.Image{}, fail.Wrap(fail.Cause(xerr), "stopping retries")
				case *retry.ErrTimeout: // On timeout, we keep the last error as cause
					return []*compute.Image{}, fail.Wrap(fail.Cause(xerr), "timeout")
				default:
					return []*compute.Image{}, xerr
				}
			}
			out = append(out, resp.Items...)
			if token = resp.NextPageToken; token == "" {
				break
			}
		}
	}
	return out, nil
}

func (s stack) rpcGetImageByID(ctx context.Context, id string) (*compute.Image, fail.Error) {
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
			xerr := stacks.RetryableRemoteCall(ctx,
				func() (err error) {
					resp, err = s.ComputeService.Images.List(f).Filter(filter).PageToken(token).Do()
					if err != nil {
						return err
					}
					if resp != nil {
						if resp.HTTPStatusCode != 200 {
							logrus.WithContext(ctx).Tracef("received http error code %d", resp.HTTPStatusCode)
							return fail.NewError("received http error code %d", resp.HTTPStatusCode)
						}
					}
					return err
				},
				normalizeError,
			)
			if xerr != nil {
				switch xerr.(type) {
				case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
					return &compute.Image{}, fail.Wrap(fail.Cause(xerr), "stopping retries")
				case *retry.ErrTimeout: // On timeout, we keep the last error as cause
					return &compute.Image{}, fail.Wrap(fail.Cause(xerr), "timeout")
				default:
					return &compute.Image{}, xerr
				}
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

func (s stack) rpcListMachineTypes(ctx context.Context) ([]*compute.MachineType, fail.Error) {
	var (
		out  []*compute.MachineType
		resp *compute.MachineTypeList
	)
	for token := ""; ; {
		var zero []*compute.MachineType
		xerr := stacks.RetryableRemoteCall(ctx,
			func() (err error) {
				resp, err = s.ComputeService.MachineTypes.List(
					s.GcpConfig.ProjectID, s.GcpConfig.Zone,
				).PageToken(token).Do()
				if err != nil {
					return err
				}
				if resp != nil {
					if resp.HTTPStatusCode != 200 {
						logrus.WithContext(ctx).Tracef("received http error code %d", resp.HTTPStatusCode)
						return fail.NewError("received http error code %d", resp.HTTPStatusCode)
					}
				}
				return err
			},
			normalizeError,
		)
		if xerr != nil {
			switch xerr.(type) {
			case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
				return zero, fail.Wrap(fail.Cause(xerr), "stopping retries")
			case *retry.ErrTimeout: // On timeout, we keep the last error as cause
				return zero, fail.Wrap(fail.Cause(xerr), "timeout")
			default:
				return zero, xerr
			}
		}
		out = append(out, resp.Items...)
		if token = resp.NextPageToken; token == "" {
			break
		}
	}
	return out, nil
}

func (s stack) rpcGetMachineType(ctx context.Context, id string) (*compute.MachineType, fail.Error) {
	if id == "" {
		return &compute.MachineType{}, fail.InvalidParameterError("id", "cannot be empty string")
	}

	var resp *compute.MachineType
	zero := &compute.MachineType{}
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.ComputeService.MachineTypes.Get(s.GcpConfig.ProjectID, s.GcpConfig.Zone, id).Do()
			if err != nil {
				return err
			}
			if resp != nil {
				if resp.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", resp.HTTPStatusCode)
					return fail.NewError("received http error code %d", resp.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return zero, fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return zero, fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return zero, xerr
		}
	}
	return resp, nil
}

func (s stack) rpcListInstances(ctx context.Context) ([]*compute.Instance, fail.Error) {
	var (
		out  []*compute.Instance
		resp *compute.InstanceList
	)
	for token := ""; ; {
		var zero []*compute.Instance
		xerr := stacks.RetryableRemoteCall(ctx,
			func() (err error) {
				resp, err = s.ComputeService.Instances.List(
					s.GcpConfig.ProjectID, s.GcpConfig.Zone,
				).PageToken(token).Do()
				if err != nil {
					return err
				}
				if resp != nil {
					if resp.HTTPStatusCode != 200 {
						logrus.WithContext(ctx).Tracef("received http error code %d", resp.HTTPStatusCode)
						return fail.NewError("received http error code %d", resp.HTTPStatusCode)
					}
				}
				return err
			},
			normalizeError,
		)
		if xerr != nil {
			switch xerr.(type) {
			case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
				return zero, fail.Wrap(fail.Cause(xerr), "stopping retries")
			case *retry.ErrTimeout: // On timeout, we keep the last error as cause
				return zero, fail.Wrap(fail.Cause(xerr), "timeout")
			default:
				return zero, xerr
			}
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

func (s stack) rpcCreateInstance(ctx context.Context, name string, networkName, subnetID, subnetName, templateName, imageURL string, diskSize int64, userdata string, hasPublicIP bool, sgs map[string]struct{}, extra interface{}) (_ *compute.Instance, ferr fail.Error) {
	var xerr fail.Error
	var tags []string
	for k := range sgs {
		tags = append(tags, k)
	}

	timings, xerr := s.Timings()
	if xerr != nil {
		return nil, xerr
	}

	// Add nat route name as tag to host that has a public IP
	var publicIP *compute.Address
	if hasPublicIP {
		tags = append(tags, fmt.Sprintf(NATRouteNameFormat, subnetID))

		// Create static regional external address
		publicIP, xerr = s.rpcCreateExternalAddress(ctx, "publicip-"+name, false)
		if xerr != nil {
			return &compute.Instance{}, fail.Wrap(xerr, "failed to create public IP of instance")
		}
	} else {
		tags = append(tags, fmt.Sprintf(NATRouteTagFormat, subnetID))
	}

	managedTag := "safescale"
	bucketName := s.Config.MetadataBucket
	now := time.Now().Format(time.RFC3339)

	ili := []*compute.MetadataItems{
		{
			Key:   "startup-script",
			Value: &userdata,
		},
		{
			Key:   "ManagedBy",
			Value: &managedTag,
		},
		{
			Key:   "DeclaredInBucket",
			Value: &bucketName,
		},
		{
			Key:   "Image",
			Value: &imageURL,
		},
		{
			Key:   "Template",
			Value: &templateName,
		},
		{
			Key:   "CreationDate",
			Value: &now,
		},
	}
	if extra != nil {
		into, ok := extra.(map[string]string)
		if !ok {
			return nil, fail.InvalidParameterError("extra", "must be a map[string]string")
		}
		for k, v := range into {
			k := k
			v := v
			ili = append(ili, &compute.MetadataItems{
				Key:   k,
				Value: &v,
			})
		}
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
				// AccessConfigs: publicAccess(hasPublicIP),
				Network:    s.selfLinkPrefix + "/global/networks/" + networkName,
				Subnetwork: s.selfLinkPrefix + "/regions/" + s.GcpConfig.Region + "/subnetworks/" + subnetName,
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
			Items: ili,
		},
	}
	if hasPublicIP {
		request.NetworkInterfaces[0].AccessConfigs = []*compute.AccessConfig{
			{
				Type:  "ONE_TO_ONE_NAT",
				Name:  "External NAT",
				NatIP: publicIP.Address,
			},
		}
	}

	var op *compute.Operation
	zero := &compute.Instance{}
	xerr = stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			op, err = s.ComputeService.Instances.Insert(s.GcpConfig.ProjectID, s.GcpConfig.Zone, &request).Do()
			if err != nil {
				return err
			}

			if op != nil {
				if op.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", op.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return zero, fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return zero, fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return zero, xerr
		}
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			if derr := s.rpcDeleteInstance(context.Background(), name); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "Cleaning up on failure, failed to delete instance '%s'", name))
			}
		}
	}()

	etag := op.Header.Get("Etag")
	xerr = s.rpcWaitUntilOperationIsSuccessfulOrTimeout(op, timings.SmallDelay(), timings.HostOperationTimeout())
	if xerr != nil {
		return &compute.Instance{}, xerr
	}

	var resp *compute.Instance
	xerr = stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.ComputeService.Instances.Get(
				s.GcpConfig.ProjectID, s.GcpConfig.Zone, name,
			).IfNoneMatch(etag).Do()
			if err != nil {
				return err
			}
			if resp != nil {
				if resp.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", resp.HTTPStatusCode)
					return fail.NewError("received http error code %d", resp.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return zero, fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return zero, fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return zero, xerr
		}
	}

	return resp, nil
}

func (s stack) rpcCreateLabels(ctx context.Context, id string, kv map[string]string) fail.Error {
	inst, xerr := s.getInstance(ctx, id)
	if xerr != nil {
		return xerr
	}

	labels := inst.Labels
	if labels == nil {
		labels = make(map[string]string)
	}
	for k, v := range kv {
		labels[k] = v
	}

	resp, err := s.ComputeService.Instances.SetLabels(s.GcpConfig.ProjectID, s.GcpConfig.Zone, id, &compute.InstancesSetLabelsRequest{
		LabelFingerprint: inst.LabelFingerprint,
		Labels:           labels,
	}).Do()

	if err != nil {
		return fail.ConvertError(err)
	}

	xerr = s.checkStatusCode(resp)
	if xerr != nil {
		return xerr
	}

	return s.checkStatusCode(resp)
}

func (s stack) rpcRemoveLabels(ctx context.Context, id string, kv []string) fail.Error {
	inst, xerr := s.getInstance(ctx, id)
	if xerr != nil {
		return xerr
	}

	labels := inst.Labels
	if labels == nil {
		labels = make(map[string]string)
	}
	for _, k := range kv {
		delete(labels, k)
	}

	resp, err := s.ComputeService.Instances.SetLabels(s.GcpConfig.ProjectID, s.GcpConfig.Zone, id, &compute.InstancesSetLabelsRequest{
		LabelFingerprint: inst.LabelFingerprint,
		Labels:           labels,
	}).Do()

	if err != nil {
		return fail.ConvertError(err)
	}

	xerr = s.checkStatusCode(resp)
	if xerr != nil {
		return xerr
	}

	return s.checkStatusCode(resp)
}

func (s stack) rpcCreateTags(ctx context.Context, id string, kv map[string]string) fail.Error {
	inst, xerr := s.getInstance(ctx, id)
	if xerr != nil {
		return xerr
	}

	metadatas := inst.Metadata
	for k, v := range kv {
		metadatas.Items = append(metadatas.Items, &compute.MetadataItems{
			Key:   k,
			Value: &v,
		})
	}

	resp, err := s.ComputeService.Instances.SetMetadata(s.GcpConfig.ProjectID, s.GcpConfig.Zone, id, metadatas).Do()
	if err != nil {
		return fail.ConvertError(err)
	}

	return s.checkStatusCode(resp)
}

func (s stack) rpcListTags(ctx context.Context, id string) (map[string]string, fail.Error) {
	inst, xerr := s.getInstance(ctx, id)
	if xerr != nil {
		return nil, xerr
	}

	labels := inst.Labels
	return labels, nil
}

func (s stack) checkStatusCode(resp *compute.Operation) fail.Error {
	if resp != nil {
		if resp.HTTPStatusCode != 200 {
			return fail.NewError("received http error code %d", resp.HTTPStatusCode)
		}
	}

	return nil
}

func (s stack) getInstance(ctx context.Context, id string) (*compute.Instance, fail.Error) {
	var resp *compute.Instance
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.ComputeService.Instances.Get(s.GcpConfig.ProjectID, s.GcpConfig.Zone, id).Do()
			if err != nil {
				return err
			}
			if resp != nil {
				if resp.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", resp.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return nil, fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return nil, fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return nil, xerr
		}
	}

	return resp, nil
}

func (s stack) rpcResetStartupScriptOfInstance(ctx context.Context, id string) fail.Error {
	var resp *compute.Instance
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.ComputeService.Instances.Get(s.GcpConfig.ProjectID, s.GcpConfig.Zone, id).Do()
			if err != nil {
				return err
			}
			if resp != nil {
				if resp.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", resp.HTTPStatusCode)
					return fail.NewError("received http error code %d", resp.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return xerr
		}
	}

	// remove startup-script from metadata to prevent it to rerun at reboot (standard behavior in GCP)
	if length := len(resp.Metadata.Items); length > 0 {
		newMetadata := &compute.Metadata{}
		newMetadata.Items = make([]*compute.MetadataItems, 0, length)
		var scriptDoNothing = "exit 0"
		for _, v := range resp.Metadata.Items {
			if v.Key == "startup-script" {
				v.Value = &scriptDoNothing
			}
			newMetadata.Items = append(newMetadata.Items, v)
		}
		newMetadata.Fingerprint = resp.Metadata.Fingerprint

		xerr = stacks.RetryableRemoteCall(ctx,
			func() (err error) {
				op, err := s.ComputeService.Instances.SetMetadata(
					s.GcpConfig.ProjectID, s.GcpConfig.Zone, resp.Name, newMetadata,
				).Do()
				if op != nil {
					if op.HTTPStatusCode != 200 {
						logrus.WithContext(ctx).Tracef("received http error code %d", op.HTTPStatusCode)
					}
				}
				return err
			},
			normalizeError,
		)
		if xerr != nil {
			switch xerr.(type) {
			case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
				return fail.Wrap(fail.Cause(xerr), "stopping retries")
			case *retry.ErrTimeout: // On timeout, we keep the last error as cause
				return fail.Wrap(fail.Cause(xerr), "timeout")
			default:
				return xerr
			}
		}
	}
	return nil
}

func (s stack) rpcCreateExternalAddress(ctx context.Context, name string, global bool) (_ *compute.Address, ferr fail.Error) {
	timings, xerr := s.Timings()
	if xerr != nil {
		return nil, xerr
	}

	query := compute.Address{
		Name: name,
	}
	var op *compute.Operation
	zero := &compute.Address{}
	if global {
		xerr = stacks.RetryableRemoteCall(ctx,
			func() (err error) {
				op, err = s.ComputeService.GlobalAddresses.Insert(s.GcpConfig.ProjectID, &query).Do()
				if err != nil {
					return err
				}
				if op != nil {
					if op.HTTPStatusCode != 200 {
						logrus.WithContext(ctx).Tracef("received http error code %d", op.HTTPStatusCode)
					}
				}
				return err
			},
			normalizeError,
		)
	} else {
		xerr = stacks.RetryableRemoteCall(ctx,
			func() (err error) {
				op, err = s.ComputeService.Addresses.Insert(s.GcpConfig.ProjectID, s.GcpConfig.Region, &query).Do()
				if err != nil {
					return err
				}
				if op != nil {
					if op.HTTPStatusCode != 200 {
						logrus.WithContext(ctx).Tracef("received http error code %d", op.HTTPStatusCode)
					}
				}
				return err
			},
			normalizeError,
		)
	}
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return zero, fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return zero, fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return zero, xerr
		}
	}

	xerr = s.rpcWaitUntilOperationIsSuccessfulOrTimeout(op, timings.SmallDelay(), timings.HostOperationTimeout())
	if xerr != nil {
		return &compute.Address{}, xerr
	}

	var resp *compute.Address
	if global {
		xerr = stacks.RetryableRemoteCall(ctx,
			func() (err error) {
				resp, err = s.ComputeService.GlobalAddresses.Get(s.GcpConfig.ProjectID, name).Do()
				if err != nil {
					return err
				}
				if resp != nil {
					if resp.HTTPStatusCode != 200 {
						logrus.WithContext(ctx).Tracef("received http error code %d", resp.HTTPStatusCode)
						return fail.NewError("received http error code %d", resp.HTTPStatusCode)
					}
				}
				return err
			},
			normalizeError,
		)
	} else {
		xerr = stacks.RetryableRemoteCall(ctx,
			func() (err error) {
				resp, err = s.ComputeService.Addresses.Get(s.GcpConfig.ProjectID, s.GcpConfig.Region, name).Do()
				if err != nil {
					return err
				}
				if resp != nil {
					if resp.HTTPStatusCode != 200 {
						logrus.WithContext(ctx).Tracef("received http error code %d", resp.HTTPStatusCode)
						return fail.NewError("received http error code %d", resp.HTTPStatusCode)
					}
				}
				return err
			},
			normalizeError,
		)
	}
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return zero, fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return zero, fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return zero, xerr
		}
	}

	return resp, nil
}

func (s stack) rpcGetInstance(ctx context.Context, ref string) (*compute.Instance, fail.Error) {
	if ref == "" {
		return &compute.Instance{}, fail.InvalidParameterError("ref", "cannot be empty string")
	}

	var resp *compute.Instance
	zero := &compute.Instance{}
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.ComputeService.Instances.Get(s.GcpConfig.ProjectID, s.GcpConfig.Zone, ref).Do()
			if err != nil {
				return err
			}
			if resp != nil {
				if resp.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", resp.HTTPStatusCode)
					return fail.NewError("received http error code %d", resp.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return zero, fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return zero, fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return zero, xerr
		}
	}
	return resp, nil
}

func (s stack) rpcDeleteInstance(ctx context.Context, ref string) fail.Error {
	timings, xerr := s.Timings()
	if xerr != nil {
		return xerr
	}

	// Get instance to make sure we have the hostname used to name the optional public IP (ref may be id or name)
	instance, xerr := s.rpcGetInstance(ctx, ref)
	if xerr != nil {
		return xerr
	}

	var op *compute.Operation
	xerr = stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			op, err = s.ComputeService.Instances.Delete(s.GcpConfig.ProjectID, s.GcpConfig.Zone, instance.Name).Do()
			if err != nil {
				return err
			}
			if op != nil {
				if op.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", op.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return xerr
		}
	}

	xerr = s.rpcWaitUntilOperationIsSuccessfulOrTimeout(op, timings.SmallDelay(), timings.HostCleanupTimeout())
	if xerr != nil {
		return xerr
	}

	publicIPName := "publicip-" + instance.Name
	if xerr = s.rpcDeleteExternalAddress(ctx, publicIPName, false); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// external ip not found, continue
		default:
			return fail.Wrap(xerr, "failed to delete public IP '%s'", publicIPName)
		}
	}

	return nil
}

func (s stack) rpcGetExternalAddress(ctx context.Context, name string, global bool) (_ *compute.Address, ferr fail.Error) {
	var resp *compute.Address
	zero := &compute.Address{}
	var xerr fail.Error
	if global {
		xerr = stacks.RetryableRemoteCall(ctx,
			func() (err error) {
				resp, err = s.ComputeService.GlobalAddresses.Get(s.GcpConfig.ProjectID, name).Do()
				if err != nil {
					return err
				}
				if resp != nil {
					if resp.HTTPStatusCode != 200 {
						logrus.WithContext(ctx).Tracef("received http error code %d", resp.HTTPStatusCode)
						return fail.NewError("received http error code %d", resp.HTTPStatusCode)
					}
				}
				return err
			},
			normalizeError,
		)
	} else {
		xerr = stacks.RetryableRemoteCall(ctx,
			func() (err error) {
				resp, err = s.ComputeService.Addresses.Get(s.GcpConfig.ProjectID, s.GcpConfig.Region, name).Do()
				if err != nil {
					return err
				}
				if resp != nil {
					if resp.HTTPStatusCode != 200 {
						logrus.WithContext(ctx).Tracef("received http error code %d", resp.HTTPStatusCode)
						return fail.NewError("received http error code %d", resp.HTTPStatusCode)
					}
				}
				return err
			},
			normalizeError,
		)
	}
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return zero, fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return zero, fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return zero, xerr
		}
	}
	return resp, nil
}

func (s stack) rpcDeleteExternalAddress(ctx context.Context, name string, global bool) fail.Error {
	if global {
		xerr := stacks.RetryableRemoteCall(ctx,
			func() (err error) {
				op, err := s.ComputeService.GlobalAddresses.Delete(s.GcpConfig.ProjectID, name).Do()
				if op != nil {
					if op.HTTPStatusCode != 200 {
						logrus.WithContext(ctx).Tracef("received http error code %d", op.HTTPStatusCode)
					}
				}
				return err
			},
			normalizeError,
		)
		if xerr != nil {
			switch xerr.(type) {
			case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
				return fail.Wrap(fail.Cause(xerr), "stopping retries")
			case *retry.ErrTimeout: // On timeout, we keep the last error as cause
				return fail.Wrap(fail.Cause(xerr), "timeout")
			default:
				return xerr
			}
		}
		return nil
	}

	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			op, err := s.ComputeService.Addresses.Delete(s.GcpConfig.ProjectID, s.GcpConfig.Region, name).Do()
			if op != nil {
				if op.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", op.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return xerr
		}
	}
	return nil
}

func (s stack) rpcStopInstance(ctx context.Context, ref string) fail.Error {
	if ref == "" {
		return fail.InvalidParameterError("ref", "cannot be empty string")
	}

	timings, xerr := s.Timings()
	if xerr != nil {
		return xerr
	}

	var op *compute.Operation
	xerr = stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			op, err = s.ComputeService.Instances.Stop(s.GcpConfig.ProjectID, s.GcpConfig.Zone, ref).Do()
			if err != nil {
				return err
			}
			if op != nil {
				if op.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", op.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return xerr
		}
	}

	return s.rpcWaitUntilOperationIsSuccessfulOrTimeout(op, timings.SmallDelay(), timings.HostOperationTimeout())
}

func (s stack) rpcStartInstance(ctx context.Context, ref string) fail.Error {
	if ref == "" {
		return fail.InvalidParameterError("ref", "cannot be empty string")
	}

	timings, xerr := s.Timings()
	if xerr != nil {
		return xerr
	}

	var op *compute.Operation
	xerr = stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			op, err = s.ComputeService.Instances.Start(s.GcpConfig.ProjectID, s.GcpConfig.Zone, ref).Do()
			if err != nil {
				return err
			}
			if op != nil {
				if op.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", op.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return xerr
		}
	}

	return s.rpcWaitUntilOperationIsSuccessfulOrTimeout(op, timings.SmallDelay(), timings.HostOperationTimeout())
}

func (s stack) rpcListZones(ctx context.Context) ([]*compute.Zone, fail.Error) {
	var (
		resp *compute.ZoneList
		out  []*compute.Zone
	)
	for token := ""; ; {
		xerr := stacks.RetryableRemoteCall(ctx,
			func() (err error) {
				resp, err = s.ComputeService.Zones.List(s.GcpConfig.ProjectID).PageToken(token).Do()
				if err != nil {
					return err
				}
				if resp != nil {
					if resp.HTTPStatusCode != 200 {
						logrus.WithContext(ctx).Tracef("received http error code %d", resp.HTTPStatusCode)
						return fail.NewError("received http error code %d", resp.HTTPStatusCode)
					}
				}
				return err
			},
			normalizeError,
		)
		if xerr != nil {
			switch xerr.(type) {
			case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
				return nil, fail.Wrap(fail.Cause(xerr), "stopping retries")
			case *retry.ErrTimeout: // On timeout, we keep the last error as cause
				return nil, fail.Wrap(fail.Cause(xerr), "timeout")
			default:
				return nil, xerr
			}
		}
		out = append(out, resp.Items...)
		if token = resp.NextPageToken; token == "" {
			break
		}
	}
	return out, nil
}

func (s stack) rpcListRegions(ctx context.Context) ([]*compute.Region, fail.Error) {
	var (
		out  []*compute.Region
		resp *compute.RegionList
	)
	for token := ""; ; {
		var zero []*compute.Region
		xerr := stacks.RetryableRemoteCall(ctx,
			func() (err error) {
				resp, err = s.ComputeService.Regions.List(s.GcpConfig.ProjectID).PageToken(token).Do()
				if err != nil {
					return err
				}
				if resp != nil {
					if resp.HTTPStatusCode != 200 {
						logrus.WithContext(ctx).Tracef("received http error code %d", resp.HTTPStatusCode)
						return fail.NewError("received http error code %d", resp.HTTPStatusCode)
					}
				}
				return err
			},
			normalizeError,
		)
		if xerr != nil {
			switch xerr.(type) {
			case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
				return zero, fail.Wrap(fail.Cause(xerr), "stopping retries")
			case *retry.ErrTimeout: // On timeout, we keep the last error as cause
				return zero, fail.Wrap(fail.Cause(xerr), "timeout")
			default:
				return zero, xerr
			}
		}
		out = append(out, resp.Items...)
		if token = resp.NextPageToken; token == "" {
			break
		}
	}
	return out, nil
}

func (s stack) rpcAddTagsToInstance(ctx context.Context, hostID string, tags []string) fail.Error {
	if hostID == "" {
		return fail.InvalidParameterError("hostID", "cannot be empty string")
	}
	if len(tags) == 0 {
		return fail.InvalidParameterError("tags", "cannot be empty slice")
	}

	timings, xerr := s.Timings()
	if xerr != nil {
		return xerr
	}

	var resp *compute.Instance
	xerr = stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.ComputeService.Instances.Get(s.GcpConfig.ProjectID, s.GcpConfig.Zone, hostID).Do()
			if err != nil {
				return err
			}
			if resp != nil {
				if resp.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", resp.HTTPStatusCode)
					return fail.NewError("received http error code %d", resp.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return xerr
		}
	}

	present := map[string]struct{}{}
	newTags := resp.Tags
	for _, v := range newTags.Items {
		present[v] = struct{}{}
	}
	for _, v := range tags {
		// If current tag is not present, add it to newTags
		if _, ok := present[v]; !ok {
			newTags.Items = append(newTags.Items, v)
		}
	}

	var opp *compute.Operation
	xerr = stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			opp, err = s.ComputeService.Instances.SetTags(s.GcpConfig.ProjectID, s.GcpConfig.Zone, hostID, newTags).Do()
			if err != nil {
				return err
			}
			if opp != nil {
				if opp.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", opp.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return xerr
		}
	}

	return s.rpcWaitUntilOperationIsSuccessfulOrTimeout(opp, timings.SmallDelay(), 2*timings.ContextTimeout())
}

func (s stack) rpcRemoveTagsFromInstance(ctx context.Context, hostID string, tags []string) fail.Error {
	if hostID == "" {
		return fail.InvalidParameterError("hostID", "cannot be empty string")
	}
	if len(tags) == 0 {
		return fail.InvalidParameterError("tags", "cannot be empty slice")
	}

	timings, xerr := s.Timings()
	if xerr != nil {
		return xerr
	}

	var resp *compute.Instance
	xerr = stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.ComputeService.Instances.Get(s.GcpConfig.ProjectID, s.GcpConfig.Zone, hostID).Do()
			if err != nil {
				return err
			}
			if resp != nil {
				if resp.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", resp.HTTPStatusCode)
					return fail.NewError("received http error code %d", resp.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return xerr
		}
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

	// FIXME: Missing Labels, GCP has all 3, metadata, tags and labels

	var opp *compute.Operation
	xerr = stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			opp, err = s.ComputeService.Instances.SetTags(s.GcpConfig.ProjectID, s.GcpConfig.Zone, hostID, newTags).Do()
			if err != nil {
				return err
			}
			if opp != nil {
				if opp.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", opp.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return xerr
		}
	}

	return s.rpcWaitUntilOperationIsSuccessfulOrTimeout(opp, timings.SmallDelay(), 2*timings.ContextTimeout())
}

func (s stack) rpcListNetworks(ctx context.Context) (_ []*compute.Network, ferr fail.Error) {
	var (
		out  []*compute.Network
		resp *compute.NetworkList
	)
	for token := ""; ; {
		var zero []*compute.Network
		xerr := stacks.RetryableRemoteCall(ctx,
			func() (err error) {
				resp, err = s.ComputeService.Networks.List(s.GcpConfig.ProjectID).PageToken(token).Do()
				if err != nil {
					return err
				}
				if resp != nil {
					if resp.HTTPStatusCode != 200 {
						logrus.WithContext(ctx).Tracef("received http error code %d", resp.HTTPStatusCode)
						return fail.NewError("received http error code %d", resp.HTTPStatusCode)
					}
				}
				return err
			},
			normalizeError,
		)
		if xerr != nil {
			switch xerr.(type) {
			case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
				return zero, fail.Wrap(fail.Cause(xerr), "stopping retries")
			case *retry.ErrTimeout: // On timeout, we keep the last error as cause
				return zero, fail.Wrap(fail.Cause(xerr), "timeout")
			default:
				return zero, xerr
			}
		}

		out = append(out, resp.Items...)
		token = resp.NextPageToken
		if token == "" {
			break
		}
	}
	return out, nil
}

func (s stack) rpcDeleteNetworkByID(ctx context.Context, id string) (ferr fail.Error) {
	if id = strings.TrimSpace(id); id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	timings, xerr := s.Timings()
	if xerr != nil {
		return xerr
	}

	var resp *compute.Operation
	xerr = stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.ComputeService.Networks.Delete(s.GcpConfig.ProjectID, id).Do()
			if err != nil {
				return err
			}
			if resp != nil {
				if resp.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", resp.HTTPStatusCode)
					return fail.NewError("received http error code %d", resp.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return xerr
		}
	}

	return s.rpcWaitUntilOperationIsSuccessfulOrTimeout(resp, timings.SmallDelay(), 2*timings.ContextTimeout())
}

func (s stack) rpcCreateDisk(ctx context.Context, name string, kind string, size int64) (*compute.Disk, fail.Error) {
	timings, xerr := s.Timings()
	if xerr != nil {
		return nil, xerr
	}

	request := compute.Disk{
		Name:   name,
		Region: s.GcpConfig.Region,
		SizeGb: size,
		Type:   kind,
		Zone:   s.GcpConfig.Zone,
	}
	var op *compute.Operation
	zero := &compute.Disk{}
	xerr = stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			op, err = s.ComputeService.Disks.Insert(s.GcpConfig.ProjectID, s.GcpConfig.Zone, &request).Do()
			if err != nil {
				return err
			}
			if op != nil {
				if op.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", op.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return zero, fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return zero, fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return zero, xerr
		}
	}

	xerr = s.rpcWaitUntilOperationIsSuccessfulOrTimeout(op, timings.SmallDelay(), timings.HostOperationTimeout())
	if xerr != nil {
		return &compute.Disk{}, xerr
	}

	return s.rpcGetDisk(ctx, name)
}

func (s stack) rpcGetDisk(ctx context.Context, ref string) (*compute.Disk, fail.Error) {
	if ref == "" {
		return &compute.Disk{}, fail.InvalidParameterError("ref", "cannot be empty string")
	}

	var resp *compute.Disk
	zero := &compute.Disk{}
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.ComputeService.Disks.Get(s.GcpConfig.ProjectID, s.GcpConfig.Zone, ref).Do()
			if err != nil {
				return err
			}
			if resp != nil {
				if resp.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", resp.HTTPStatusCode)
					return fail.NewError("received http error code %d", resp.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return zero, fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return zero, fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return zero, xerr
		}
	}
	if resp == nil {
		return &compute.Disk{}, fail.NotFoundError("failed to find Volume named '%s'", ref)
	}
	return resp, nil
}

func (s stack) rpcDeleteDisk(ctx context.Context, ref string) fail.Error {
	if ref == "" {
		return fail.InvalidParameterError("ref", "cannot be empty string")
	}

	timings, xerr := s.Timings()
	if xerr != nil {
		return xerr
	}

	var op *compute.Operation
	xerr = stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			op, err = s.ComputeService.Disks.Delete(s.GcpConfig.ProjectID, s.GcpConfig.Zone, ref).Do()
			if err != nil {
				return err
			}
			if op != nil {
				if op.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", op.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return xerr
		}
	}

	return s.rpcWaitUntilOperationIsSuccessfulOrTimeout(op, timings.SmallDelay(), timings.HostOperationTimeout())
}

func (s stack) rpcCreateDiskAttachment(ctx context.Context, diskRef, hostRef string) (string, fail.Error) {
	if diskRef == "" {
		return "", fail.InvalidParameterError("diskRef", "cannot be empty string")
	}
	if hostRef == "" {
		return "", fail.InvalidParameterError("hostRef", "cannot be empty string")
	}

	timings, xerr := s.Timings()
	if xerr != nil {
		return "", xerr
	}

	instance, xerr := s.rpcGetInstance(ctx, hostRef)
	if xerr != nil {
		return "", xerr
	}

	disk, xerr := s.rpcGetDisk(ctx, diskRef)
	if xerr != nil {
		return "", xerr
	}

	request := compute.AttachedDisk{
		DeviceName: disk.Name,
		Source:     disk.SelfLink,
	}
	var op *compute.Operation
	zero := ""
	xerr = stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			op, err = s.ComputeService.Instances.AttachDisk(
				s.GcpConfig.ProjectID, s.GcpConfig.Zone, instance.Name, &request,
			).Do()
			if err != nil {
				return err
			}
			if op != nil {
				if op.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", op.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return zero, fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return zero, fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return zero, xerr
		}
	}

	xerr = s.rpcWaitUntilOperationIsSuccessfulOrTimeout(op, timings.SmallDelay(), timings.HostOperationTimeout())
	if xerr != nil {
		return "", xerr
	}

	return generateDiskAttachmentID(instance.Name, disk.Name), nil
}

func (s stack) rpcDeleteDiskAttachment(ctx context.Context, vaID string) fail.Error {
	if vaID == "" {
		return fail.InvalidParameterError("vaID", "cannot be empty string")
	}

	timings, xerr := s.Timings()
	if xerr != nil {
		return xerr
	}

	serverName, diskName := extractFromAttachmentID(vaID)
	if serverName == "" || diskName == "" {
		return fail.SyntaxError("the content of 'vaID' does not represent an ID for a Volume attachment")
	}
	var op *compute.Operation
	xerr = stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			op, err = s.ComputeService.Instances.DetachDisk(
				s.GcpConfig.ProjectID, s.GcpConfig.Zone, serverName, diskName,
			).Do()
			if err != nil {
				return err
			}
			if op != nil {
				if op.HTTPStatusCode != 200 {
					logrus.WithContext(ctx).Tracef("received http error code %d", op.HTTPStatusCode)
				}
			}
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return xerr
		}
	}

	return s.rpcWaitUntilOperationIsSuccessfulOrTimeout(op, timings.SmallDelay(), timings.HostOperationTimeout())
}
