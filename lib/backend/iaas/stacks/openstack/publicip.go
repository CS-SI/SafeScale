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

package openstack

import (
	"context"

	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/floatingips"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// ListPublicIPs ...
func (s stack) ListPublicIPs(ctx context.Context) ([]*abstract.PublicIP, fail.Error) {
	if valid.IsNull(s) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	return nil, fail.NotImplementedError("stacks.openstack.ListPublicIPs() not implemented")
}

// CreatePublicIP allocates a Public IP and returns abstract for it
func (s stack) CreatePublicIP(ctx context.Context, kind ipversion.Enum, description string) (*abstract.PublicIP, fail.Error) {
	if valid.IsNull(s) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	// Create the floating IP
	ip, xerr := s.rpcCreateFloatingIP(ctx)
	if xerr != nil {
		return &abstract.PublicIP{}, xerr
	}

	// Returns the abstract of Public IP
	out := abstract.NewPublicIP()
	out.ID = ip.ID
	out.Name = ip.IP
	out.Kind = ipversion.IPv4
	out.Description = description
	return out, nil
}

// DeletePublicIP deallocates a Public IP
func (s stack) DeletePublicIP(ctx context.Context, pipParam stacks.PublicIPParameter) fail.Error {
	if valid.IsNull(s) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	apip, _, xerr := stacks.ValidatePublicIParameter(pipParam)
	if xerr != nil {
		return xerr
	}

	return stacks.RetryableRemoteCall(ctx,
		func() error {
			return floatingips.Delete(s.ComputeClient, apip.ID).ExtractErr()
		},
		NormalizeError,
	)
}

// InspectPublicIP returns information about Public IP
func (s stack) InspectPublicIP(ctx context.Context, pipParam stacks.PublicIPParameter) (*abstract.PublicIP, fail.Error) {
	if valid.IsNull(s) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	apip, _, xerr := stacks.ValidatePublicIParameter(pipParam)
	if xerr != nil {
		return nil, xerr
	}

	_, xerr = s.rpcGetFloatingIP(ctx, apip.ID)
	if xerr != nil {
		return &abstract.PublicIP{}, xerr
	}

	out := abstract.NewPublicIP()
	return out, nil
}

// BindPublicIPToHost binds the PublicIP to an Host
func (s stack) BindPublicIPToHost(ctx context.Context, pipParam stacks.PublicIPParameter, hostParam stacks.HostParameter, _ string) fail.Error {
	if valid.IsNull(s) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	apip, _, xerr := stacks.ValidatePublicIParameter(pipParam)
	if xerr != nil {
		return xerr
	}
	ahf, _, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return xerr
	}

	// Associate floating IP to host
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			return floatingips.AssociateInstance(s.ComputeClient, ahf.Core.ID, floatingips.AssociateOpts{
				FloatingIP: apip.Name,
			}).ExtractErr()
		},
		NormalizeError,
	)
}

// UnbindPublicIPFromHost unbinds the PublicIP from an Host
func (s stack) UnbindPublicIPFromHost(ctx context.Context, pipParam stacks.PublicIPParameter, hostParam stacks.HostParameter) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	apip, _, xerr := stacks.ValidatePublicIParameter(pipParam)
	if xerr != nil {
		return xerr
	}
	ahf, _, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return xerr
	}

	return stacks.RetryableRemoteCall(ctx,
		func() error {
			return floatingips.DisassociateInstance(s.ComputeClient, ahf.Core.ID, floatingips.DisassociateOpts{
				FloatingIP: apip.Name,
			}).ExtractErr()
		},
		NormalizeError,
	)
}
