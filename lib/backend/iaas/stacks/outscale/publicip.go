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

package outscale

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// ListPublicIPs returns a list of public ip
func (s stack) ListPublicIPs(ctx context.Context) ([]*abstract.PublicIP, fail.Error) {
	if valid.IsNull(s) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	return nil, fail.NotImplementedError("stacks.outscale.ListPublicIP() not implemented")
}

// CreatePublicIP allocates a Public IP and returns abstract for it
func (s stack) CreatePublicIP(ctx context.Context, kind ipversion.Enum, description string) (*abstract.PublicIP, fail.Error) {
	if valid.IsNull(s) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	resp, xerr := s.rpcCreatePublicIP(ctx)
	if xerr != nil {
		return &abstract.PublicIP{}, xerr
	}

	// Returns the abstract of Public IP
	out := abstract.NewPublicIP()
	out.ID = resp.PublicIpId
	out.Name = resp.PublicIp
	out.Kind = ipversion.IPv4
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

	return s.rpcDeletePublicIPByIP(ctx, apip.ID)
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

	_, xerr = s.rpcReadPublicIP(ctx, apip.ID)
	if xerr != nil {
		return nil, xerr
	}

	out := abstract.NewPublicIP()
	return out, nil
}

// BindPublicIPToHost binds a previously created Public IP to a Host
// Note: by convention, if nicID == "", tries to bind on first interface of Host
func (s stack) BindPublicIPToHost(ctx context.Context, pipParam stacks.PublicIPParameter, hostParam stacks.HostParameter, nicID string) fail.Error {
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

	if nicID == "" {
		nics, xerr := s.rpcReadNics(ctx, "", ahf.Core.ID)
		if xerr != nil {
			return xerr
		}

		nicID = nics[0].NicId
	}
	return s.rpcLinkPublicIPToNic(ctx, apip.ID, nicID)
}

// BindPublicIPToInterface binds a previously created Public IP to an interface
func (s stack) BindPublicIPToInterface(ctx context.Context, pipParam stacks.PublicIPParameter, nicID string) fail.Error {
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
	if nicID == "" {
		return fail.InvalidParameterCannotBeNilError("nicID")
	}

	// Attach public ip
	return s.rpcLinkPublicIPToNic(ctx, apip.ID, nicID)
}

// UnbindPublicIPFromHost unbinds the PublicIP from an Host
func (s stack) UnbindPublicIPFromHost(ctx context.Context, pipParam stacks.PublicIPParameter, _ stacks.HostParameter) fail.Error {
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

	return s.rpcUnlinkPublicIP(ctx, apip.ID)
}
