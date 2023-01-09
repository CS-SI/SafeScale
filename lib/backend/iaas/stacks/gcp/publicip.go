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

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// CreatePublicIP allocates a Public IP and returns abstract for it
func (s stack) CreatePublicIP(ctx context.Context, description string) (*abstract.PublicIP, fail.Error) {
	// Create the floating IP
	resp, xerr := s.rpcCreateExternalAddress(ctx, description, false)
	if xerr != nil {
		return &abstract.PublicIP{}, xerr
	}

	// Returns the abstract of Public IP
	out := abstract.NewPublicIP()
	out.ID = resp.Name
	out.Name = resp.Address
	out.Kind = ipversion.IPv4
	out.Description = description
	return out, nil
}

// DeletePublicIP deallocates a Public IP
func (s stack) DeletePublicIP(ctx context.Context, pipParam stacks.PublicIPParameter) fail.Error {
	apip, _, xerr := stacks.ValidatePublicIParameter(pipParam)
	if xerr != nil {
		return xerr
	}

	return s.rpcDeleteExternalAddress(ctx, apip.ID, false)
}

// InspectPublicIP returns information about Public IP
func (s stack) InspectPublicIP(ctx context.Context, id string) (*abstract.PublicIP, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return &abstract.PublicIP{}, fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	resp, xerr := s.rpcGetExternalAddress(ctx, id, false)
	if xerr != nil {
		return &abstract.PublicIP{}, xerr
	}

	out := abstract.NewPublicIP()
	out.ID = resp.Name
	out.Name = resp.Address
	out.Kind = ipversion.IPv4
	return out, nil
}

// BindPublicIPToHost binds the PublicIP to an Host
func (s stack) BindPublicIPToHost(ctx context.Context, pipParam stacks.PublicIPParameter, hostParam stacks.HostParameter) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}

	panic("not implemented")
}

// UnbindPublicIPFromHost unbinds the PublicIP from an Host
func (s stack) UnbindPublicIPFromHost(ctx context.Context, pipParam stacks.PublicIPParameter, hostParam stacks.HostParameter) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}

	panic("not implemented")
}
