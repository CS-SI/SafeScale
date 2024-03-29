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
	"sort"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// CreateVIP ...
func (s stack) CreateVIP(ctx context.Context, networkID, subnetID, name string, securityGroups []string) (_ *abstract.VirtualIP, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	// networkID is not used by Outscale
	if subnetID = strings.TrimSpace(subnetID); subnetID == "" {
		return nil, fail.InvalidParameterError("subnetID", "cannot be empty string")
	}
	if name = strings.TrimSpace(name); name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	subnet, xerr := s.InspectSubnet(ctx, subnetID)
	if xerr != nil {
		return nil, xerr
	}

	resp, xerr := s.rpcCreateNic(ctx, subnet.ID, name, name, securityGroups)
	if xerr != nil {
		return nil, xerr
	}
	if len(resp.PrivateIps) < 1 {
		return nil, fail.InconsistentError("inconsistent provider response, no interface found")
	}

	vip := abstract.NewVirtualIP()
	vip.ID = resp.NicId
	vip.Name = name
	vip.PrivateIP = resp.PrivateIps[0].PrivateIp
	vip.SubnetID = subnet.ID
	vip.PublicIP = ""
	return vip, nil
}

// AddPublicIPToVIP adds a public IP to VIP
func (s stack) AddPublicIPToVIP(context.Context, *abstract.VirtualIP) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}

	return fail.NotImplementedError("AddPublicIPToVIP() not implemented yet") // FIXME: Technical debt
}

func (s stack) getFirstFreeDeviceNumber(ctx context.Context, hostID string) (int64, fail.Error) {
	resp, xerr := s.rpcReadNicsOfVM(ctx, hostID)
	if xerr != nil {
		return 0, xerr
	}

	var numbers sort.IntSlice
	for _, nic := range resp {
		numbers = append(numbers, int(nic.LinkNic.DeviceNumber))
	}
	if numbers == nil {
		return 0, fail.NewError("no nics linked to the VM")
	}

	sort.Sort(numbers)
	for i := 1; i <= 7; i++ {
		if idx := sort.SearchInts(numbers, i); idx < 0 || idx >= numbers.Len() {
			return int64(i), nil
		}
	}
	return 0, fail.InvalidRequestError("no more free device on host %s", hostID)
}

// BindHostToVIP makes the host passed as parameter an allowed "target" of the VIP
func (s stack) BindHostToVIP(ctx context.Context, vip *abstract.VirtualIP, hostID string) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterCannotBeNilError("vip")
	}
	if hostID == "" {
		return fail.InvalidParameterError("host", "cannot be empty string")
	}

	return nil

}

// UnbindHostFromVIP removes the bind between the VIP and a host
func (s stack) UnbindHostFromVIP(ctx context.Context, vip *abstract.VirtualIP, hostID string) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterCannotBeNilError("vip")
	}
	if hostID == "" {
		return fail.InvalidParameterError("host", "cannot be empty string")
	}

	return nil
}

// DeleteVIP deletes the port corresponding to the VIP
func (s stack) DeleteVIP(ctx context.Context, vip *abstract.VirtualIP) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterCannotBeNilError("vip")
	}

	if xerr := s.rpcDeleteNic(ctx, vip.ID); xerr != nil {
		return xerr
	}

	return s.rpcDeletePublicIPByIP(ctx, vip.PublicIP)
}
