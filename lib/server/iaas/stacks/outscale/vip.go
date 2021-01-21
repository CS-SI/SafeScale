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

package outscale

import (
	"sort"
	"strings"

	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// CreateVIP ...
func (s stack) CreateVIP(networkID, subnetID, name string, securityGroups []string) (_ *abstract.VirtualIP, xerr fail.Error) {
	if s.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	// networkID is not used by Outscale
	if subnetID = strings.TrimSpace(subnetID); subnetID == "" {
		return nil, fail.InvalidParameterError("subnetID", "cannot be empty string")
	}
	if name = strings.TrimSpace(name); name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%s, '%s')", subnetID, name).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	subnet, xerr := s.InspectSubnet(subnetID)
	if xerr != nil {
		return nil, xerr
	}

	resp, xerr := s.rpcCreateNic(subnet.ID, name, name, securityGroups)
	if xerr != nil {
		return nil, xerr
	}
	if len(resp.PrivateIps) < 1 {
		return nil, fail.InconsistentError("inconsistent provider response, no interface found")
	}

	// ip, err := s.addPublicIP(&nic)
	// VPL: twice ?
	// if len(res.Nic.PrivateIps) < 1 {
	//	return nil, fail.InconsistentError("Inconsistent provider response")
	// }

	vip := abstract.NewVirtualIP()
	vip.ID = resp.NicId
	vip.Name = name
	vip.PrivateIP = resp.PrivateIps[0].PrivateIp
	vip.SubnetID = subnet.ID
	vip.PublicIP = ""
	return vip, nil
}

// AddPublicIPToVIP adds a public IP to VIP
func (s stack) AddPublicIPToVIP(*abstract.VirtualIP) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}

	return fail.NotImplementedError("AddPublicIPToVIP() not implemented yet")
}

func (s stack) getFirstFreeDeviceNumber(hostID string) (int64, fail.Error) {
	resp, xerr := s.rpcReadNicsOfVm(hostID)
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
func (s stack) BindHostToVIP(vip *abstract.VirtualIP, hostID string) (xerr fail.Error) {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterError("vip", "cannot be nil")
	}
	if hostID == "" {
		return fail.InvalidParameterError("host", "cannot be empty string")
	}

	// tracer := debug.NewTracer(nil, debug.ShouldTrace("stacks.outscale"), "(%v)", vip).WithStopwatch().Entering()
	// defer tracer.Exiting()
	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	// deviceNumber, err := s.getFirstFreeDeviceNumber(hostID)
	// if err != nil {
	// 	return err
	// }
	// res, err := s.client.POST_ReadNics(osc.ReadNicsRequest{
	// 	Filters: osc.FiltersNic{
	// 		NicIds: []string{vip.ID},
	// 	},
	// })
	// if err != nil {
	// 	return normalizeError(err)
	// }
	// if res == nil || (res.OK != nil && len(res.OK.Nics) > 1) {
	// 	return fail.InconsistentError("Inconsistent provider response")
	// }
	// if res.OK == nil || len(res.OK.Nics) == 0 {
	// 	return fail.InvalidParameterError("vip", "VIP does not exixt")
	// }
	// _, err = s.client.POST_LinkNic(osc.LinkNicRequest{
	// 	NicId:        res.OK.Nics[0].NicId,
	// 	VmId:         hostID,
	// 	DeviceNumber: deviceNumber,
	// })
	// if err != nil {
	// 	logrus.Errorf("BindHostToVIP %v", err)
	// 	return normalizeError(err)
	// }
	return nil

}

// UnbindHostFromVIP removes the bind between the VIP and a host
func (s stack) UnbindHostFromVIP(vip *abstract.VirtualIP, hostID string) (xerr fail.Error) {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterError("vip", "cannot be nil")
	}
	if hostID == "" {
		return fail.InvalidParameterError("host", "cannot be empty string")
	}

	// tracer := debug.NewTracer(nil, debug.ShouldTrace("stacks.outscale"), "(%v, %s)", vip, hostID).WithStopwatch().Entering()
	// defer tracer.Exiting()
	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	// res, err := s.client.POST_ReadNics(osc.ReadNicsRequest{
	// 	Filters: osc.FiltersNic{
	// 		NicIds: []string{vip.ID},
	// 	},
	// })
	// if err != nil {
	// 	return normalizeError(err)
	// }
	// if res == nil || (res.OK != nil && len(res.OK.Nics) > 1) {
	// 	return fail.InconsistentError("Inconsistent provider response")
	// }
	// if res.OK == nil || len(res.OK.Nics) == 0 {
	// 	return fail.InvalidParameterError("vip", "VIP does not exixt")
	// }
	// nic := res.OK.Nics[0]
	// _, err = s.client.POST_UnlinkNic(osc.UnlinkNicRequest{
	// 	LinkNicId: nic.LinkNic.LinkNicId,
	// })
	// return normalizeError(err)
	return nil
}

// DeleteVIP deletes the port corresponding to the VIP
func (s stack) DeleteVIP(vip *abstract.VirtualIP) (xerr fail.Error) {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterError("vip", "cannot be nil")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%v)", vip).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	if xerr := s.rpcDeleteNic(vip.ID); xerr != nil {
		return xerr
	}

	return s.rpcDeletePublicIpByIP(vip.PublicIP)
}
