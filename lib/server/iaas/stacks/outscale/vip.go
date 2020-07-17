/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
	"fmt"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"sort"

	"github.com/antihax/optional"
	"github.com/outscale/osc-sdk-go/osc"

	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// CreateVIP ...
func (s *Stack) CreateVIP(subnetID string, name string) (_ *abstract.VirtualIP, xerr fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	tracer := concurrency.NewTracer(nil, debug.ShouldTrace("stacks.outscale"), "(%s, '%s')", subnetID, name).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(), &xerr)

	subnet, xerr := s.getSubnet(subnetID)
	if xerr != nil {
		return nil, xerr
	}
	netID := subnet.NetId
	group, xerr := s.getNetworkSecurityGroup(netID)
	if xerr != nil {
		return nil, xerr
	}
	createNicRequest := osc.CreateNicRequest{
		Description:      name,
		SubnetId:         subnetID,
		SecurityGroupIds: []string{group.SecurityGroupId},
	}
	res, _, err := s.client.NicApi.CreateNic(s.auth, &osc.CreateNicOpts{
		CreateNicRequest: optional.NewInterface(createNicRequest),
	})
	if err != nil {
		return nil, normalizeError(err)
	}
	if len(res.Nic.PrivateIps) < 1 {
		return nil, fail.InconsistentError("Inconsistent provider response")
	}
	nic := res.Nic
	// ip, err := s.addPublicIP(&nic)
	// VPL: twice ?
	// if len(res.Nic.PrivateIps) < 1 {
	//	return nil, fail.InconsistentError("Inconsistent provider response")
	// }

	xerr = s.setResourceTags(nic.NicId, map[string]string{
		"name": name,
	})
	if xerr != nil {
		return nil, xerr
	}
	// primary := deviceNumber == 0
	return &abstract.VirtualIP{
		ID:        nic.NicId,
		PrivateIP: nic.PrivateIps[0].PrivateIp,
		NetworkID: netID,
		Hosts:     nil,
		PublicIP:  "",
	}, nil
}

// AddPublicIPToVIP adds a public IP to VIP
func (s *Stack) AddPublicIPToVIP(*abstract.VirtualIP) fail.Error {
	if s == nil {
		return fail.InvalidInstanceError()
	}

	return fail.NotImplementedError("AddPublicIPToVIP() not implemented yet")
}

func (s *Stack) getFirstFreeDeviceNumber(hostID string) (int64, fail.Error) {
	readNicsRequest := osc.ReadNicsRequest{
		Filters: osc.FiltersNic{
			LinkNicVmIds: []string{hostID},
		},
	}
	res, _, err := s.client.NicApi.ReadNics(s.auth, &osc.ReadNicsOpts{
		ReadNicsRequest: optional.NewInterface(readNicsRequest),
	})
	if err != nil {
		return 0, normalizeError(err)
	}
	if len(res.Nics) == 0 {
		return -1, fail.NewError("no nics linked to the VM")
	}
	var numbers sort.IntSlice
	for _, nic := range res.Nics {
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
	return 0, fail.InvalidRequestError(fmt.Sprintf("No more free device on host %s", hostID))
}

// BindHostToVIP makes the host passed as parameter an allowed "target" of the VIP
func (s *Stack) BindHostToVIP(vip *abstract.VirtualIP, hostID string) (xerr fail.Error) {
	if s == nil {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterError("vip", "cannot be nil")
	}
	if hostID == "" {
		return fail.InvalidParameterError("host", "cannot be empty string")
	}

	//tracer := concurrency.NewTracer(nil, debug.ShouldTrace("stacks.outscale"), "(%v)", vip).WithStopwatch().Entering()
	//defer tracer.OnExitTrace()
	//defer fail.OnExitLogError(tracer.TraceMessage(), &xerr)

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
func (s *Stack) UnbindHostFromVIP(vip *abstract.VirtualIP, hostID string) (xerr fail.Error) {
	if s == nil {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterError("vip", "cannot be nil")
	}
	if hostID == "" {
		return fail.InvalidParameterError("host", "cannot be empty string")
	}

	//tracer := concurrency.NewTracer(nil, debug.ShouldTrace("stacks.outscale"), "(%v, %s)", vip, hostID).WithStopwatch().Entering()
	//defer tracer.OnExitTrace()
	//defer fail.OnExitLogError(tracer.TraceMessage(), &xerr)

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
func (s *Stack) DeleteVIP(vip *abstract.VirtualIP) (xerr fail.Error) {
	if s == nil {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterError("vip", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, debug.ShouldTrace("stacks.outscale"), "(%v)", vip).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(), &xerr)

	deleteNicRequest := osc.DeleteNicRequest{
		NicId: vip.ID,
	}
	_, _, err := s.client.NicApi.DeleteNic(s.auth, &osc.DeleteNicOpts{
		DeleteNicRequest: optional.NewInterface(deleteNicRequest),
	})
	if err != nil {
		return normalizeError(err)
	}
	deletePublicIpRequest := osc.DeletePublicIpRequest{
		PublicIp: vip.PublicIP,
	}
	_, _, err = s.client.PublicIpApi.DeletePublicIp(s.auth, &osc.DeletePublicIpOpts{
		DeletePublicIpRequest: optional.NewInterface(deletePublicIpRequest),
	})
	return normalizeError(err)
}
