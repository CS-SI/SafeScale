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
	"github.com/antihax/optional"
	"sort"

	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/outscale-dev/osc-sdk-go/osc"
)

// CreateVIP ...
func (s *Stack) CreateVIP(subnetID string, name string) (*resources.VirtualIP, error) {
	subnet, err := s.getSubnet(subnetID)
	if err != nil {
		return nil, err
	}
	netID := subnet.NetId
	group, err := s.getNetworkSecurityGroup(netID)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	if len(res.Nic.PrivateIps) < 1 {
		return nil, scerr.InconsistentError("Inconsistent provider response")
	}
	nic := res.Nic
	// ip, err := s.addPublicIP(&nic)
	if len(res.Nic.PrivateIps) < 1 {
		return nil, scerr.InconsistentError("Inconsistent provider response")
	}

	err = s.setResourceTags(nic.NicId, map[string]string{
		"name": name,
	})
	if err != nil {
		return nil, err
	}
	// primary := deviceNumber == 0
	return &resources.VirtualIP{
		ID:        nic.NicId,
		PrivateIP: nic.PrivateIps[0].PrivateIp,
		NetworkID: netID,
		Hosts:     nil,
		PublicIP:  "",
	}, nil
}

// AddPublicIPToVIP adds a public IP to VIP
func (s *Stack) AddPublicIPToVIP(*resources.VirtualIP) error {
	if s == nil {
		return scerr.InvalidInstanceError()
	}

	return scerr.NotImplementedError("AddPublicIPToVIP() not implemented yet")
}

func (s *Stack) getFirstFreeDeviceNumber(hostID string) (int64, error) {
	readNicsRequest := osc.ReadNicsRequest{
		Filters: osc.FiltersNic{
			LinkNicVmIds: []string{hostID},
		},
	}
	res, _, err := s.client.NicApi.ReadNics(s.auth, &osc.ReadNicsOpts{
		ReadNicsRequest: optional.NewInterface(readNicsRequest),
	})
	if err != nil {
		return 0, err
	}
	// No nics linked to the VM
	if len(res.Nics) == 0 {
		return -1, scerr.NewErrCore("no nics linked to the VM", nil, nil)
	}
	var numbers sort.IntSlice
	for _, nic := range res.Nics {
		numbers = append(numbers, int(nic.LinkNic.DeviceNumber))
	}

	if numbers == nil {
		return 0, scerr.NewErrCore("no nics linked to the VM", nil, nil)
	}

	sort.Sort(numbers)
	for i := 1; i <= 7; i++ {
		if idx := sort.SearchInts(numbers, i); idx < 0 || idx >= numbers.Len() {
			return int64(i), nil
		}
	}
	return 0, scerr.InvalidRequestError(fmt.Sprintf("No more free device on host %s", hostID))
}

// BindHostToVIP makes the host passed as parameter an allowed "target" of the VIP
func (s *Stack) BindHostToVIP(vip *resources.VirtualIP, hostID string) error {
	if s == nil {
		return scerr.InvalidInstanceError()
	}
	if vip == nil {
		return scerr.InvalidParameterError("vip", "cannot be nil")
	}
	if hostID == "" {
		return scerr.InvalidParameterError("host", "cannot be empty string")
	}
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
	// 	return err
	// }
	// if res == nil || (res.OK != nil && len(res.OK.Nics) > 1) {
	// 	return scerr.InconsistentError("Inconsistent provider response")
	// }
	// if res.OK == nil || len(res.OK.Nics) == 0 {
	// 	return scerr.InvalidParameterError("vip", "VIP does not exixt")
	// }
	// _, err = s.client.POST_LinkNic(osc.LinkNicRequest{
	// 	NicId:        res.OK.Nics[0].NicId,
	// 	VmId:         hostID,
	// 	DeviceNumber: deviceNumber,
	// })
	// if err != nil {
	// 	logrus.Errorf("BindHostToVIP %v", err)
	// 	return err
	// }
	return nil

}

// UnbindHostFromVIP removes the bind between the VIP and a host
func (s *Stack) UnbindHostFromVIP(vip *resources.VirtualIP, hostID string) error {
	if s == nil {
		return scerr.InvalidInstanceError()
	}
	if vip == nil {
		return scerr.InvalidParameterError("vip", "cannot be nil")
	}
	if hostID == "" {
		return scerr.InvalidParameterError("host", "cannot be empty string")
	}
	// res, err := s.client.POST_ReadNics(osc.ReadNicsRequest{
	// 	Filters: osc.FiltersNic{
	// 		NicIds: []string{vip.ID},
	// 	},
	// })
	// if err != nil {
	// 	return err
	// }
	// if res == nil || (res.OK != nil && len(res.OK.Nics) > 1) {
	// 	return scerr.InconsistentError("Inconsistent provider response")
	// }
	// if res.OK == nil || len(res.OK.Nics) == 0 {
	// 	return scerr.InvalidParameterError("vip", "VIP does not exixt")
	// }
	// nic := res.OK.Nics[0]
	// _, err = s.client.POST_UnlinkNic(osc.UnlinkNicRequest{
	// 	LinkNicId: nic.LinkNic.LinkNicId,
	// })
	// return err
	return nil
}

// DeleteVIP deletes the port corresponding to the VIP
func (s *Stack) DeleteVIP(vip *resources.VirtualIP) error {
	if s == nil {
		return scerr.InvalidInstanceError()
	}
	if vip == nil {
		return scerr.InvalidParameterError("vip", "cannot be nil")
	}

	deleteNicRequest := osc.DeleteNicRequest{
		NicId: vip.ID,
	}
	_, _, err := s.client.NicApi.DeleteNic(s.auth, &osc.DeleteNicOpts{
		DeleteNicRequest: optional.NewInterface(deleteNicRequest),
	})
	if err != nil {
		return err
	}
	deletePublicIpRequest := osc.DeletePublicIpRequest{
		PublicIp: vip.PublicIP,
	}
	_, _, err = s.client.PublicIpApi.DeletePublicIp(s.auth, &osc.DeletePublicIpOpts{
		DeletePublicIpRequest: optional.NewInterface(deletePublicIpRequest),
	})

	return err
}
