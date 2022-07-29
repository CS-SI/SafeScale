/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

package net

import (
	"net"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// FirstIncludedSubnet takes a parent CIDR range and gives the first subnet within it
// with the given number of additional prefix bits 'maskAddition'.
//
// For example, 192.168.0.0/16, extended by 8 bits becomes 192.168.0.0/24.
func FirstIncludedSubnet(base net.IPNet, maskAddition uint8) (net.IPNet, fail.Error) {
	return NthIncludedSubnet(base, maskAddition, 0)
}

// NthIncludedSubnet takes a parent CIDR range and gives the 'nth' subnet within it with the
// given numver of additional prefix bits 'maskAddition'
//
// For example, 192.168.0.0/16, extended by 8 bits gives as 4th subnet 192.168.4.0/24.
func NthIncludedSubnet(base net.IPNet, maskAddition uint8, nth uint) (net.IPNet, fail.Error) {
	ip := base.IP
	mask := base.Mask

	parentLen, addrLen := mask.Size()
	newPrefixLen := parentLen + int(maskAddition)

	if newPrefixLen > addrLen {
		return net.IPNet{}, fail.OverflowError(nil, uint(addrLen), "insufficient address space to extend prefix of %d by %d", parentLen, maskAddition)
	}

	var maxNetNum uint64 = 1<<maskAddition - 1
	if uint64(1) > maxNetNum {
		return net.IPNet{}, fail.OverflowError(nil, uint(maxNetNum), "prefix extension of %d does not accommodate a subnet", maskAddition)
	}

	ipAsNumber := IPv4ToUInt32(ip)
	bitShift := uint32(32 - newPrefixLen)
	ipAsNumber |= uint32(nth) << bitShift
	return net.IPNet{
		IP:   UInt32ToIPv4(ipAsNumber),
		Mask: net.CIDRMask(newPrefixLen, addrLen),
	}, nil
}
