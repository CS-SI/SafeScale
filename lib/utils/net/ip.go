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

package net

import (
	"net"
	"strconv"
	"strings"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

var networks = map[string]*net.IPNet{}

// CIDRToIPv4Range converts CIDR to IPv4 range
func CIDRToIPv4Range(cidr string) (string, string, fail.Error) {
	start, end, err := CIDRToUInt32Range(cidr)
	if err != nil {
		return "", "", err
	}

	ipStart := UInt32ToIPv4String(start)
	ipEnd := UInt32ToIPv4String(end)

	return ipStart, ipEnd, nil
}

// CIDRToUInt32Range converts CIDR to IPv4 range
func CIDRToUInt32Range(cidr string) (uint32, uint32, fail.Error) {
	if cidr == "" {
		return 0, 0, fail.InvalidParameterError("cidr", "cannot be empty string")
	}

	var (
		ip    uint32 // ip address
		start uint32 // Start IP address range
		end   uint32 // End IP address range
	)

	splitted := strings.Split(cidr, "/")
	ip = IPv4StringToUInt32(splitted[0])
	bits, _ := strconv.ParseUint(splitted[1], 10, 32)

	if start == 0 || start > ip {
		start = ip
	}

	ip |= 0xFFFFFFFF >> bits
	if end < ip {
		end = ip
	}

	return start, end, nil
}

// IPv4ToUInt32 converts net.IP to uint32
func IPv4ToUInt32(ip net.IP) uint32 {
	ipv4 := ip.To4() // make sure we have the version with 4 first significant bytes
	result := (uint32(ipv4[0]) << 24) | (uint32(ipv4[1]) << 16) | (uint32(ipv4[2]) << 8) | uint32(ipv4[3])
	return uint32(result)
}

// IPv4StringToUInt32 converts IPv4 to uint32
func IPv4StringToUInt32(ip string) uint32 {
	parts := [4]uint64{}

	for i, v := range strings.SplitN(ip, ".", 4) {
		parts[i], _ = strconv.ParseUint(v, 10, 32)
	}
	result := (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
	return uint32(result)
}

// UInt32ToIPv4 converts uint32 to net.IP
func UInt32ToIPv4(value uint32) net.IP {
	return net.IP{
		byte(value >> 24),
		byte((value & 0x00FFFFFF) >> 16),
		byte((value & 0x0000FFFF) >> 8),
		byte(value & 0x000000FF),
	}
}

// UInt32ToIPv4String converts uint32 to IP
func UInt32ToIPv4String(value uint32) string {
	return UInt32ToIPv4(value).String()
}

// IsCIDRRoutable tells if the network is routable
func IsCIDRRoutable(cidr string) (bool, fail.Error) {
	first, last, err := CIDRToIPv4Range(cidr)
	if err != nil {
		return false, err
	}
	splitted := strings.Split(cidr, "/")
	firstIP, _, _ := net.ParseCIDR(first + "/" + splitted[1])
	lastIP, _, _ := net.ParseCIDR(last + "/" + splitted[1])
	for _, nr := range networks {
		if nr.Contains(firstIP) && nr.Contains(lastIP) {
			return false, nil
		}
	}
	return true, nil
}

// CIDROverlap tells if the 2 CIDR passed as parameter intersect
func CIDROverlap(n1, n2 net.IPNet) bool {
	return n2.Contains(n1.IP) || n1.Contains(n2.IP)
}

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

	maxNetNum := uint64(1<<uint64(maskAddition)) - 1
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

func init() {
	notRoutables := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

	for _, n := range notRoutables {
		_, ipnet, _ := net.ParseCIDR(n)
		networks[n] = ipnet
	}
}
