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

package net

import (
	"net"
	"strconv"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
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
		return 0, 0, fail.InvalidParameterCannotBeEmptyStringError("cidr")
	}

	var (
		ip    uint32 // ip address
		start uint32 // Start IP address range
		end   uint32 // End IP address range
	)

	var splitted []string
	if strings.Contains(cidr, "/") {
		splitted = strings.Split(cidr, "/")
	} else {
		splitted = []string{
			cidr,
			"32",
		}
	}

	ip = IPv4StringToUInt32(splitted[0])
	bits, err := strconv.ParseUint(splitted[1], 10, 32)
	if err != nil {
		return 0, 0, fail.InvalidParameterError("fail to extract network mask", err)
	}
	if bits > 32 {
		return 0, 0, fail.InvalidParameterError("invalid network mask", err)
	}

	if start == 0 || start > ip {
		start = ip
	}

	ip |= 0xFFFFFFFF >> bits
	if end < ip {
		end = ip
	}

	return start, end, nil
}

// IsCIDRRoutable tells if the network is routable
func IsCIDRRoutable(cidr string) (bool, fail.Error) {
	first, last, xerr := CIDRToIPv4Range(cidr)
	if xerr != nil {
		return false, xerr
	}
	var splitted []string
	if strings.Contains(cidr, "/") {
		splitted = strings.Split(cidr, "/")
	} else {
		splitted = []string{
			cidr,
			"32",
		}
	}
	firstIP, _, err := net.ParseCIDR(first + "/" + splitted[1])
	if err != nil {
		return false, fail.Wrap(err)
	}
	lastIP, _, err := net.ParseCIDR(last + "/" + splitted[1])
	if err != nil {
		return false, fail.Wrap(err)
	}

	for _, nr := range networks {
		if nr.Contains(firstIP) && nr.Contains(lastIP) {
			return false, nil
		}
	}
	return true, nil
}

// CIDROverlap VPL: Not used ? duplicate with DoCIDRsIntersect
// CIDROverlap tells if the 2 CIDR passed as parameter intersect
func CIDROverlap(n1, n2 net.IPNet) bool {
	return n2.Contains(n1.IP) || n1.Contains(n2.IP)
}

// CIDRString string representing a CIDR
type CIDRString string

// Contains tells if 'cs' contains 'cidr'
func (cs CIDRString) Contains(cidr CIDRString) (bool, error) {
	_, sourceDesc, err := net.ParseCIDR(string(cs))
	if err != nil {
		return false, err
	}
	_, targetDesc, err := net.ParseCIDR(string(cidr))
	if err != nil {
		return false, err
	}
	return sourceDesc.Contains(targetDesc.IP), nil
}

// IntersectsWith tells if the 2 cidr intersects
func (cs CIDRString) IntersectsWith(cidr CIDRString) (bool, error) {
	l2r, err := cs.Contains(cidr)
	if err != nil {
		return false, err
	}
	r2l, err := cidr.Contains(cs)
	if err != nil {
		return false, err
	}
	return l2r || r2l, nil
}

// init initializes networks variable with parsed not routable CIDRs
func init() {
	notRoutables := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

	for _, n := range notRoutables {
		_, ipnet, _ := net.ParseCIDR(n)
		networks[n] = ipnet
	}
}
