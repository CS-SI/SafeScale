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

// VPL: Not used ? duplicate with DoCIDRsIntersect
// CIDROverlap tells if the 2 CIDR passed as parameter intersect
func CIDROverlap(n1, n2 net.IPNet) bool {
    return n2.Contains(n1.IP) || n1.Contains(n2.IP)
}

type CIDRString string

// Contains tells if 'cs' contains 'cidr'
func (cs CIDRString) Contains(cidr CIDRString) (bool, error) {
    _, sourceDesc, _ := net.ParseCIDR(string(cs))
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

type CIDR net.IPNet

// Contains tells if 'cs' contains 'cidr'
func (c CIDR) Contains(cidr CIDR) bool {
    return c.Contains(cidr)
}

// IntersectsWith tells if the 2 cidr intersects
func (c CIDR) IntersectsWith(cidr CIDR) bool {
    return c.Contains(cidr) || cidr.Contains(c)
}

func DoCIDRsIntersect(cidr1, cidr2 string) (bool, error) {
    _, cidr1Desc, _ := net.ParseCIDR(cidr1)
    _, cidr2Desc, err := net.ParseCIDR(cidr2)
    if err != nil {
        return false, err
    }
    return cidr2Desc.Contains(cidr1Desc.IP) || cidr1Desc.Contains(cidr2Desc.IP), nil
}

func init() {
    notRoutables := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

    for _, n := range notRoutables {
        _, ipnet, _ := net.ParseCIDR(n)
        networks[n] = ipnet
    }
}
