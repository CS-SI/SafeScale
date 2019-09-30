/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package utils

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

var networks = map[string]*net.IPNet{}

// CIDRToIPv4Range converts CIDR to IPv4 range
func CIDRToIPv4Range(cidr string) (string, string, error) {
	start, end, err := CIDRToLongRange(cidr)
	if err != nil {
		return "", "", err
	}

	ipStart := LongToIPv4(start)
	ipEnd := LongToIPv4(end)

	return ipStart, ipEnd, nil
}

// CIDRToLongRange converts CIDR to IPv4 range
func CIDRToLongRange(cidr string) (uint32, uint32, error) {
	if cidr == "" {
		return 0, 0, fmt.Errorf("invalid parameter 'cidr': can't be empty string")
	}

	var (
		ip    uint32 // ip address
		start uint32 // Start IP address range
		end   uint32 // End IP address range
	)

	splitted := strings.Split(cidr, "/")
	ip = IPv4ToLong(splitted[0])
	bits, _ := strconv.ParseUint(splitted[1], 10, 32)

	if start == 0 || start > ip {
		start = ip
	}

	ip = ip | (0xFFFFFFFF >> bits)
	if end < ip {
		end = ip
	}

	return start, end, nil
}

// IPv4ToLong converts IPv4 to uint32
func IPv4ToLong(ip string) uint32 {
	parts := [4]uint64{}

	for i, v := range strings.SplitN(ip, ".", 4) {
		parts[i], _ = strconv.ParseUint(v, 10, 32)
	}

	result := (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
	return uint32(result)
}

// LongToIPv4 converts uint32 to IP
func LongToIPv4(value uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", value>>24, (value&0x00FFFFFF)>>16, (value&0x0000FFFF)>>8, value&0x000000FF)
}

// IsCIDRRoutable tells if the network is routable
func IsCIDRRoutable(cidr string) (bool, error) {
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

func init() {
	notRoutables := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

	for _, n := range notRoutables {
		_, ipnet, _ := net.ParseCIDR(n)
		networks[n] = ipnet
	}
}
