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
	"fmt"
	"net"
	"strconv"
	"strings"
)

// IPv4ToUInt32 converts net.IP to uint32
func IPv4ToUInt32(ip net.IP) uint32 {
	ipv4 := ip.To4() // make sure we have the version with 4 first significant bytes
	result := (uint32(ipv4[0]) << 24) | (uint32(ipv4[1]) << 16) | (uint32(ipv4[2]) << 8) | uint32(ipv4[3])
	return result
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
	// Care, net.IP is [16]byte for ip v6, use ipv4 constructor
	return net.IPv4(
		byte(value>>24),
		byte((value&0x00FFFFFF)>>16),
		byte((value&0x0000FFFF)>>8),
		byte(value&0x000000FF),
	)
}

// UInt32ToIPv4String converts uint32 to IP
func UInt32ToIPv4String(value uint32) string {
	return UInt32ToIPv4(value).String()
}

// PrivateIPv4OfNic returns a slice of hosted privater IPv4 by nic
func PrivateIPv4OfNic(nic net.Interface) ([]string, error) {
	var list []string

	addresses, err := nic.Addrs()
	if err != nil {
		return nil, err
	}

	for _, rawAddr := range addresses {
		var ip net.IP
		switch addr := rawAddr.(type) {
		case *net.IPAddr:
			ip = addr.IP
		case *net.IPNet:
			ip = addr.IP
		default:
			continue
		}
		if ip.To4() == nil {
			continue
		}
		if !isPrivate(ip) {
			continue
		}
		list = append(list, ip.String())
	}
	return list, nil
}

// AllActivePrivateIPv4s returns the list of private network IPv4 addresses on all active interfaces
func AllActivePrivateIPv4s() ([]string, error) {
	nics, err := ActiveNics()
	if err != nil {
		return nil, fmt.Errorf("failed to get active interfaces: %v", err)
	}

	var addrs []string
	for _, item := range nics {
		addresses, err := item.Addrs()
		if err != nil {
			return nil, err
		}

		var ip net.IP
		for _, rawAddr := range addresses {
			switch addr := rawAddr.(type) {
			case *net.IPAddr:
				ip = addr.IP
			case *net.IPNet:
				ip = addr.IP
			default:
				continue
			}
			if ip.To4() == nil {
				continue
			}
			if !isPrivate(ip) {
				continue
			}
			addrs = append(addrs, ip.String())
		}
	}
	return addrs, nil
}

// privateBlocks contains non-forwardable address blocks which are used
// for private networks. RFC 6890 provides an overview of special
// address blocks.
var privateBlocks = []*net.IPNet{
	parseCIDR("10.0.0.0/8"),     // RFC 1918 IPv4 private network address
	parseCIDR("100.64.0.0/10"),  // RFC 6598 IPv4 shared address space
	parseCIDR("127.0.0.0/8"),    // RFC 1122 IPv4 loopback address
	parseCIDR("172.16.0.0/12"),  // RFC 1918 IPv4 private network address
	parseCIDR("192.0.0.0/24"),   // RFC 6890 IPv4 IANA address
	parseCIDR("192.0.2.0/24"),   // RFC 5737 IPv4 documentation address
	parseCIDR("192.168.0.0/16"), // RFC 1918 IPv4 private network address
	parseCIDR("::1/128"),        // RFC 1884 IPv6 loopback address
	parseCIDR("fe80::/10"),      // RFC 4291 IPv6 link local addresses
	parseCIDR("fc00::/7"),       // RFC 4193 IPv6 unique local addresses
	parseCIDR("fec0::/10"),      // RFC 1884 IPv6 site-local addresses
	parseCIDR("2001:db8::/32"),  // RFC 3849 IPv6 documentation address
}

// VPL: put out this network of private blocks; it's a special private block known as link-local, and rarely usable...
var linkLocalBlocks = []*net.IPNet{parseCIDR("169.254.0.0/16")} // RFC 3927 IPv4 link local address

func parseCIDR(s string) *net.IPNet {
	_, block, err := net.ParseCIDR(s)
	if err != nil {
		panic(fmt.Sprintf("Bad CIDR %s: %s", s, err))
	}
	return block
}

func isPrivate(ip net.IP) bool {
	for _, priv := range privateBlocks {
		if priv.Contains(ip) {
			return true
		}
	}
	return false
}
