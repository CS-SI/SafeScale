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
