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
	"fmt"
	"net"
)

// ActiveNics returns a list of active network interface
func ActiveNics() ([]net.Interface, error) {
	var upNics, loNics []net.Interface

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("Failed to get interfaces: %v", err)
	}

	for _, iface := range interfaces {
		// Require interface to be up
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		if iface.Flags&net.FlagLoopback != 0 {
			loNics = append(loNics, iface)
			continue
		}

		upNics = append(upNics, iface)
	}

	if len(upNics) == 0 {
		return loNics, nil
	}

	return upNics, nil
}

// ActiveNicsWithPrivateIPv4 returns a list of active network interface with private IPv4
func ActiveNicsWithPrivateIPv4() ([]net.Interface, error) {
	var list []net.Interface

	interfaces, err := ActiveNics()
	if err != nil {
		return nil, fmt.Errorf("Failed to get interfaces: %v", err)
	}

	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
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

			list = append(list, iface)
			break
		}
	}

	return list, nil
}
