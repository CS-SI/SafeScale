//go:build allintegration || integration
// +build allintegration integration

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

package helpers

import (
	"fmt"
	"strings"
)

// Names ...
type Names struct {
	Buckets  []string
	Volumes  []string
	Shares   []string
	Hosts    []string
	Networks []string
	Clusters []string
}

func GetNames(coreString string, nbBukets int, nbVolumes int, nbShares int, nbHosts int, nbNetworks int, nbClusters int) Names {
	coreString = strings.ToLower(coreString)

	names := Names{
		Buckets:  []string{},
		Volumes:  []string{},
		Shares:   []string{},
		Hosts:    []string{},
		Networks: []string{},
		Clusters: []string{},
	}

	for i := 1; i <= nbBukets; i++ {
		names.Buckets = append(names.Buckets, fmt.Sprintf("%s-bucket-%d", coreString, i))
	}
	for i := 1; i <= nbVolumes; i++ {
		names.Volumes = append(names.Volumes, fmt.Sprintf("%s-volume-%d", coreString, i))
	}
	for i := 1; i <= nbShares; i++ {
		names.Shares = append(names.Shares, fmt.Sprintf("%s-share-%d", coreString, i))
	}
	for i := 1; i <= nbHosts; i++ {
		names.Hosts = append(names.Hosts, fmt.Sprintf("%s-host-%d", coreString, i))
	}
	for i := 1; i <= nbNetworks; i++ {
		names.Networks = append(names.Networks, fmt.Sprintf("%s-network-%d", coreString, i))
	}
	for i := 1; i <= nbClusters; i++ {
		names.Clusters = append(names.Clusters, fmt.Sprintf("%s-cluster-%d", coreString, i))
	}

	return names
}

func (names *Names) TearDown() {
	// TODO: is it possible to suppress a non empty bucket?
	for _, bucketName := range names.Buckets {
		_, _ = GetTaggedOutput(fmt.Sprintf("safescale bucket delete %s", bucketName), "Teardown: ")
	}
	for _, volumeName := range names.Volumes {
		for _, hostName := range names.Hosts {
			_, _ = GetTaggedOutput(fmt.Sprintf("safescale volume detach %s %s", volumeName, hostName), "Teardown: ")
		}
		_, _ = GetTaggedOutput(fmt.Sprintf("safescale volume delete %s", volumeName), "Teardown: ")
	}
	for _, shareName := range names.Shares {
		for _, hostName := range names.Hosts {
			_, _ = GetTaggedOutput(fmt.Sprintf("safescale share umount %s %s", shareName, hostName), "Teardown: ")
		}
		_, _ = GetTaggedOutput(fmt.Sprintf("safescale share delete %s", shareName), "Teardown: ")
	}
	for _, hostName := range names.Hosts {
		_, _ = GetTaggedOutput(fmt.Sprintf("safescale host delete %s", hostName), "Teardown: ")
	}
	for _, networkName := range names.Networks {
		_, _ = GetTaggedOutput(fmt.Sprintf("safescale network delete %s", networkName), "Teardown: ")
	}
	for _, clusterName := range names.Clusters {
		_, _ = GetTaggedOutput(fmt.Sprintf("safescale cluster delete --yes %s", clusterName), "Teardown: ")
	}
}
