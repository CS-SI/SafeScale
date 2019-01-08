package integration_tests

import (
	"fmt"
	"strings"
)

//Names ...
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
		names.Buckets = append(names.Buckets, fmt.Sprintf("%s_bucket_%d", coreString, i))
	}
	for i := 1; i <= nbVolumes; i++ {
		names.Volumes = append(names.Volumes, fmt.Sprintf("%s_volume_%d", coreString, i))
	}
	for i := 1; i <= nbShares; i++ {
		names.Shares = append(names.Shares, fmt.Sprintf("%s_share_%d", coreString, i))
	}
	for i := 1; i <= nbHosts; i++ {
		names.Hosts = append(names.Hosts, fmt.Sprintf("%s_host_%d", coreString, i))
	}
	for i := 1; i <= nbNetworks; i++ {
		names.Networks = append(names.Networks, fmt.Sprintf("%s_network_%d", coreString, i))
	}
	for i := 1; i <= nbClusters; i++ {
		names.Clusters = append(names.Clusters, fmt.Sprintf("%s_cluster_%d", coreString, i))
	}

	return names
}

func (names *Names) TearDown() {
	//TODO is it possible to supress a non empty bucket?
	for _, bucketName := range names.Buckets {
		_, _ = GetOutput(fmt.Sprintf("broker bucket delete %s", bucketName))
	}
	for _, volumeName := range names.Volumes {
		for _, hostName := range names.Hosts {
			_, _ = GetOutput(fmt.Sprintf("broker volume detach %s %s", volumeName, hostName))
		}
		_, _ = GetOutput(fmt.Sprintf("broker volume delete %s", volumeName))
	}
	for _, shareName := range names.Shares {
		for _, hostName := range names.Hosts {
			_, _ = GetOutput(fmt.Sprintf("broker share umount %s %s", shareName, hostName))
		}
		_, _ = GetOutput(fmt.Sprintf("broker share delete %s", shareName))
	}
	for _, hostName := range names.Hosts {
		_, _ = GetOutput(fmt.Sprintf("broker host delete %s", hostName))
	}
	for _, networkName := range names.Networks {
		_, _ = GetOutput(fmt.Sprintf("broker network delete %s", networkName))
	}
	for _, clusterName := range names.Clusters {
		_, _ = GetOutput(fmt.Sprintf("yes | deploy cluster delete %s", clusterName))
	}
}
