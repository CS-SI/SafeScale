/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

package install

import (
	"github.com/CS-SI/SafeScale/deploy/install/enums/Method"

	clusterapi "github.com/CS-SI/SafeScale/deploy/cluster/api"
	"github.com/CS-SI/SafeScale/deploy/cluster/api/Flavor"

	pb "github.com/CS-SI/SafeScale/broker"
)

// Target is an interface that target must satisfy to be able to install something
// on it
type Target interface {
	// Name returns the name of the target
	Name() string
	// Type returns the name of the target
	Type() string
	// Methods returns a list of installation methods useable on the target, ordered from
	// upper to lower priority (1 = highest priority)
	Methods() map[uint8]Method.Enum
	// Installed returns a list of installed components
	Installed() []string
}

// HostTarget defines a target of type Host, satisfying TargetAPI
type HostTarget struct {
	host    *pb.Host
	methods map[uint8]Method.Enum
}

// NewHostTarget ...
func NewHostTarget(host *pb.Host) Target {
	if host == nil {
		panic("host is nil!")
	}
	return createHostTarget(host)
}

// createHostTarget ...
func createHostTarget(host *pb.Host) *HostTarget {
	var (
		index   uint8
		methods = map[uint8]Method.Enum{}
	)
	//TODO: LinuxKind field doesn't exist, it should contain the $LINUX_KIND value
	//switch host.LinuxKind {
	//case "centos":
	//	fallthrough
	//case "redhat":
	//	index++
	//	methods[index] = Method.Yum
	//case "debian":
	//	fallthrough
	//case "ubuntu":
	index++
	methods[index] = Method.Apt
	//case "fedora":
	//	index++
	//	methods[index] = Method.Dnf
	//}
	index++
	methods[index] = Method.Bash
	return &HostTarget{
		host:    host,
		methods: methods,
	}
}

// Type returns the type of the Target
func (t *HostTarget) Type() string {
	return "host"
}

// Name returns the name of the Target
func (t *HostTarget) Name() string {
	return t.host.GetName()
}

// Methods returns a list of packaging managers useable on the target
func (t *HostTarget) Methods() map[uint8]Method.Enum {
	return t.methods
}

// Installed returns a list of installed components
func (t *HostTarget) Installed() []string {
	var list []string
	return list
}

// ClusterTarget defines a target of type Host, satisfying TargetAPI
type ClusterTarget struct {
	cluster clusterapi.Cluster
	methods map[uint8]Method.Enum
}

// NewClusterTarget ...
func NewClusterTarget(cluster clusterapi.Cluster) Target {
	if cluster == nil {
		panic("cluster is nil!")
	}
	var (
		index   uint8
		methods = map[uint8]Method.Enum{}
	)
	if cluster.GetConfig().Flavor == Flavor.DCOS {
		index++
		methods[index] = Method.DCOS
	}
	index++
	methods[index] = Method.Bash
	return &ClusterTarget{
		cluster: cluster,
		methods: methods,
	}
}

// Type returns the type of the Target
func (t *ClusterTarget) Type() string {
	return "cluster"
}

// Name returns the name of the cluster
func (t *ClusterTarget) Name() string {
	return t.cluster.GetName()
}

// Methods returns a list of packaging managers useable on the target
func (t *ClusterTarget) Methods() map[uint8]Method.Enum {
	return t.methods
}

// Installed returns a list of installed component
func (t *ClusterTarget) Installed() []string {
	var list []string
	return list
}

// NodeTarget defines a target of type Node of cluster, including a master
type NodeTarget struct {
	*HostTarget
}

// NewNodeTarget ...
func NewNodeTarget(host *pb.Host) Target {
	if host == nil {
		panic("host is nil!")
	}
	return &NodeTarget{
		HostTarget: createHostTarget(host),
	}
}
