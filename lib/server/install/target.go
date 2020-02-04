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

package install

import (
	"github.com/CS-SI/SafeScale/lib/server/install/enums/method"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"

	clusterapi "github.com/CS-SI/SafeScale/lib/server/cluster/api"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/flavor"

	pb "github.com/CS-SI/SafeScale/lib"
)

//go:generate mockgen -destination=../mocks/mock_target.go -package=mocks github.com/CS-SI/SafeScale/lib/server/install Target

// Target is an interface that target must satisfy to be able to install something on it
type Target interface {
	// Name returns the name of the target
	Name() string
	// Type returns the name of the target
	Type() string
	// Methods returns a list of installation methods usable on the target, ordered from
	// upper to lower priority (1 = highest priority)
	Methods() map[uint8]method.Enum
	// Installed returns a list of installed features
	Installed() []string
}

// HostTarget defines a target of type Host, satisfying TargetAPI
type HostTarget struct {
	host    *pb.Host
	methods map[uint8]method.Enum
	name    string
}

// NewHostTarget ...
func NewHostTarget(host *pb.Host) (Target, error) {
	if host == nil {
		return nil, scerr.InvalidParameterError("host", "cannot be nil")
	}
	return createHostTarget(host)
}

// createHostTarget ...
func createHostTarget(host *pb.Host) (*HostTarget, error) {
	var (
		index   uint8
		methods = map[uint8]method.Enum{}
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
	methods[index] = method.Apt
	//case "fedora":
	//	index++
	//	methods[index] = Method.Dnf
	//}
	index++
	methods[index] = method.Bash
	return &HostTarget{
		host:    host,
		methods: methods,
		name:    host.Name,
	}, nil
}

// Type returns the type of the Target
func (t *HostTarget) Type() string {
	return "host"
}

// Name returns the name of the Target
func (t *HostTarget) Name() string {
	return t.name
}

// Methods returns a list of packaging managers usable on the target
func (t *HostTarget) Methods() map[uint8]method.Enum {
	return t.methods
}

// Installed returns a list of installed features
func (t *HostTarget) Installed() []string {
	var list []string
	return list
}

// ClusterTarget defines a target of type Host, satisfying TargetAPI
type ClusterTarget struct {
	cluster clusterapi.Cluster
	methods map[uint8]method.Enum
	name    string
}

// NewClusterTarget ...
func NewClusterTarget(task concurrency.Task, cluster clusterapi.Cluster) (Target, error) {
	if cluster == nil {
		return nil, scerr.InvalidParameterError("cluster", "cannot be nil")
	}
	var (
		index   uint8
		methods = map[uint8]method.Enum{}
	)
	identity := cluster.GetIdentity(task)
	if identity.Flavor == flavor.DCOS {
		index++
		methods[index] = method.DCOS
	}
	index++
	methods[index] = method.Bash
	return &ClusterTarget{
		cluster: cluster,
		methods: methods,
		name:    identity.Name,
	}, nil
}

// Type returns the type of the Target
func (t *ClusterTarget) Type() string {
	return "cluster"
}

// Name returns the name of the cluster
func (t *ClusterTarget) Name() string {
	return t.name
}

// Methods returns a list of packaging managers usable on the target
func (t *ClusterTarget) Methods() map[uint8]method.Enum {
	return t.methods
}

// Installed returns a list of installed feature
func (t *ClusterTarget) Installed() []string {
	var list []string
	return list
}

// NodeTarget defines a target of type Node of cluster, including a master
type NodeTarget struct {
	*HostTarget
}

// NewNodeTarget ...
func NewNodeTarget(host *pb.Host) (Target, error) {
	if host == nil {
		return nil, scerr.InvalidParameterError("host", "cannot be nil")
	}
	t, err := createHostTarget(host)
	if err != nil {
		return nil, err
	}
	return &NodeTarget{HostTarget: t}, nil
}

// Type returns the type of the Target
func (t *NodeTarget) Type() string {
	return "node"
}
