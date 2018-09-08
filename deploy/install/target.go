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
	"github.com/CS-SI/SafeScale/deploy/install/api"
	"github.com/CS-SI/SafeScale/deploy/install/api/Method"

	clusterapi "github.com/CS-SI/SafeScale/deploy/cluster/api"
	"github.com/CS-SI/SafeScale/deploy/cluster/api/Flavor"

	pb "github.com/CS-SI/SafeScale/broker"
)

// HostTarget defines a target of type Host, satisfying TargetAPI
type HostTarget struct {
	host *pb.Host
}

// NewHostTarget ...
func NewHostTarget(host *pb.Host) api.Target {
	if host == nil {
		panic("host is nil!")
	}

	return &HostTarget{host: host}
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
func (t *HostTarget) Methods() []Method.Enum {
	methods := []Method.Enum{
		Method.Bash,
	}
	// TODO: défines the managers available for a host to be able to get it there
	methods = append(methods, Method.Apt) // hardcoded, bad !
	return methods
}

// Installed returns a list of installed components
func (t *HostTarget) Installed() []string {
	var list []string
	return list
}

// ClusterTarget defines a target of type Host, satisfying TargetAPI
type ClusterTarget struct {
	cluster clusterapi.Cluster
}

// NewClusterTarget ...
func NewClusterTarget(cluster clusterapi.Cluster) api.Target {
	if cluster == nil {
		panic("cluster is nil!")
	}
	return &ClusterTarget{
		cluster: cluster,
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
func (t *ClusterTarget) Methods() []Method.Enum {
	methods := []Method.Enum{
		Method.Bash,
	}
	if t.cluster.GetConfig().Flavor == Flavor.DCOS {
		methods = append(methods, Method.DCOS)
	}
	return methods
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
func NewNodeTarget(host *pb.Host) api.Target {
	if host == nil {
		panic("host is nil!")
	}
	return &NodeTarget{
		HostTarget: &HostTarget{host: host},
	}
}
