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

// GetName returns the name of the Target
func (t *HostTarget) GetName() string {
	return t.host.GetName()
}

// GetMethods returns a list of packaging managers useable on the target
func (t *HostTarget) GetMethods() []Method.Enum {
	methods := []Method.Enum{
		Method.Bash,
	}
	// TODO: défines the managers available for a host to be able to get it there
	methods = append(methods, Method.Apt) // hardcoded, bad !
	return methods
}

// List returns a list of installed components
func (t *HostTarget) List() []string {
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

// GetMethods returns a list of packaging managers useable on the target
func (t *ClusterTarget) GetMethods() []Method.Enum {
	methods := []Method.Enum{
		Method.Bash,
	}
	if t.cluster.GetConfig().Flavor == Flavor.DCOS {
		methods = append(methods, Method.DCOS)
	}
	return methods
}

// List returns a list of installed component
func (t *ClusterTarget) List() []string {
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
