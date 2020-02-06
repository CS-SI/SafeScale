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

package propertiesv2

import (
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// ClusterNode describes a Node in the cluster
type ClusterNode struct {
	ID          string `json:"id"`         // ID of the node
	NumericalID uint   `json:"intid"`      // Numerical (unsigned integer) ID of the node
	Name        string `json:"name"`       // Name of the node
	PublicIP    string `json:"public_ip"`  // public ip of the node
	PrivateIP   string `json:"private_ip"` // private ip of the node
}

// ClusterNodes contains all the nodes created in the cluster
type ClusterNodes struct {
	Masters          []*ClusterNode `json:"masters"`                 // Masters contains the ID of the masters
	PublicNodes      []*ClusterNode `json:"public_nodes,omitempty"`  // PublicNodes is a slice of IDs of the public cluster nodes
	PrivateNodes     []*ClusterNode `json:"private_nodes,omitempty"` // PrivateNodes is a slice of IDs of the private cluster nodes
	MasterLastIndex  int            `json:"master_last_index"`       // MasterLastIndex
	PrivateLastIndex int            `json:"private_last_index"`      // PrivateLastIndex
	PublicLastIndex  int            `json:"public_last_index"`       // PublicLastIndex
	GlobalLastIndex  uint           `json:"global_last_index"`       // GlobalLastIndes is used to keep of the index associated to the last created node
}

func newClusterNodes() *ClusterNodes {
	return &ClusterNodes{
		Masters:         []*ClusterNode{},
		PublicNodes:     []*ClusterNode{},
		PrivateNodes:    []*ClusterNode{},
		GlobalLastIndex: 10, // Keep some places for special cases, like gateways NumericalID
	}
}

// Content ... (data.Clonable interface)
func (n *ClusterNodes) Content() interface{} {
	return n
}

// Clone ... (data.Clonable interface)
func (n *ClusterNodes) Clone() data.Clonable {
	return newClusterNodes().Replace(n)
}

// Replace ... (data.Clonable interface)
func (n *ClusterNodes) Replace(p data.Clonable) data.Clonable {
	src := p.(*ClusterNodes)
	*n = *src
	n.Masters = make([]*ClusterNode, len(src.Masters))
	copy(n.Masters, src.Masters)
	n.PublicNodes = make([]*ClusterNode, len(src.PublicNodes))
	copy(n.PublicNodes, src.PublicNodes)
	n.PrivateNodes = make([]*ClusterNode, len(src.PrivateNodes))
	copy(n.PrivateNodes, src.PrivateNodes)
	return n
}

func init() {
	serialize.PropertyTypeRegistry.Register("clusters", string(clusterproperty.NodesV2), newClusterNodes())
}
