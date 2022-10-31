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

package propertiesv2

import (
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
)

// ClusterNode describes a node in the cluster
// !!! FROZEN !!!
type ClusterNode struct {
	ID          string `json:"id"`         // ID of the node
	NumericalID uint   `json:"intid"`      // Numerical (unsigned integer) ID of the node
	Name        string `json:"name"`       // GetName of the node
	PublicIP    string `json:"public_ip"`  // public ip of the node
	PrivateIP   string `json:"private_ip"` // private ip of the node
}

// ClusterNodes contains all the nodes created in the cluster
// !!! FROZEN !!!
type ClusterNodes struct {
	Masters          []*ClusterNode `json:"masters,omitempty"`            // Masters contains the ID of the masters
	PublicNodes      []*ClusterNode `json:"public_nodes,omitempty"`       // PublicNodes is a slice of IDs of the public cluster nodes
	PrivateNodes     []*ClusterNode `json:"private_nodes,omitempty"`      // PrivateNodes is a slice of IDs of the private cluster nodes
	MasterLastIndex  int            `json:"master_last_index,omitempty"`  // MasterLastIndex
	PrivateLastIndex int            `json:"private_last_index,omitempty"` // PrivateLastIndex
	PublicLastIndex  int            `json:"public_last_index,omitempty"`  // PublicLastIndex
	GlobalLastIndex  uint           `json:"global_last_index,omitempty"`  // is used to keep of the index associated to the last created node
}

func newClusterNodes() *ClusterNodes {
	return &ClusterNodes{
		Masters:         []*ClusterNode{},
		PublicNodes:     []*ClusterNode{},
		PrivateNodes:    []*ClusterNode{},
		GlobalLastIndex: 10, // Keep some places for special cases, like gateways NumericalID
	}
}

// IsNull ...
// satisfies interface clonable.Clonable
func (n *ClusterNodes) IsNull() bool {
	return n == nil || (len(n.Masters) == 0 && len(n.PublicNodes) == 0 && len(n.PrivateNodes) == 0)
}

// Clone ...
// satisfies interface clonable.Clonable
func (n *ClusterNodes) Clone() (clonable.Clonable, error) {
	if n == nil {
		return nil, fail.InvalidInstanceError()
	}

	nn := newClusterNodes()
	return nn, nn.Replace(n)
}

// Replace ...
// satisfies interface clonable.Clonable
func (n *ClusterNodes) Replace(p clonable.Clonable) error {
	if n == nil {
		return fail.InvalidInstanceError()
	}

	src, err := lang.Cast[*ClusterNodes](p)
	if err != nil {
		return err
	}

	*n = *src
	n.Masters = make([]*ClusterNode, 0, len(src.Masters))
	// copy(n.Masters, src.Masters)
	for _, v := range src.Masters {
		node := *v
		n.Masters = append(n.Masters, &node)
	}

	n.PrivateNodes = make([]*ClusterNode, 0, len(src.PrivateNodes))
	// copy(n.PrivateNodes, src.PrivateNodes)
	for _, v := range src.PrivateNodes {
		node := *v
		n.PrivateNodes = append(n.PrivateNodes, &node)
	}
	return nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.cluster", clusterproperty.NodesV2, newClusterNodes())
}
