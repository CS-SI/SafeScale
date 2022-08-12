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

package propertiesv3

import (
	"fmt"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
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
// Not frozen yet
type ClusterNodes struct {
	Masters           []uint                `json:"masters,omitempty"`
	MasterByName      map[string]uint       `json:"master_by_name,omitempty"`
	MasterByID        map[string]uint       `json:"master_by_id,omitempty"`
	PrivateNodes      []uint                `json:"private_nodes,omitempty"`
	PrivateNodeByName map[string]uint       `json:"private_node_by_name,omitempty"`
	PrivateNodeByID   map[string]uint       `json:"private_node_by_id,omitempty"`
	PublicNodes       []uint                `json:"public_nodes,omitempty"`
	PublicNodeByName  map[string]uint       `json:"public_node_by_name,omitempty"`
	PublicNodeByID    map[string]uint       `json:"public_node_by_id,omitempty"`
	ByNumericalID     map[uint]*ClusterNode `json:"host_by_numeric_id,omitempty"` // maps *ClusterNode with NumericalID
	MasterLastIndex   int                   `json:"master_last_index,omitempty"`  // is used to keep the index associated to the name of the last created master
	PrivateLastIndex  int                   `json:"private_last_index,omitempty"` // is used to keep the index associated to the name of the last created private node
	PublicLastIndex   int                   `json:"public_last_index,omitempty"`  // is used to keep the index associated to the name of the last created public node
	GlobalLastIndex   uint                  `json:"global_last_index,omitempty"`  // is used to keep the index associated to the last created ClusterNode (being master or node)
}

func newClusterNodes() *ClusterNodes {
	return &ClusterNodes{
		Masters:      []uint{},
		MasterByName: map[string]uint{},
		MasterByID:   map[string]uint{},
		// PublicNodes:     []uint{},
		// PublicNodeByName: map[string]uint{},
		// PublicNodeByID: map[string]uint{},
		PrivateNodes:      []uint{},
		PrivateNodeByName: map[string]uint{},
		PrivateNodeByID:   map[string]uint{},
		ByNumericalID:     map[uint]*ClusterNode{},
		GlobalLastIndex:   10, // Keep some places for special cases, like gateways NumericalID
	}
}

// IsNull ...
// satisfies interface data.Clonable
func (n *ClusterNodes) IsNull() bool {
	return n == nil || (len(n.ByNumericalID) == 0 && n.GlobalLastIndex <= 10)
}

// Clone ...
// satisfies interface data.Clonable
func (n ClusterNodes) Clone() (data.Clonable, error) {
	return newClusterNodes().Replace(&n)
}

// Replace ...
// satisfies interface data.Clonable
func (n *ClusterNodes) Replace(p data.Clonable) (data.Clonable, error) {
	if n == nil || p == nil {
		return nil, fail.InvalidInstanceError()
	}

	src, ok := p.(*ClusterNodes)
	if !ok {
		return nil, fmt.Errorf("p is not a *ClusterNodes")
	}

	*n = *src

	n.Masters = make([]uint, len(src.Masters))
	copy(n.Masters, src.Masters)

	n.MasterByName = make(map[string]uint, len(src.MasterByName))
	for k, v := range src.MasterByName {
		n.MasterByName[k] = v
	}

	n.MasterByID = make(map[string]uint, len(src.MasterByID))
	for k, v := range src.MasterByID {
		n.MasterByID[k] = v
	}

	n.PrivateNodes = make([]uint, len(src.PrivateNodes))
	copy(n.PrivateNodes, src.PrivateNodes)

	n.PrivateNodeByName = make(map[string]uint, len(src.PrivateNodeByName))
	for k, v := range src.PrivateNodeByName {
		n.PrivateNodeByName[k] = v
	}

	n.PrivateNodeByID = make(map[string]uint, len(src.PrivateNodeByID))
	for k, v := range src.PrivateNodeByID {
		n.PrivateNodeByID[k] = v
	}

	n.ByNumericalID = make(map[uint]*ClusterNode, len(src.ByNumericalID))
	for k, v := range src.ByNumericalID {
		node := *v
		n.ByNumericalID[k] = &node
	}

	return n, nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.cluster", clusterproperty.NodesV3, newClusterNodes())
}
