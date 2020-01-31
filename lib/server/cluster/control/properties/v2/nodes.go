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
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/property"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// Node describes a Node in the cluster
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with updated/additional fields
type Node struct {
	ID          string `json:"id"`         // ID of the node
	NumericalID uint   `json:"intid"`      // Numerical (unsigned integer) ID of the node
	Name        string `json:"name"`       // Name of the node
	PublicIP    string `json:"public_ip"`  // public ip of the node
	PrivateIP   string `json:"private_ip"` // private ip of the node
}

// Nodes contains all the nodes created in the cluster
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with updated/additional fields
type Nodes struct {
	Masters          []*Node `json:"masters"`                 // Masters contains the ID of the masters
	PublicNodes      []*Node `json:"public_nodes,omitempty"`  // PublicNodes is a slice of IDs of the public cluster nodes
	PrivateNodes     []*Node `json:"private_nodes,omitempty"` // PrivateNodes is a slice of IDs of the private cluster nodes
	MasterLastIndex  int     `json:"master_last_index"`       // MasterLastIndex
	PrivateLastIndex int     `json:"private_last_index"`      // PrivateLastIndex
	PublicLastIndex  int     `json:"public_last_index"`       // PublicLastIndex
	GlobalLastIndex  uint    `json:"global_last_index"`       // GlobalLastIndes is used to keep of the index associated to the last created node
}

func newNodes() *Nodes {
	return &Nodes{
		Masters:         []*Node{},
		PublicNodes:     []*Node{},
		PrivateNodes:    []*Node{},
		GlobalLastIndex: 10, // Keep some places for special cases, like gateways NumericalID
	}
}

// Content ...
// satisfies interface data.Clonable
func (n *Nodes) Content() data.Clonable {
	return n
}

// Clone ...
// satisfies interface data.Clonable
func (n *Nodes) Clone() data.Clonable {
	return newNodes().Replace(n)
}

// Replace ...
// satisfies interface data.Clonable
func (n *Nodes) Replace(p data.Clonable) data.Clonable {
	src := p.(*Nodes)
	*n = *src
	n.Masters = make([]*Node, len(src.Masters))
	for k, v := range src.Masters {
		newV := *v
		n.Masters[k] = &newV
	}
	n.PublicNodes = make([]*Node, len(src.PublicNodes))
	for k, v := range src.PublicNodes {
		newV := *v
		n.PublicNodes[k] = &newV
	}
	n.PrivateNodes = make([]*Node, len(src.PrivateNodes))
	for k, v := range src.PrivateNodes {
		newV := *v
		n.PrivateNodes[k] = &newV
	}
	return n
}

func init() {
	serialize.PropertyTypeRegistry.Register("clusters", property.NodesV2, newNodes())
}
