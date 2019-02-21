/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package propertiesv1

import (
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/Property"
	"github.com/CS-SI/SafeScale/utils/serialize"
)

// Node ...
type Node struct {
	ID        string `json:"id"`         // ID of the node
	PublicIP  string `json:"public_ip"`  // public ip of the node
	PrivateIP string `json:"private_ip"` // private ip of the node
}

// Nodes ...
type Nodes struct {
	Masters          []*Node `json:"masters"`                 // MasterIDs contains the ID of the masters
	PublicNodes      []*Node `json:"public_nodes,omitempty"`  // PublicNodeIDs is a slice of IDs of the public cluster nodes
	PrivateNodes     []*Node `json:"private_nodes,omitempty"` // PrivateNodedIDs is a slice of IDs of the private cluster nodes
	MasterLastIndex  int     `json:"master_last_index"`       // MasterLastIndex
	PrivateLastIndex int     `json:"private_last_index"`      // PrivateLastIndex
	PublicLastIndex  int     `json:"public_last_index"`       // PublicLastIndex
}

func newNodes() *Nodes {
	return &Nodes{
		Masters:      []*Node{},
		PublicNodes:  []*Node{},
		PrivateNodes: []*Node{},
	}
}

// Content ... (serialize.Property interface)
func (n *Nodes) Content() interface{} {
	return n
}

// Clone ... (serialize.Property interface)
func (n *Nodes) Clone() serialize.Property {
	return newNodes().Replace(n)
}

// Replace ... (serialize.Property interface)
func (n *Nodes) Replace(p serialize.Property) serialize.Property {
	src := p.(*Nodes)
	*n = *src
	n.Masters = make([]*Node, len(src.Masters))
	n.PublicNodes = make([]*Node, len(src.PublicNodes))
	n.PrivateNodes = make([]*Node, len(src.PrivateNodes))
	for k, v := range src.Masters {
		n.Masters[k] = v
	}
	for k, v := range src.PublicNodes {
		n.PublicNodes[k] = v
	}
	for k, v := range src.PrivateNodes {
		n.PrivateNodes[k] = v
	}
	return n
}

func init() {
	serialize.PropertyTypeRegistry.Register("clusters", Property.NodesV1, newNodes())
}
