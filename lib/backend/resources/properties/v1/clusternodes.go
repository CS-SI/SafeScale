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

package propertiesv1

import (
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// ClusterNode ...
type ClusterNode struct {
	ID        string `json:"id"`         // ID of the node
	Name      string `json:"name"`       // GetName of the node
	PublicIP  string `json:"public_ip"`  // public ip of the node
	PrivateIP string `json:"private_ip"` // private ip of the node
}

// ClusterNodes ...
type ClusterNodes struct {
	Masters          []*ClusterNode `json:"masters,omitempty"`            // Masters contains the ID of the masters
	PublicNodes      []*ClusterNode `json:"public_nodes,omitempty"`       // PublicNodes is a slice of IDs of the public cluster nodes
	PrivateNodes     []*ClusterNode `json:"private_nodes,omitempty"`      // PrivateNodes is a slice of IDs of the private cluster nodes
	MasterLastIndex  int            `json:"master_last_index,omitempty"`  // MasterLastIndex
	PrivateLastIndex int            `json:"private_last_index,omitempty"` // PrivateLastIndex
	PublicLastIndex  int            `json:"public_last_index,omitempty"`  // PublicLastIndex
}

func newClusterNodes() *ClusterNodes {
	return &ClusterNodes{
		Masters:      []*ClusterNode{},
		PublicNodes:  []*ClusterNode{},
		PrivateNodes: []*ClusterNode{},
	}
}

// IsNull ...
// satisfies interface clonable.Clonable
func (n *ClusterNodes) IsNull() bool {
	return n == nil || (len(n.Masters) == 0 && len(n.PublicNodes) == 0 && len(n.PrivateNodes) == 0)
}

// Clone ... (clonable.Clonable interface)
func (n *ClusterNodes) Clone() (clonable.Clonable, error) {
	if n == nil {
		return nil, fail.InvalidInstanceError()
	}

	ncn := newClusterNodes()
	return ncn, ncn.Replace(n)
}

// Replace ... (clonable.Clonable interface)
func (n *ClusterNodes) Replace(p clonable.Clonable) error {
	if n == nil {
		return fail.InvalidInstanceError()
	}

	src, err := clonable.Cast[*ClusterNodes](p)
	if err != nil {
		return err
	}

	*n = *src
	n.Masters = make([]*ClusterNode, len(src.Masters))
	for k, v := range src.Masters {
		newNode := *v
		n.Masters[k] = &newNode
	}

	n.PublicNodes = make([]*ClusterNode, len(src.PublicNodes))
	for k, v := range src.PublicNodes {
		newNode := *v
		n.PublicNodes[k] = &newNode
	}

	n.PrivateNodes = make([]*ClusterNode, len(src.PrivateNodes))
	for k, v := range src.PrivateNodes {
		newNode := *v
		n.PrivateNodes[k] = &newNode
	}
	return nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.cluster", clusterproperty.NodesV1, newClusterNodes())
}
